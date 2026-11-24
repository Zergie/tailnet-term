use std::{
    error::Error,
    io::{self, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

use crypto_box::{
    PublicKey, SalsaBox, SecretKey,
    aead::{Aead, Nonce},
};
use rustls::{ClientConnection, StreamOwned};
use serde_json::Value;
use std::{sync::mpsc, thread, time::Instant};

const MAX_FRAME: usize = 64 * 1024;
const IDLE_READ_TIMEOUT: Duration = Duration::from_millis(150);
const TERMINAL_READ_TIMEOUT: Duration = Duration::from_millis(10);

/// A DERP node that may serve as relay: region ID, host name and TLS port.
type Candidate = (u16, String, u16);
/// A DERP frame: its type and payload.
type Frame = (u8, Vec<u8>);

/// Lists the relay nodes of `selected`, or of every region not marked `Avoid`.
/// Nodes with an invalid `DERPPort` are skipped.
fn candidates(regions: &Value, selected: Option<u16>) -> Result<Vec<Candidate>, Box<dyn Error>> {
    let regions = regions.as_object().ok_or("missing Tailnet DERP map")?;
    let mut candidates = Vec::new();
    for (id, region) in regions {
        let Ok(id) = id.parse::<u16>() else { continue };
        if selected.is_some_and(|wanted| wanted != id)
            || (selected.is_none() && region["Avoid"].as_bool() == Some(true))
        {
            continue;
        }
        for node in region["Nodes"].as_array().into_iter().flatten() {
            if node["STUNOnly"].as_bool() == Some(true) {
                continue;
            }
            let Some(host) = node["HostName"].as_str() else {
                continue;
            };
            let Ok(port) = u16::try_from(node["DERPPort"].as_u64().unwrap_or(0)) else {
                continue;
            };
            candidates.push((id, host.to_owned(), if port == 0 { 443 } else { port }));
        }
    }
    Ok(candidates)
}

/// Orders candidates for connection attempts: probed ones by latency. When no probe
/// answered in time, all candidates are tried in map order, since slower relays may work.
fn connection_order(mut ranked: Vec<(Duration, usize)>, count: usize) -> Vec<usize> {
    if ranked.is_empty() {
        return (0..count).collect();
    }
    ranked.sort_unstable();
    ranked.into_iter().map(|(_, index)| index).collect()
}

pub fn select(
    regions: &Value,
    selected: Option<u16>,
    private: [u8; 32],
    public: [u8; 32],
) -> Result<(u16, String, Relay), Box<dyn Error>> {
    let candidates = candidates(regions, selected)?;
    let mut ranked = Vec::new();
    if selected.is_none() && candidates.len() > 1 {
        let timeout = Duration::from_secs(2);
        let (sender, receiver) = mpsc::channel();
        for (index, (_, host, port)) in candidates.iter().enumerate() {
            let (host, port, sender) = (host.clone(), *port, sender.clone());
            thread::spawn(move || {
                let address = (host.as_str(), port)
                    .to_socket_addrs()
                    .ok()
                    .and_then(|mut addresses| addresses.find(|address| address.is_ipv4()));
                if let Some(address) = address {
                    let start = Instant::now();
                    if TcpStream::connect_timeout(&address, timeout).is_ok() {
                        let _ = sender.send((start.elapsed(), index));
                    }
                }
            });
        }
        drop(sender);
        let deadline = Instant::now() + timeout;
        while let Ok(probe) =
            receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            ranked.push(probe);
        }
    }
    let mut last_error = None;
    for index in connection_order(ranked, candidates.len()) {
        if super::STOPPING.load(std::sync::atomic::Ordering::Relaxed) {
            return Err("stopped while selecting a DERP relay".into());
        }
        let (id, host, port) = &candidates[index];
        match Relay::connect(host, *port, private, public) {
            Ok(relay) => return Ok((*id, host.clone(), relay)),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| "no usable DERP relay for the requested selection".into()))
}

pub struct Relay {
    stream: StreamOwned<ClientConnection, TcpStream>,
    pending: Vec<u8>,
}

impl Relay {
    pub fn connect(
        host: &str,
        port: u16,
        private: [u8; 32],
        public: [u8; 32],
    ) -> Result<Self, Box<dyn Error>> {
        let (mut relay, relay_key) = Self::open(host, port)?;
        let cipher = SalsaBox::new(&PublicKey::from(relay_key), &SecretKey::from(private));
        let mut nonce = [0; 24];
        getrandom::getrandom(&mut nonce).map_err(|error| error.to_string())?;
        let sealed = cipher
            .encrypt(
                Nonce::<SalsaBox>::from_slice(&nonce),
                &br#"{"version":2}"#[..],
            )
            .map_err(|_| "DERP client-info encryption failed")?;
        let mut info = public.to_vec();
        info.extend_from_slice(&nonce);
        info.extend_from_slice(&sealed);
        relay.write_frame(2, &info)?;
        let (3, info) = relay.frame()?.ok_or("DERP did not confirm the client")? else {
            return Err("DERP sent an unexpected confirmation frame".into());
        };
        if info.len() < 40
            || cipher
                .decrypt(Nonce::<SalsaBox>::from_slice(&info[..24]), &info[24..])
                .is_err()
        {
            return Err("DERP confirmation failed authentication".into());
        }
        relay.write_frame(7, &[1])?;
        relay.set_terminal_active(false)?;
        Ok(relay)
    }

    pub fn set_terminal_active(&self, active: bool) -> io::Result<()> {
        let timeout = if active {
            TERMINAL_READ_TIMEOUT
        } else {
            IDLE_READ_TIMEOUT
        };
        self.stream.sock.set_read_timeout(Some(timeout))
    }

    pub fn open(host: &str, port: u16) -> Result<(Self, [u8; 32]), Box<dyn Error>> {
        if !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
        {
            return Err("invalid DERP hostname".into());
        }
        let address = (host, port)
            .to_socket_addrs()?
            .find(|address| address.is_ipv4())
            .ok_or("DERP DNS returned no IPv4 address")?;
        let socket = TcpStream::connect_timeout(&address, Duration::from_secs(8))?;
        socket.set_read_timeout(Some(Duration::from_secs(8)))?;
        socket.set_write_timeout(Some(Duration::from_secs(8)))?;
        let stream = crate::tls_stream(host, socket)?;
        let mut relay = Self {
            stream,
            pending: Vec::new(),
        };
        write!(
            relay.stream,
            "GET /derp HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n"
        )?;
        relay.stream.flush()?;
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() == 4096 {
                return Err("DERP upgrade header too large".into());
            }
            let mut byte = [0];
            relay.stream.read_exact(&mut byte)?;
            header.push(byte[0]);
        }
        if !header.starts_with(b"HTTP/1.1 101 ") {
            return Err("DERP refused protocol upgrade".into());
        }
        let (kind, key) = relay.frame()?.ok_or("DERP did not send a relay key")?;
        if kind != 1 || key.len() < 40 || &key[..8] != b"DERP\xf0\x9f\x94\x91" {
            return Err("invalid DERP relay key".into());
        }
        Ok((relay, key[8..40].try_into()?))
    }

    pub fn frame(&mut self) -> Result<Option<Frame>, Box<dyn Error>> {
        loop {
            if self.pending.len() >= 5 {
                let len = u32::from_be_bytes(self.pending[1..5].try_into()?) as usize;
                if len > MAX_FRAME {
                    return Err("DERP frame too large".into());
                }
                if self.pending.len() >= 5 + len {
                    let frame: Vec<_> = self.pending.drain(..5 + len).collect();
                    return Ok(Some((frame[0], frame[5..].to_vec())));
                }
            }
            let mut buffer = [0; 4096];
            match self.stream.read(&mut buffer) {
                Ok(0) => return Err("DERP closed the connection".into()),
                Ok(count) => self.pending.extend_from_slice(&buffer[..count]),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    return Ok(None);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub fn write_frame(&mut self, kind: u8, data: &[u8]) -> io::Result<()> {
        let mut frame = Vec::with_capacity(5 + data.len());
        frame.push(kind);
        frame.extend_from_slice(&(data.len() as u32).to_be_bytes());
        frame.extend_from_slice(data);
        self.stream.write_all(&frame)?;
        self.stream.flush()
    }

    pub fn send_packet(&mut self, peer: &[u8; 32], packet: &[u8]) -> io::Result<()> {
        let mut data = peer.to_vec();
        data.extend_from_slice(packet);
        self.write_frame(4, &data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn map() -> Value {
        json!({
            "1": {"Nodes": [
                {"HostName": "a.example", "DERPPort": 0},
                {"HostName": "stun.example", "STUNOnly": true},
                {"HostName": "bad-port.example", "DERPPort": 70000},
                {"DERPPort": 443}
            ]},
            "2": {"Avoid": true, "Nodes": [{"HostName": "avoid.example"}]},
            "3": {"Nodes": [{"HostName": "c.example", "DERPPort": 8443}]},
            "x": {"Nodes": [{"HostName": "invalid-id.example"}]}
        })
    }

    #[test]
    fn candidates_skip_invalid_nodes_and_avoided_regions() {
        let mut found = candidates(&map(), None).unwrap();
        found.sort();
        assert_eq!(
            found,
            vec![
                (1, "a.example".to_owned(), 443),
                (3, "c.example".to_owned(), 8443)
            ]
        );
    }

    #[test]
    fn explicit_region_includes_avoided_region() {
        assert_eq!(
            candidates(&map(), Some(2)).unwrap(),
            vec![(2, "avoid.example".to_owned(), 443)]
        );
        assert!(candidates(&map(), Some(9)).unwrap().is_empty());
        assert!(candidates(&Value::Null, None).is_err());
    }

    #[test]
    fn connection_order_ranks_probes_and_falls_back_to_all() {
        let ranked = vec![
            (Duration::from_millis(30), 2),
            (Duration::from_millis(10), 0),
        ];
        assert_eq!(connection_order(ranked, 3), vec![0, 2]);
        assert_eq!(connection_order(Vec::new(), 3), vec![0, 1, 2]);
        assert!(connection_order(Vec::new(), 0).is_empty());
    }
}
