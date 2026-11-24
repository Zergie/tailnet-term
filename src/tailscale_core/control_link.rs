//! HTTP/1.1 upgrade to the control protocol and record framing on top of the
//! upgraded connection.

use anyhow::{Result, anyhow, bail};

use super::duplex::Duplex;

const UPGRADE_PROTOCOL: &str = "tailscale-control-protocol";
const MAX_RESPONSE_HEAD: usize = 8192;

/// An upgraded control connection that yields `[type][u16 length][body]`
/// records.
pub struct ControlLink {
    io: Box<dyn Duplex>,
    buffered: Vec<u8>,
}

/// Sends the upgrade request carrying the base64 handshake `handshake` and
/// waits for `101 Switching Protocols`. Bytes the server sent after the
/// response head are kept for the first [`ControlLink::read_record`].
pub fn negotiate_upgrade(io: Box<dyn Duplex>, host: &str, handshake: &str) -> Result<ControlLink> {
    let mut link = ControlLink {
        io,
        buffered: Vec::new(),
    };

    let request = format!(
        "POST /ts2021 HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: {UPGRADE_PROTOCOL}\r\n\
         Connection: upgrade\r\n\
         X-Tailscale-Handshake: {handshake}\r\n\
         Content-Length: 0\r\n\r\n"
    );
    link.io
        .write_all(request.as_bytes())
        .map_err(|_| anyhow!("control upgrade: failed to send the request"))?;

    let mut head = Vec::new();
    let mut buf = [0u8; 512];
    let body_start = loop {
        let got = link
            .io
            .read(&mut buf)
            .map_err(|_| anyhow!("control upgrade: failed to read the response"))?;
        if got == 0 {
            bail!("control upgrade: connection closed before the response was complete");
        }
        head.extend_from_slice(&buf[..got]);
        if let Some(pos) = find(&head, b"\r\n\r\n") {
            break pos + 4;
        }
        if head.len() > MAX_RESPONSE_HEAD {
            bail!("control upgrade: response headers exceed {MAX_RESPONSE_HEAD} bytes");
        }
    };

    let status_line = head
        .split(|&b| b == b'\n')
        .next()
        .map(|line| String::from_utf8_lossy(line).trim().to_string())
        .unwrap_or_default();
    if !status_line.contains(" 101 ") {
        let body = String::from_utf8_lossy(&head[body_start..]);
        let body = body.trim();
        let separator = if body.is_empty() { "" } else { ": " };
        bail!("control upgrade: server answered '{status_line}' instead of 101{separator}{body}");
    }

    link.buffered.extend_from_slice(&head[body_start..]);
    Ok(link)
}

impl ControlLink {
    /// Reads one record and returns its type and body.
    pub fn read_record(&mut self) -> Result<(u8, Vec<u8>)> {
        let header = self.take(3)?;
        let len = u16::from_be_bytes([header[1], header[2]]) as usize;
        let body = self.take(len)?;
        Ok((header[0], body))
    }

    pub fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.io
            .write_all(data)
            .map_err(|_| anyhow!("control connection: write failed"))
    }

    fn take(&mut self, wanted: usize) -> Result<Vec<u8>> {
        let mut buf = [0u8; 2048];
        while self.buffered.len() < wanted {
            let got = self
                .io
                .read(&mut buf)
                .map_err(|_| anyhow!("control connection: read failed"))?;
            if got == 0 {
                bail!(
                    "control connection: closed mid-record (needed {wanted} bytes, had {})",
                    self.buffered.len()
                );
            }
            self.buffered.extend_from_slice(&buf[..got]);
        }
        Ok(self.buffered.drain(..wanted).collect())
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Standard base64 with padding.
pub fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let sextet = |shift: u32| ALPHABET[((n >> shift) & 0x3f) as usize] as char;
        out.push(sextet(18));
        out.push(sextet(12));
        out.push(if chunk.len() > 1 { sextet(6) } else { '=' });
        out.push(if chunk.len() > 2 { sextet(0) } else { '=' });
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    /// A connection that replays scripted reads and records every write.
    pub(crate) struct ScriptedIo {
        pub reads: VecDeque<Vec<u8>>,
        pub written: Rc<RefCell<Vec<u8>>>,
    }

    impl ScriptedIo {
        pub(crate) fn new(reads: &[&[u8]]) -> (Box<dyn Duplex>, Rc<RefCell<Vec<u8>>>) {
            let written = Rc::new(RefCell::new(Vec::new()));
            let io = ScriptedIo {
                reads: reads.iter().map(|r| r.to_vec()).collect(),
                written: written.clone(),
            };
            (Box::new(io), written)
        }
    }

    impl Duplex for ScriptedIo {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
            let Some(mut next) = self.reads.pop_front() else {
                return Ok(0);
            };
            let n = next.len().min(buf.len());
            buf[..n].copy_from_slice(&next[..n]);
            if n < next.len() {
                self.reads.push_front(next.split_off(n));
            }
            Ok(n)
        }

        fn write_all(&mut self, buf: &[u8]) -> Result<(), ()> {
            self.written.borrow_mut().extend_from_slice(buf);
            Ok(())
        }
    }

    struct Failing;

    impl Duplex for Failing {
        fn read(&mut self, _: &mut [u8]) -> Result<usize, ()> {
            Err(())
        }
        fn write_all(&mut self, _: &[u8]) -> Result<(), ()> {
            Err(())
        }
    }

    const SWITCHING: &[u8] =
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\n\r\n";

    #[test]
    fn base64_matches_rfc4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input.as_bytes()), expected);
        }
        assert_eq!(base64_encode(&[0xfb, 0xff, 0xbf]), "+/+/");
    }

    #[test]
    fn sends_the_upgrade_request() {
        let (io, written) = ScriptedIo::new(&[SWITCHING]);
        negotiate_upgrade(io, "control.example", "AAEC").unwrap();
        assert_eq!(
            String::from_utf8(written.borrow().clone()).unwrap(),
            "POST /ts2021 HTTP/1.1\r\n\
             Host: control.example\r\n\
             Upgrade: tailscale-control-protocol\r\n\
             Connection: upgrade\r\n\
             X-Tailscale-Handshake: AAEC\r\n\
             Content-Length: 0\r\n\r\n"
        );
    }

    #[test]
    fn keeps_bytes_after_the_response_head_and_reads_split_records() {
        let mut first = SWITCHING.to_vec();
        first.extend_from_slice(&[2, 0, 3, b'a']);
        let (io, _) = ScriptedIo::new(&[&first, b"b", b"c\x04\x00", b"\x00", b"\x03\x00\x01z"]);
        let mut link = negotiate_upgrade(io, "h", "x").unwrap();

        assert_eq!(link.read_record().unwrap(), (2, b"abc".to_vec()));
        assert_eq!(link.read_record().unwrap(), (4, Vec::new()));
        assert_eq!(link.read_record().unwrap(), (3, b"z".to_vec()));
        let err = link.read_record().unwrap_err().to_string();
        assert_eq!(
            err,
            "control connection: closed mid-record (needed 3 bytes, had 0)"
        );
    }

    #[test]
    fn response_head_may_arrive_byte_by_byte() {
        let pieces: Vec<&[u8]> = SWITCHING.chunks(1).collect();
        let (io, _) = ScriptedIo::new(&pieces);
        assert!(negotiate_upgrade(io, "h", "x").is_ok());
    }

    #[test]
    fn rejects_other_statuses_and_reports_the_body() {
        let (io, _) = ScriptedIo::new(&[b"HTTP/1.1 403 Forbidden\r\nX: y\r\n\r\n  denied \n"]);
        let err = negotiate_upgrade(io, "h", "x").err().unwrap().to_string();
        assert_eq!(
            err,
            "control upgrade: server answered 'HTTP/1.1 403 Forbidden' instead of 101: denied"
        );
    }

    #[test]
    fn rejects_truncated_or_oversized_heads() {
        let (io, _) = ScriptedIo::new(&[b"HTTP/1.1 101 Switching\r\n"]);
        let err = negotiate_upgrade(io, "h", "x").err().unwrap().to_string();
        assert_eq!(
            err,
            "control upgrade: connection closed before the response was complete"
        );

        let big = vec![b'x'; MAX_RESPONSE_HEAD + 1];
        let (io, _) = ScriptedIo::new(&[b"HTTP/1.1 101 OK\r\n", &big]);
        let err = negotiate_upgrade(io, "h", "x").err().unwrap().to_string();
        assert_eq!(err, "control upgrade: response headers exceed 8192 bytes");
    }

    #[test]
    fn surfaces_io_failures() {
        let err = negotiate_upgrade(Box::new(Failing), "h", "x")
            .err()
            .unwrap();
        assert_eq!(
            err.to_string(),
            "control upgrade: failed to send the request"
        );
    }
}
