mod derp;
mod policy;

use std::{
    error::Error,
    fs,
    io::{self, ErrorKind, Write},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use smoltcp::{iface::SocketSet, socket::tcp::Socket, time::Instant as TcpTime};
use crate::tailscale_core::{discovery, http2::Http2Client, tunnel};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    open_control,
    tcp_probe::{PacketDevice, interface, server_socket},
    terminal::{auth, session::TerminalSession},
};
use derp::Relay;

pub const PORT: u16 = 7681;
/// Interval between Tailnet map refreshes.
const REFRESH: Duration = Duration::from_secs(10);
/// Bounds of the reconnect backoff for control and DERP.
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// Pause of the packet loop while it has no DERP connection.
const IDLE_PAUSE: Duration = Duration::from_millis(100);

#[cfg(feature = "diagnostics")]
pub fn relay_probe(host: &str) -> Result<(), Box<dyn Error>> {
    Relay::open(host, 443)?;
    println!("PASS: DERP TLS handshake, HTTP upgrade and relay key frame");
    Ok(())
}

struct Keys {
    private: [u8; 32],
    public: [u8; 32],
}

impl Keys {
    fn random() -> Result<Self, Box<dyn Error>> {
        let mut private = [0; 32];
        getrandom::getrandom(&mut private).map_err(|error| error.to_string())?;
        Ok(Self::from_private(private))
    }

    fn from_private(private: [u8; 32]) -> Self {
        let public = PublicKey::from(&StaticSecret::from(private)).to_bytes();
        Self { private, public }
    }
}

struct NodeKeys {
    machine: Keys,
    node: Keys,
    disco: Keys,
}

impl NodeKeys {
    fn load(path: &Path) -> Result<Option<Self>, Box<dyn Error>> {
        let encrypted = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut bytes = auth::dpapi(&encrypted, false)?;
        if bytes.len() != 96 || bytes.as_chunks::<32>().0.contains(&[0; 32]) {
            return Err("invalid Tailnet state file".into());
        }
        let keys = Self {
            machine: Keys::from_private(bytes[..32].try_into()?),
            node: Keys::from_private(bytes[32..64].try_into()?),
            disco: Keys::from_private(bytes[64..].try_into()?),
        };
        bytes.fill(0);
        Ok(Some(keys))
    }

    fn save(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        let mut bytes = [0; 96];
        bytes[..32].copy_from_slice(&self.machine.private);
        bytes[32..64].copy_from_slice(&self.node.private);
        bytes[64..].copy_from_slice(&self.disco.private);
        let encrypted = auth::dpapi(&bytes, true);
        bytes.fill(0);
        let encrypted = encrypted?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(&encrypted)?;
        file.sync_all()?;
        Ok(())
    }
}

fn encoded(prefix: &str, public: &[u8; 32]) -> String {
    let mut text = String::from(prefix);
    use std::fmt::Write;
    for byte in public {
        write!(text, "{byte:02x}").expect("writing to a String cannot fail");
    }
    text
}

fn parse_key(text: &str, prefix: &str) -> Option<[u8; 32]> {
    let hex = text.strip_prefix(prefix)?;
    if hex.len() != 64 || !hex.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut key = [0; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(key)
}

fn request(control: &mut Http2Client, path: &str, value: &Value) -> Result<Value, Box<dyn Error>> {
    let body = serde_json::to_vec(value)?;
    let (status, response) = control
        .post(path, &body)
        .map_err(|error| error.to_string())?;
    if status != 200 {
        return Err(format!("{path} returned HTTP {status}").into());
    }
    Ok(serde_json::from_slice(&response)?)
}

pub(crate) fn tailnet_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn ipv4_addresses(node: &Value) -> impl Iterator<Item = Ipv4Addr> + '_ {
    node["Addresses"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let (address, bits) = entry.as_str()?.split_once('/')?;
            if bits != "32" {
                return None;
            }
            let address = address.parse::<Ipv4Addr>().ok()?;
            tailnet_ipv4(address).then_some(address)
        })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PeerKeys {
    node: [u8; 32],
    disco: Option<[u8; 32]>,
}

fn authorized_peer(
    map: &Value,
    peer: Ipv4Addr,
    our_ip: Ipv4Addr,
) -> Result<PeerKeys, Box<dyn Error>> {
    if !policy::permits(map, peer, our_ip, PORT) {
        return Err(
            "the Tailnet packet filter does not authorize the selected IPv4 peer on TCP port 7681"
                .into(),
        );
    }
    let mut peers = map["Peers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|node| ipv4_addresses(node).any(|address| address == peer));
    let peer = peers
        .next()
        .ok_or("selected peer is not present in the Tailnet map")?;
    if peers.next().is_some() {
        return Err("selected peer IP matched more than one node".into());
    }
    let node = peer["Key"]
        .as_str()
        .and_then(|key| parse_key(key, "nodekey:"))
        .ok_or("selected peer has no valid node key")?;
    let disco = peer["DiscoKey"]
        .as_str()
        .and_then(|key| parse_key(key, "discokey:"));
    Ok(PeerKeys { node, disco })
}

/// How a map refresh changes what the server knows about its peer.
#[derive(Debug, PartialEq, Eq)]
enum PeerChange {
    Unchanged,
    /// Only the disco key changed, as on every tailscaled restart.
    Disco,
    /// The node key changed, as after a re-login; the WireGuard tunnel is stale.
    Node,
    /// The peer is missing from the map or no longer authorized.
    Lost,
    /// A previously lost peer is authorized again with the same node key.
    Restored,
}

fn peer_change(current: &PeerKeys, authorized: bool, updated: Option<&PeerKeys>) -> PeerChange {
    match updated {
        None if authorized => PeerChange::Lost,
        None => PeerChange::Unchanged,
        Some(updated) if updated.node != current.node => PeerChange::Node,
        Some(_) if !authorized => PeerChange::Restored,
        Some(updated) if updated.disco != current.disco => PeerChange::Disco,
        Some(_) => PeerChange::Unchanged,
    }
}

/// Minimum spacing of handshake initiations processed per peer (50 per second).
const MIN_INITIATION_INTERVAL: Duration = Duration::from_millis(20);

/// The permitted client and its WireGuard state.
struct Peer {
    ip: Ipv4Addr,
    keys: PeerKeys,
    authorized: bool,
    tunnel: Option<tunnel::TunnelSession>,
    last_counter: Option<u64>,
    last_timestamp: [u8; 12],
    last_initiation: Option<Instant>,
}

impl Peer {
    fn new(ip: Ipv4Addr, keys: PeerKeys) -> Self {
        Self {
            ip,
            keys,
            authorized: true,
            tunnel: None,
            last_counter: None,
            last_timestamp: [0; 12],
            last_initiation: None,
        }
    }

    fn drop_tunnel(&mut self) {
        self.tunnel = None;
        self.last_counter = None;
    }

    /// Applies the peer lookup of a fresh map. Returns true when the terminal session
    /// must end because the peer is no longer authorized or now uses a different node key.
    fn update(&mut self, updated: Result<PeerKeys, Box<dyn Error>>) -> bool {
        let mut end_session = false;
        match peer_change(&self.keys, self.authorized, updated.as_ref().ok()) {
            PeerChange::Lost => {
                if let Err(error) = &updated {
                    eprintln!(
                        "Warning: {error}; dropping the connection until the peer is authorized again"
                    );
                }
                self.authorized = false;
                self.drop_tunnel();
                return true;
            }
            PeerChange::Node => {
                eprintln!("Peer node key changed; waiting for a new WireGuard handshake");
                self.drop_tunnel();
                // Initiation timestamps are tracked per node key.
                self.last_timestamp = [0; 12];
                // The session was authenticated over the old WireGuard identity; make the
                // client authenticate again rather than continuing over the new one.
                end_session = true;
            }
            PeerChange::Restored => eprintln!("Peer is authorized again"),
            PeerChange::Disco | PeerChange::Unchanged => {}
        }
        if let Ok(keys) = updated {
            self.keys = keys;
            self.authorized = true;
        }
        end_session
    }

    /// Handles a packet the peer sent through DERP.
    fn receive(
        &mut self,
        relay: &mut Relay,
        packet: &[u8],
        local: &LocalNode,
        device: &mut PacketDevice,
    ) -> io::Result<()> {
        if discovery::is_discovery(packet) {
            if let Ok(message) = discovery::decrypt_packet(&local.disco.private, packet)
                && message.kind == discovery::TYPE_PING
                && Some(message.sender) == self.keys.disco
                && let Ok(wire) = discovery::encrypt_packet(
                    &local.disco.private,
                    &local.disco.public,
                    &message.sender,
                    &discovery::pong_payload(&message.tx_id, (Ipv4Addr::UNSPECIFIED, 0).into()),
                )
            {
                relay.send_packet(&self.keys.node, &wire)?;
            }
        } else if packet.first() == Some(&tunnel::HANDSHAKE_INITIATION) {
            // Every initiation costs Diffie-Hellman work, so like WireGuard's
            // rate limiter, look at no more than one per interval.
            let now = Instant::now();
            if self
                .last_initiation
                .is_some_and(|last| now.duration_since(last) < MIN_INITIATION_INTERVAL)
            {
                return Ok(());
            }
            self.last_initiation = Some(now);
            if let Ok((reply, connection, timestamp)) = tunnel::accept_initiation(
                &local.node.private,
                &local.node.public,
                packet,
                tunnel::random_index(),
                &self.keys.node,
                &self.last_timestamp,
            ) {
                relay.send_packet(&self.keys.node, &reply)?;
                self.last_timestamp = timestamp;
                self.last_counter = None;
                self.tunnel = Some(connection);
            }
        } else if let Some(connection) = &self.tunnel
            && let Some((counter, inner)) =
                accept_transport(connection, packet, self.last_counter, self.ip, local.ip)
        {
            self.last_counter = Some(counter);
            device.incoming.push_back(inner);
        }
        Ok(())
    }
}

/// Bounded exponential backoff for reconnects.
struct Backoff {
    delay: Duration,
}

impl Backoff {
    fn new() -> Self {
        Self { delay: BACKOFF_MIN }
    }

    fn next(&mut self) -> Duration {
        let delay = self.delay;
        self.delay = (self.delay * 2).min(BACKOFF_MAX);
        delay
    }

    fn reset(&mut self) {
        self.delay = BACKOFF_MIN;
    }
}

/// This node's identity and its registration with control.
struct LocalNode<'a> {
    machine: &'a Keys,
    node: &'a Keys,
    disco: &'a Keys,
    ip: Ipv4Addr,
    map_request: Value,
    /// DERP region requested with TS_DERP_REGION.
    configured_region: Option<u16>,
}

/// Connections to Tailscale control and the DERP relay, with their reconnect state.
struct Links {
    control: Option<Http2Client>,
    control_backoff: Backoff,
    next_refresh: Instant,
    relay: Option<Relay>,
    relay_backoff: Backoff,
    next_relay_attempt: Instant,
    region: u16,
    regions: Value,
}

impl Links {
    /// Fetches the Tailnet map, opening a new control connection when needed.
    fn fetch_map(&mut self, local: &LocalNode) -> Result<Value, Box<dyn Error>> {
        let mut control = match self.control.take() {
            Some(control) => control,
            None => open_control(&local.machine.private)?,
        };
        let map = request(&mut control, "/machine/map", &local.map_request)?;
        self.control = Some(control);
        Ok(map)
    }

    /// Reconnects to DERP, preferring the current region because peers learn about
    /// another region only through control.
    fn reconnect_relay(
        &mut self,
        local: &mut LocalNode,
        terminal_active: bool,
    ) -> Result<(), Box<dyn Error>> {
        let (private, public) = (local.node.private, local.node.public);
        let (region, host, relay) = derp::select(&self.regions, Some(self.region), private, public)
            .or_else(|error| match local.configured_region {
                Some(_) => Err(error),
                None => derp::select(&self.regions, None, private, public),
            })?;
        relay.set_terminal_active(terminal_active)?;
        println!("Reconnected to DERP region {region} ({host})");
        if region != self.region {
            local.map_request["Hostinfo"]["NetInfo"]["PreferredDERP"] = json!(region);
            self.region = region;
            self.next_refresh = Instant::now();
        }
        self.relay = Some(relay);
        Ok(())
    }

    /// Drops a failed DERP connection and schedules a reconnect. A DERP reconnect request
    /// also waits, so a draining relay cannot cause a reconnect loop.
    fn relay_failed(&mut self, error: &dyn Error) {
        self.relay = None;
        let delay = self.relay_backoff.next();
        eprintln!(
            "Warning: DERP connection lost ({error}); reconnecting in {} s",
            delay.as_secs()
        );
        self.next_relay_attempt = Instant::now() + delay;
    }
}

pub fn run_terminal(
    peer_ip: Ipv4Addr,
    key: auth::PublicKey,
    program: PathBuf,
    state_file: PathBuf,
) -> Result<(), Box<dyn Error>> {
    let program = std::path::absolute(program)?;
    if !program.is_file() {
        return Err("the PowerShell executable must be an existing file".into());
    }
    run_service(peer_ip, key, program, &state_file)
}

static STOPPING: AtomicBool = AtomicBool::new(false);

fn stopping() -> bool {
    STOPPING.load(Ordering::Relaxed)
}

unsafe extern "system" fn stop_on_ctrl_c(event: u32) -> i32 {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};
    if matches!(event, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
        STOPPING.store(true, Ordering::Relaxed);
        1
    } else {
        0
    }
}

fn run_service(
    peer_ip: Ipv4Addr,
    key: auth::PublicKey,
    program: PathBuf,
    state_file: &Path,
) -> Result<(), Box<dyn Error>> {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
    // This handler accesses only a static atomic flag and never calls console APIs.
    if unsafe { SetConsoleCtrlHandler(Some(stop_on_ctrl_c), 1) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if !tailnet_ipv4(peer_ip) {
        return Err("choose a tailnet peer in 100.64.0.0/10".into());
    }
    let configured_region = match std::env::var("TS_DERP_REGION") {
        Ok(value) => value
            .parse::<std::num::NonZeroU16>()
            .map_err(|_| "TS_DERP_REGION must be a positive DERP region ID")?
            .get()
            .into(),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error.into()),
    };
    let existing = NodeKeys::load(state_file)?;
    let enrolling = existing.is_none();
    let keys = if let Some(keys) = existing {
        keys
    } else {
        NodeKeys {
            machine: Keys::random()?,
            node: Keys::random()?,
            disco: Keys::random()?,
        }
    };
    let NodeKeys {
        machine,
        node,
        disco,
    } = &keys;
    let mut control = open_control(&machine.private)?;
    let hostinfo = json!({"Hostname":"mpe-windows-terminal", "OS":"windows", "GoArch":"amd64",
        "NetInfo":{"WorkingIPv4":true,"PreferredDERP":configured_region.unwrap_or(0),"LinkType":"wired"}});
    let node_name = encoded("nodekey:", &node.public);
    let disco_name = encoded("discokey:", &disco.public);
    let mut registration = json!({
        "Version":90,"NodeKey":node_name,"MachineKey":encoded("mkey:",&machine.public),
        "DiscoKey":disco_name,"Hostinfo":hostinfo,"Ephemeral":false
    });
    if enrolling {
        let auth_key = std::env::var("TS_AUTH_KEY")
            .map_err(|_| "set TS_AUTH_KEY to a one-time Tailnet auth key for initial enrollment")?;
        if !auth_key.starts_with("tskey-auth-") {
            return Err("TS_AUTH_KEY is not a Tailnet auth key".into());
        }
        registration["Auth"] = json!({"AuthKey":auth_key});
    }
    let register = request(&mut control, "/machine/register", &registration)?;
    if register["MachineAuthorized"].as_bool() != Some(true)
        || register["NodeKeyExpired"].as_bool() == Some(true)
    {
        return Err("Tailscale did not authorize the node; check its enrollment or the device approval policy".into());
    }
    if enrolling {
        keys.save(state_file)?;
    }
    let mut map_request = json!({"Version":90,"NodeKey":node_name,"DiscoKey":disco_name,"Hostinfo":hostinfo,
        "Stream":false,"OmitPeers":false,"ReadOnly":false,"Endpoints":[],"Compress":""});
    let mut map = request(&mut control, "/machine/map", &map_request)?;
    let (region, host, relay) = derp::select(
        &map["DERPMap"]["Regions"],
        configured_region,
        node.private,
        node.public,
    )?;
    if map_request["Hostinfo"]["NetInfo"]["PreferredDERP"].as_u64() != Some(region.into()) {
        map_request["Hostinfo"]["NetInfo"]["PreferredDERP"] = json!(region);
        map = request(&mut control, "/machine/map", &map_request)?;
    }
    let our_ip = ipv4_addresses(&map["Node"])
        .next()
        .ok_or("control did not assign a Tailnet IPv4 address")?;
    let peer = Peer::new(peer_ip, authorized_peer(&map, peer_ip, our_ip)?);
    let terminal = TerminalSession::new(key, program, our_ip);
    println!(
        "Terminal listening for {peer_ip} at {our_ip}:{PORT} via DERP region {region} ({host}); press Ctrl+C to stop"
    );
    let local = LocalNode {
        machine,
        node,
        disco,
        ip: our_ip,
        map_request,
        configured_region,
    };
    let now = Instant::now();
    let links = Links {
        control: Some(control),
        control_backoff: Backoff::new(),
        next_refresh: now + REFRESH,
        relay: Some(relay),
        relay_backoff: Backoff::new(),
        next_relay_attempt: now,
        region,
        regions: map["DERPMap"]["Regions"].take(),
    };
    serve(local, links, peer, terminal)
}

/// Runs the packet loop. It survives peer, control and DERP changes.
fn serve(
    mut local: LocalNode,
    mut links: Links,
    mut peer: Peer,
    mut session: TerminalSession,
) -> Result<(), Box<dyn Error>> {
    let mut device = PacketDevice::default();
    let mut interface = interface(&mut device, local.ip, 10);
    let mut sockets = SocketSet::new(vec![]);
    let mut socket = server_socket();
    socket.listen(PORT)?;
    let handle = sockets.add(socket);
    let start = Instant::now();
    let mut terminal_active = false;
    while !stopping() {
        if Instant::now() >= links.next_refresh {
            match links.fetch_map(&local) {
                Ok(mut map) => {
                    links.control_backoff.reset();
                    links.next_refresh = Instant::now() + REFRESH;
                    if map["DERPMap"]["Regions"].is_object() {
                        links.regions = map["DERPMap"]["Regions"].take();
                    }
                    if peer.update(authorized_peer(&map, peer.ip, local.ip)) {
                        sockets.get_mut::<Socket>(handle).abort();
                        session.reset();
                    }
                }
                Err(error) => {
                    let delay = links.control_backoff.next();
                    eprintln!(
                        "Warning: Tailscale control request failed ({error}); retrying in {} s",
                        delay.as_secs()
                    );
                    links.next_refresh = Instant::now() + delay;
                }
            }
        }
        if let Some(relay) = &mut links.relay {
            let result = match relay.frame() {
                Ok(Some((0x15, _))) => Err("DERP asked the server to reconnect".into()),
                Ok(Some((12, data))) if data.len() == 8 => {
                    relay.write_frame(13, &data).map_err(Into::into)
                }
                Ok(Some((5, data)))
                    if peer.authorized && data.get(..32) == Some(peer.keys.node.as_slice()) =>
                {
                    peer.receive(relay, &data[32..], &local, &mut device)
                        .map_err(Into::into)
                }
                Ok(_) => Ok(()),
                Err(error) => Err(error),
            };
            if let Err(error) = result {
                links.relay_failed(error.as_ref());
            }
        } else if Instant::now() >= links.next_relay_attempt {
            match links.reconnect_relay(&mut local, terminal_active) {
                Ok(()) => links.relay_backoff.reset(),
                Err(error) => {
                    let delay = links.relay_backoff.next();
                    eprintln!(
                        "Warning: DERP reconnect failed ({error}); retrying in {} s",
                        delay.as_secs()
                    );
                    links.next_relay_attempt = Instant::now() + delay;
                }
            }
        } else {
            thread::sleep(IDLE_PAUSE);
        }
        interface.poll(
            TcpTime::from_millis(start.elapsed().as_millis() as i64),
            &mut device,
            &mut sockets,
        );
        match (&mut links.relay, &mut peer.tunnel) {
            (Some(relay), Some(connection)) => {
                let mut result = Ok(());
                while let Some(packet) = device.outgoing.pop_front() {
                    let Ok(wire) = connection.encrypt(&packet) else {
                        // Message limit reached; the peer's next handshake replaces the session.
                        device.outgoing.clear();
                        break;
                    };
                    result = relay.send_packet(&peer.keys.node, &wire);
                    if result.is_err() {
                        break;
                    }
                }
                if let Err(error) = result {
                    device.outgoing.clear();
                    links.relay_failed(&error);
                }
            }
            // Without a relay or tunnel the packets cannot leave; TCP retransmits them.
            _ => device.outgoing.clear(),
        }
        let socket = sockets.get_mut::<Socket>(handle);
        // A closed socket (finished, aborted or timed out) is re-armed only after the
        // interface had a chance to send its final RST or FIN.
        if !socket.is_open() {
            session.reset();
            socket.listen(PORT)?;
        }
        if let Err(error) = session.poll(socket) {
            eprintln!("Terminal session failed: {error}");
            socket.abort();
            session.reset();
        }
        let active = socket.may_send() || socket.may_recv();
        if active != terminal_active {
            terminal_active = active;
            if let Some(relay) = &links.relay
                && let Err(error) = relay.set_terminal_active(active)
            {
                links.relay_failed(&error);
            }
        }
    }
    Ok(())
}

fn accept_transport(
    connection: &tunnel::TunnelSession,
    packet: &[u8],
    last_counter: Option<u64>,
    peer: Ipv4Addr,
    local: Ipv4Addr,
) -> Option<(u64, Vec<u8>)> {
    if packet.first() != Some(&tunnel::TRANSPORT_DATA)
        || u32::from_le_bytes(packet.get(4..8)?.try_into().ok()?) != connection.local_index()
    {
        return None;
    }
    let counter = u64::from_le_bytes(packet.get(8..16)?.try_into().ok()?);
    if last_counter.is_some_and(|last| counter <= last) {
        return None;
    }
    let mut inner = connection.decrypt(packet).ok()?;
    if !allowed_tcp(&inner, peer, local) {
        return None;
    }
    inner.truncate(u16::from_be_bytes(inner[2..4].try_into().ok()?) as usize);
    Some((counter, inner))
}

fn allowed_tcp(packet: &[u8], peer: Ipv4Addr, local: Ipv4Addr) -> bool {
    if packet.len() < 40 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return false;
    }
    let header = usize::from(packet[0] & 15) * 4;
    let length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let fragments = u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff;
    header >= 20
        && length >= header + 20
        && length <= packet.len()
        && fragments == 0
        && packet[12..16] == peer.octets()
        && packet[16..20] == local.octets()
        && u16::from_be_bytes([packet[header + 2], packet[header + 3]]) == PORT
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(node: u8, disco: Option<u8>) -> PeerKeys {
        PeerKeys {
            node: [node; 32],
            disco: disco.map(|disco| [disco; 32]),
        }
    }

    #[test]
    fn peer_change_distinguishes_disco_node_and_authorization() {
        let current = keys(1, Some(2));
        let same = keys(1, Some(2));
        let new_disco = keys(1, Some(3));
        let new_node = keys(4, Some(2));
        assert_eq!(
            peer_change(&current, true, Some(&same)),
            PeerChange::Unchanged
        );
        assert_eq!(
            peer_change(&current, true, Some(&new_disco)),
            PeerChange::Disco
        );
        assert_eq!(
            peer_change(&current, true, Some(&new_node)),
            PeerChange::Node
        );
        assert_eq!(peer_change(&current, true, None), PeerChange::Lost);
        assert_eq!(peer_change(&current, false, None), PeerChange::Unchanged);
        assert_eq!(
            peer_change(&current, false, Some(&new_disco)),
            PeerChange::Restored
        );
        assert_eq!(
            peer_change(&current, false, Some(&new_node)),
            PeerChange::Node
        );
    }

    #[test]
    fn peer_update_keeps_or_resets_replay_state() {
        let ip = Ipv4Addr::new(100, 64, 0, 1);
        let mut peer = Peer::new(ip, keys(1, Some(2)));
        peer.last_timestamp = [7; 12];
        peer.last_counter = Some(5);

        // A tailscaled restart changes only the disco key: keep everything else.
        assert!(!peer.update(Ok(keys(1, Some(3)))));
        assert_eq!(peer.keys, keys(1, Some(3)));
        assert_eq!(peer.last_counter, Some(5));
        assert_eq!(peer.last_timestamp, [7; 12]);

        // A lost peer ends the session but keeps the replay timestamp of its key.
        assert!(peer.update(Err("gone".into())));
        assert!(!peer.authorized);
        assert_eq!(peer.last_counter, None);
        assert_eq!(peer.last_timestamp, [7; 12]);
        assert!(!peer.update(Err("still gone".into())));

        // Restored with the same node key.
        assert!(!peer.update(Ok(keys(1, Some(3)))));
        assert!(peer.authorized);
        assert_eq!(peer.last_timestamp, [7; 12]);

        // A new node key needs a fresh handshake and ends the session.
        peer.last_counter = Some(9);
        assert!(peer.update(Ok(keys(4, None))));
        assert_eq!(peer.keys, keys(4, None));
        assert_eq!(peer.last_counter, None);
        assert_eq!(peer.last_timestamp, [0; 12]);
    }

    #[test]
    fn backoff_doubles_up_to_the_limit_and_resets() {
        let mut backoff = Backoff::new();
        let delays: Vec<_> = (0..7).map(|_| backoff.next().as_secs()).collect();
        assert_eq!(delays, [1, 2, 4, 8, 16, 30, 30]);
        backoff.reset();
        assert_eq!(backoff.next(), BACKOFF_MIN);
    }
}
