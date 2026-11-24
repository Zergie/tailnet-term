use std::{collections::VecDeque, net::Ipv4Addr};

use smoltcp::{
    iface::{Config, Interface},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{Socket, SocketBuffer},
    time::{Duration, Instant},
    wire::{HardwareAddress, IpAddress, IpCidr},
};

/// Socket buffer size of the terminal server, large enough to keep a DERP path busy.
const SERVER_BUFFER: usize = 64 * 1024;
/// Idle interval after which the server probes the client with a keep-alive ACK.
const SERVER_KEEP_ALIVE: Duration = Duration::from_secs(15);
/// The server drops a connection whose client stays silent this long while the server
/// waits for an answer (keep-alive, unacknowledged data or an unacknowledged FIN).
const SERVER_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Default)]
pub(crate) struct PacketDevice {
    pub(crate) incoming: VecDeque<Vec<u8>>,
    pub(crate) outgoing: VecDeque<Vec<u8>>,
}

impl Device for PacketDevice {
    type RxToken<'a> = Received;
    type TxToken<'a> = Transmit<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Received, Transmit<'_>)> {
        Some((
            Received(self.incoming.pop_front()?),
            Transmit(&mut self.outgoing),
        ))
    }

    fn transmit(&mut self, _: Instant) -> Option<Transmit<'_>> {
        Some(Transmit(&mut self.outgoing))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1280;
        capabilities
    }
}

pub(crate) struct Received(Vec<u8>);
impl RxToken for Received {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

pub(crate) struct Transmit<'a>(&'a mut VecDeque<Vec<u8>>);
impl TxToken for Transmit<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut bytes = vec![0; len];
        let result = f(&mut bytes);
        self.0.push_back(bytes);
        result
    }
}

pub(crate) fn interface(device: &mut PacketDevice, addr: Ipv4Addr, prefix: u8) -> Interface {
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        device,
        Instant::from_millis(0),
    );
    iface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(addr), prefix))
            .unwrap()
    });
    iface
}

/// The listening socket of the terminal server. Keep-alive and timeout make a client that
/// vanishes without FIN or RST end in `Closed`, so the listener can be re-armed.
pub(crate) fn server_socket() -> Socket<'static> {
    let mut socket = Socket::new(
        SocketBuffer::new(vec![0; SERVER_BUFFER]),
        SocketBuffer::new(vec![0; SERVER_BUFFER]),
    );
    socket.set_keep_alive(Some(SERVER_KEEP_ALIVE));
    socket.set_timeout(Some(SERVER_TIMEOUT));
    socket
}

#[cfg(test)]
pub(crate) fn tcp_socket() -> Socket<'static> {
    Socket::new(
        SocketBuffer::new(vec![0; 2048]),
        SocketBuffer::new(vec![0; 2048]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::{
        iface::{SocketHandle, SocketSet},
        socket::tcp::State,
    };

    const SERVER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
    const PORT: u16 = 7681;

    struct Pair {
        client_device: PacketDevice,
        server_device: PacketDevice,
        client: Interface,
        server: Interface,
        client_sockets: SocketSet<'static>,
        server_sockets: SocketSet<'static>,
        server_handle: SocketHandle,
    }

    impl Pair {
        fn connected() -> Self {
            let mut client_device = PacketDevice::default();
            let mut server_device = PacketDevice::default();
            let mut client = interface(&mut client_device, Ipv4Addr::new(192, 0, 2, 1), 24);
            let server = interface(&mut server_device, SERVER_IP, 24);
            let mut server_sockets = SocketSet::new(vec![]);
            let mut listener = server_socket();
            listener.listen(PORT).unwrap();
            let server_handle = server_sockets.add(listener);
            let mut client_sockets = SocketSet::new(vec![]);
            let mut connector = tcp_socket();
            connector
                .connect(client.context(), (IpAddress::Ipv4(SERVER_IP), PORT), 49152)
                .unwrap();
            client_sockets.add(connector);
            let mut pair = Self {
                client_device,
                server_device,
                client,
                server,
                client_sockets,
                server_sockets,
                server_handle,
            };
            for tick in 0..100 {
                pair.step(Instant::from_millis(tick), true);
            }
            assert_eq!(pair.server_socket().state(), State::Established);
            pair
        }

        /// Runs both stacks once. With `deliver == false` the client has vanished:
        /// its packets are lost and it never sees the server's packets.
        fn step(&mut self, now: Instant, deliver: bool) {
            if deliver {
                self.client
                    .poll(now, &mut self.client_device, &mut self.client_sockets);
                self.server_device
                    .incoming
                    .extend(self.client_device.outgoing.drain(..));
            }
            self.server
                .poll(now, &mut self.server_device, &mut self.server_sockets);
            let outgoing: Vec<_> = self.server_device.outgoing.drain(..).collect();
            if deliver {
                self.client_device.incoming.extend(outgoing);
            }
        }

        fn server_socket(&mut self) -> &mut Socket<'static> {
            self.server_sockets.get_mut::<Socket>(self.server_handle)
        }

        /// Advances time in 500 ms steps without the client. Returns how long it took until
        /// the server socket stopped being open, or `None` after `limit`.
        fn run_without_client(&mut self, from: u64, limit: Duration) -> Option<Duration> {
            let mut elapsed = Duration::ZERO;
            while elapsed <= limit {
                self.step(
                    Instant::from_millis((from + elapsed.total_millis()) as i64),
                    false,
                );
                if !self.server_socket().is_open() {
                    return Some(elapsed);
                }
                elapsed += Duration::from_millis(500);
            }
            None
        }
    }

    #[test]
    fn server_socket_uses_large_buffers_and_timers() {
        let socket = server_socket();
        assert_eq!(socket.recv_capacity(), SERVER_BUFFER);
        assert_eq!(socket.send_capacity(), SERVER_BUFFER);
        assert_eq!(socket.keep_alive(), Some(SERVER_KEEP_ALIVE));
        assert_eq!(socket.timeout(), Some(SERVER_TIMEOUT));
    }

    #[test]
    fn idle_connection_to_vanished_client_closes_and_listener_rearms() {
        let mut pair = Pair::connected();
        let closed = pair
            .run_without_client(100, SERVER_TIMEOUT + Duration::from_secs(5))
            .expect("server socket should time out");
        assert!(closed <= SERVER_TIMEOUT + Duration::from_secs(1));
        let socket = pair.server_socket();
        assert_eq!(socket.state(), State::Closed);
        socket
            .listen(PORT)
            .expect("listener should re-arm after the timeout");
        assert!(socket.is_listening());
        assert_eq!(socket.timeout(), Some(SERVER_TIMEOUT));
        assert_eq!(socket.keep_alive(), Some(SERVER_KEEP_ALIVE));
    }

    #[test]
    fn unacknowledged_fin_to_vanished_client_closes() {
        let mut pair = Pair::connected();
        pair.server_socket().close();
        let closed = pair
            .run_without_client(100, SERVER_TIMEOUT + Duration::from_secs(5))
            .expect("server socket should time out while its FIN is unacknowledged");
        assert!(closed <= SERVER_TIMEOUT + Duration::from_secs(1));
        pair.server_socket()
            .listen(PORT)
            .expect("listener should re-arm after the timeout");
    }

    #[test]
    fn listen_fails_while_connection_is_open() {
        let mut pair = Pair::connected();
        assert!(pair.server_socket().listen(PORT).is_err());
    }
}
