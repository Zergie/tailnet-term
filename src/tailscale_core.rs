//! Minimal Tailscale protocol pieces used by tailnet-term.
//!
//! * [`control_link`] upgrades an HTTP/1.1 connection to the control protocol
//!   and splits it into typed records.
//! * [`control_cipher`] performs the Noise IK handshake with the control
//!   server and seals/opens the records that follow it.
//! * [`http2`] runs a small HTTP/2 client on top of those encrypted records.
//! * [`tunnel`] answers WireGuard handshake initiations and carries
//!   transport packets for the resulting session.
//! * [`discovery`] seals and opens peer discovery (ping/pong) messages.

pub mod control_cipher;
pub mod control_link;
pub mod discovery;
pub mod duplex;
pub mod http2;
pub mod tunnel;
