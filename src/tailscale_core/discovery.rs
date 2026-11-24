//! Peer discovery messages: `MAGIC | sender public key | nonce | NaCl box`.
//!
//! Only ping parsing and pong construction are needed here.

use std::net::SocketAddr;

use anyhow::{Result, anyhow, bail};
use crypto_box::aead::{Aead, Nonce};
use crypto_box::{PublicKey, SalsaBox, SecretKey};

/// `"TS💬"` in UTF-8.
pub const MAGIC: [u8; 6] = [0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac];
pub const TYPE_PING: u8 = 0x01;
pub const TYPE_PONG: u8 = 0x02;

const PROTOCOL_VERSION: u8 = 0x00;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = MAGIC.len() + KEY_LEN + NONCE_LEN;
const TX_ID_LEN: usize = 12;

/// A decrypted discovery message.
pub struct DiscoveryMessage {
    /// The sender's discovery public key.
    pub sender: [u8; 32],
    /// Message type, e.g. [`TYPE_PING`].
    pub kind: u8,
    /// Transaction id for pings and pongs; zero for other types.
    pub tx_id: [u8; 12],
}

pub fn is_discovery(packet: &[u8]) -> bool {
    packet.starts_with(&MAGIC)
}

/// Decrypts a discovery packet addressed to `our_secret`.
pub fn decrypt_packet(our_secret: &[u8; 32], packet: &[u8]) -> Result<DiscoveryMessage> {
    if packet.len() < HEADER_LEN + TAG_LEN || !is_discovery(packet) {
        bail!("discovery packet: too short or missing magic");
    }
    let (key_bytes, rest) = packet[MAGIC.len()..].split_at(KEY_LEN);
    let (nonce_bytes, sealed) = rest.split_at(NONCE_LEN);
    let sender: [u8; 32] = key_bytes.try_into().expect("split at KEY_LEN");
    let plain = salsa_box(our_secret, &sender)
        .decrypt(Nonce::<SalsaBox>::from_slice(nonce_bytes), sealed)
        .map_err(|_| anyhow!("discovery packet: authentication failed"))?;

    let [kind, _version, body @ ..] = plain.as_slice() else {
        bail!(
            "discovery message: too short ({} byte{})",
            plain.len(),
            if plain.len() == 1 { "" } else { "s" }
        );
    };
    let mut tx_id = [0u8; TX_ID_LEN];
    if matches!(*kind, TYPE_PING | TYPE_PONG) {
        let Some(id) = body.get(..TX_ID_LEN) else {
            bail!("discovery message type {kind:#x}: missing transaction id");
        };
        tx_id.copy_from_slice(id);
    }
    Ok(DiscoveryMessage {
        sender,
        kind: *kind,
        tx_id,
    })
}

/// Encrypts `plaintext` for `peer` under a fresh random nonce.
pub fn encrypt_packet(
    our_secret: &[u8; 32],
    our_public: &[u8; 32],
    peer: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).expect("OS random number generator unavailable");
    let sealed = salsa_box(our_secret, peer)
        .encrypt(Nonce::<SalsaBox>::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow!("discovery message: encryption failed"))?;

    let mut out = Vec::with_capacity(HEADER_LEN + sealed.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(our_public);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Plaintext of a pong answering `tx_id`, reporting the `observed` source.
pub fn pong_payload(tx_id: &[u8; 12], observed: SocketAddr) -> Vec<u8> {
    let mut payload = Vec::with_capacity(2 + TX_ID_LEN + 18);
    payload.push(TYPE_PONG);
    payload.push(PROTOCOL_VERSION);
    payload.extend_from_slice(tx_id);
    payload.extend_from_slice(&encode_addr(observed));
    payload
}

/// 16-byte IPv6 (IPv4 is v4-mapped) followed by the big-endian port.
fn encode_addr(addr: SocketAddr) -> [u8; 18] {
    let ip = match addr {
        SocketAddr::V4(v4) => v4.ip().to_ipv6_mapped(),
        SocketAddr::V6(v6) => *v6.ip(),
    };
    let mut out = [0u8; 18];
    out[..16].copy_from_slice(&ip.octets());
    out[16..].copy_from_slice(&addr.port().to_be_bytes());
    out
}

fn salsa_box(our_secret: &[u8; 32], their_public: &[u8; 32]) -> SalsaBox {
    SalsaBox::new(
        &PublicKey::from(*their_public),
        &SecretKey::from(*our_secret),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    struct Keys {
        secret: [u8; 32],
        public: [u8; 32],
    }

    fn keys(seed: u8) -> Keys {
        let secret = [seed; 32];
        let public = *SecretKey::from(secret).public_key().as_bytes();
        Keys { secret, public }
    }

    /// Builds a packet with `crypto_box` directly, independent of `seal`.
    fn packet_from(sender: &Keys, recipient: &Keys, nonce: [u8; 24], plaintext: &[u8]) -> Vec<u8> {
        let b = SalsaBox::new(
            &PublicKey::from(recipient.public),
            &SecretKey::from(sender.secret),
        );
        let sealed = b
            .encrypt(Nonce::<SalsaBox>::from_slice(&nonce), plaintext)
            .unwrap();
        [&MAGIC[..], &sender.public, &nonce, &sealed].concat()
    }

    fn ping(tx_id: [u8; 12]) -> Vec<u8> {
        let mut plain = vec![TYPE_PING, 0];
        plain.extend_from_slice(&tx_id);
        plain.extend_from_slice(&[0xaa; 32]); // node key trailer
        plain
    }

    #[test]
    fn magic_is_ts_speech_balloon() {
        assert_eq!(MAGIC, "TS💬".as_bytes());
        assert!(is_discovery(b"TS\xf0\x9f\x92\xacanything"));
        assert!(!is_discovery(b"TS\xf0\x9f\x92"));
        assert!(!is_discovery(&[1, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn opens_a_ping_from_a_peer() {
        let (peer, us) = (keys(1), keys(2));
        let tx_id = *b"abcdefghijkl";
        let packet = packet_from(&peer, &us, [7; 24], &ping(tx_id));

        let message = decrypt_packet(&us.secret, &packet).unwrap();
        assert_eq!(message.kind, TYPE_PING);
        assert_eq!(message.sender, peer.public);
        assert_eq!(message.tx_id, tx_id);
    }

    #[test]
    fn other_message_types_have_no_tx_id() {
        let (peer, us) = (keys(1), keys(2));
        let packet = packet_from(&peer, &us, [7; 24], &[0x03, 0]);
        let message = decrypt_packet(&us.secret, &packet).unwrap();
        assert_eq!(message.kind, 0x03);
        assert_eq!(message.tx_id, [0; 12]);
    }

    #[test]
    fn rejects_short_wrong_or_tampered_packets() {
        let (peer, us, other) = (keys(1), keys(2), keys(3));
        let open_err = |packet: &[u8]| {
            decrypt_packet(&us.secret, packet)
                .err()
                .unwrap()
                .to_string()
        };

        let good = packet_from(&peer, &us, [7; 24], &ping([1; 12]));
        assert_eq!(
            open_err(&good[..HEADER_LEN + TAG_LEN - 1]),
            "discovery packet: too short or missing magic"
        );
        let mut bad_magic = good.clone();
        bad_magic[0] = b'X';
        assert_eq!(
            open_err(&bad_magic),
            "discovery packet: too short or missing magic"
        );

        let mut tampered = good.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            open_err(&tampered),
            "discovery packet: authentication failed"
        );
        assert_eq!(
            open_err(&packet_from(&peer, &other, [7; 24], &ping([1; 12]))),
            "discovery packet: authentication failed"
        );

        assert_eq!(
            open_err(&packet_from(&peer, &us, [7; 24], &[TYPE_PING])),
            "discovery message: too short (1 byte)"
        );
        assert_eq!(
            open_err(&packet_from(&peer, &us, [7; 24], &[TYPE_PONG, 0, 1, 2])),
            "discovery message type 0x2: missing transaction id"
        );
    }

    #[test]
    fn sealed_packets_open_for_the_peer() {
        let (us, peer) = (keys(4), keys(5));
        let packet = encrypt_packet(&us.secret, &us.public, &peer.public, b"hello").unwrap();
        assert_eq!(&packet[..6], &MAGIC);
        assert_eq!(&packet[6..38], &us.public);
        assert_eq!(packet.len(), HEADER_LEN + 5 + TAG_LEN);

        let b = SalsaBox::new(&PublicKey::from(us.public), &SecretKey::from(peer.secret));
        let plain = b
            .decrypt(
                Nonce::<SalsaBox>::from_slice(&packet[38..62]),
                &packet[62..],
            )
            .unwrap();
        assert_eq!(plain, b"hello");

        let again = encrypt_packet(&us.secret, &us.public, &peer.public, b"hello").unwrap();
        assert_ne!(packet[38..62], again[38..62], "nonces must be random");
    }

    #[test]
    fn pong_payload_layout() {
        let tx_id = [9; 12];
        let v4 = pong_payload(&tx_id, (Ipv4Addr::new(100, 64, 1, 2), 41641).into());
        let mut expected = vec![TYPE_PONG, 0];
        expected.extend_from_slice(&tx_id);
        expected.extend_from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 100, 64, 1, 2, 0xa2, 0xa9,
        ]);
        assert_eq!(v4, expected);

        let v6 = pong_payload(&tx_id, (Ipv6Addr::LOCALHOST, 1).into());
        assert_eq!(&v6[14..30], &Ipv6Addr::LOCALHOST.octets());
        assert_eq!(&v6[30..], &[0, 1]);
    }

    #[test]
    fn a_pong_round_trips_through_encrypt_and_decrypt() {
        let (us, peer) = (keys(6), keys(7));
        let packet = encrypt_packet(
            &us.secret,
            &us.public,
            &peer.public,
            &pong_payload(&[3; 12], (Ipv4Addr::UNSPECIFIED, 0).into()),
        )
        .unwrap();
        let message = decrypt_packet(&peer.secret, &packet).unwrap();
        assert_eq!(
            (message.kind, message.tx_id, message.sender),
            (TYPE_PONG, [3; 12], us.public)
        );
    }
}
