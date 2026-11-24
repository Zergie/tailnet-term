//! Responder side of the WireGuard handshake and the transport packets of the
//! resulting session.
//!
//! Only what an always-responding peer needs is implemented: initiations are
//! answered (mac2/cookies are neither checked nor produced) and data packets
//! are sealed and opened. Initiations are only answered for the expected peer
//! and a fresh timestamp; per-packet replay protection is left to the caller.

use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, ensure};
use blake2::digest::Mac;
use blake2::digest::consts::U16;
use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

pub const HANDSHAKE_INITIATION: u8 = 1;
pub const HANDSHAKE_RESPONSE: u8 = 2;
pub const TRANSPORT_DATA: u8 = 4;

pub const INITIATION_LEN: usize = 148;
pub const RESPONSE_LEN: usize = 92;

/// A session stops accepting packets this long after its handshake
/// (WireGuard's REJECT_AFTER_TIME).
pub const SESSION_LIFETIME: Duration = Duration::from_secs(180);
/// Counters at or above this are never used (WireGuard's
/// REJECT_AFTER_MESSAGES, 2^64 - 2^13 - 1).
const MESSAGE_LIMIT: u64 = u64::MAX - (1 << 13);

/// Header of a transport packet: type, 3 reserved bytes, receiver index and
/// counter.
const TRANSPORT_HEADER_LEN: usize = 16;
const TAG_LEN: usize = 16;

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const MAC1_LABEL: &[u8] = b"mac1----";
const ZERO_PSK: [u8; 32] = [0u8; 32];
const LOW_ORDER_POINT: &str = "WireGuard handshake: peer key is a low-order point";

/// Byte ranges inside an initiation message.
mod initiation {
    use std::ops::Range;
    pub const SENDER: Range<usize> = 4..8;
    pub const EPHEMERAL: Range<usize> = 8..40;
    pub const STATIC: Range<usize> = 40..88;
    pub const TIMESTAMP: Range<usize> = 88..116;
    pub const MAC1: Range<usize> = 116..132;
}

/// Byte ranges inside a response message.
mod response {
    use std::ops::Range;
    pub const SENDER: Range<usize> = 4..8;
    pub const RECEIVER: Range<usize> = 8..12;
    pub const EPHEMERAL: Range<usize> = 12..44;
    pub const EMPTY: Range<usize> = 44..60;
    pub const MAC1: Range<usize> = 60..76;
}

/// Transport keys of an established session.
pub struct TunnelSession {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    remote_index: u32,
    local_index: u32,
    send_counter: u64,
    established: Instant,
}

/// Validates and answers a handshake initiation addressed to `our_secret`.
///
/// Only `expected_peer` may initiate, and its TAI64N timestamp must be newer
/// than `last_timestamp`. Both are checked as soon as they are decrypted, so an
/// initiation from anyone else, or a replayed one, costs at most two
/// Diffie-Hellman operations and never gets a response.
///
/// Returns the response to send back, the new session and the initiation's
/// timestamp (the caller's next `last_timestamp`).
pub fn accept_initiation(
    our_secret: &[u8; 32],
    our_public: &[u8; 32],
    message: &[u8],
    local_index: u32,
    expected_peer: &[u8; 32],
    last_timestamp: &[u8; 12],
) -> Result<([u8; RESPONSE_LEN], TunnelSession, [u8; 12])> {
    ensure!(
        message.len() >= INITIATION_LEN,
        "WireGuard initiation: {} bytes, expected {INITIATION_LEN}",
        message.len()
    );
    ensure!(
        message[0] == HANDSHAKE_INITIATION,
        "WireGuard initiation: wrong message type {}",
        message[0]
    );
    ensure!(
        mac_matches(
            &hash(&[MAC1_LABEL, our_public]),
            &message[..initiation::MAC1.start],
            &message[initiation::MAC1]
        ),
        "WireGuard initiation: invalid mac1"
    );
    let remote_index = u32::from_le_bytes(message[initiation::SENDER].try_into().unwrap());
    let peer_ephemeral: [u8; 32] = message[initiation::EPHEMERAL].try_into().unwrap();
    let sealed_static = &message[initiation::STATIC];
    let sealed_timestamp = &message[initiation::TIMESTAMP];

    // Initiator's half: e, es, s, ss.
    let initial = hash(&[CONSTRUCTION]);
    let mut transcript = hash(&[&initial, IDENTIFIER]);
    transcript = hash(&[&transcript, our_public]);
    let mut chain = Zeroizing::new(initial);

    [chain] = kdf(&chain, &peer_ephemeral);
    transcript = hash(&[&transcript, &peer_ephemeral]);

    let [next, key] = kdf(&chain, &*dh(our_secret, &peer_ephemeral)?);
    chain = next;
    let peer_static: [u8; 32] = aead_open(&key, 0, sealed_static, &transcript)
        .map_err(|_| anyhow!("WireGuard initiation: cannot decrypt the static key"))?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("WireGuard initiation: static key has the wrong length"))?;
    ensure!(
        peer_static == *expected_peer,
        "WireGuard initiation: unexpected peer"
    );
    transcript = hash(&[&transcript, sealed_static]);

    let [next, key] = kdf(&chain, &*dh(our_secret, &peer_static)?);
    chain = next;
    let timestamp: [u8; 12] = aead_open(&key, 0, sealed_timestamp, &transcript)
        .map_err(|_| anyhow!("WireGuard initiation: cannot decrypt the timestamp"))?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("WireGuard initiation: timestamp has the wrong length"))?;
    // TAI64N is big-endian, so byte order is time order.
    ensure!(
        timestamp > *last_timestamp,
        "WireGuard initiation: replayed or stale timestamp"
    );
    transcript = hash(&[&transcript, sealed_timestamp]);

    // Our half: e, ee, se, psk.
    let mut reply = [0u8; RESPONSE_LEN];
    reply[0] = HANDSHAKE_RESPONSE;
    reply[response::SENDER].copy_from_slice(&local_index.to_le_bytes());
    reply[response::RECEIVER].copy_from_slice(&remote_index.to_le_bytes());

    let ephemeral = fresh_secret();
    let ephemeral_public = public_of(&ephemeral);
    reply[response::EPHEMERAL].copy_from_slice(&ephemeral_public);
    [chain] = kdf(&chain, &ephemeral_public);
    transcript = hash(&[&transcript, &ephemeral_public]);

    [chain] = kdf(&chain, &*dh(&ephemeral, &peer_ephemeral)?);
    [chain] = kdf(&chain, &*dh(&ephemeral, &peer_static)?);

    let [next, tau, key] = kdf(&chain, &ZERO_PSK);
    chain = next;
    transcript = hash(&[&transcript, &tau[..]]);
    let empty = aead_seal(&key, 0, &[], &transcript);
    reply[response::EMPTY].copy_from_slice(&empty);

    let mac1 = mac(
        &hash(&[MAC1_LABEL, &peer_static]),
        &reply[..response::MAC1.start],
    );
    reply[response::MAC1].copy_from_slice(&mac1);

    let [recv_key, send_key] = kdf(&chain, &[]);
    let session = TunnelSession {
        send_key: *send_key,
        recv_key: *recv_key,
        remote_index,
        local_index,
        send_counter: 0,
        established: Instant::now(),
    };
    Ok((reply, session, timestamp))
}

/// A random sender index for a new session.
pub fn random_index() -> u32 {
    let mut bytes = [0u8; 4];
    fill_random(&mut bytes);
    u32::from_le_bytes(bytes)
}

impl TunnelSession {
    /// Our sender index, which the peer puts in its transport packets.
    pub fn local_index(&self) -> u32 {
        self.local_index
    }

    /// Seals `inner` (zero-padded to 16 bytes) into a transport packet.
    ///
    /// Only the message limit applies here, not [`SESSION_LIFETIME`]: this side
    /// cannot start a handshake, so refusing to send would stall the
    /// connection until the peer happens to send something.
    pub fn encrypt(&mut self, inner: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            self.send_counter < MESSAGE_LIMIT,
            "WireGuard packet: session message limit reached"
        );
        let mut padded = inner.to_vec();
        padded.resize(inner.len().next_multiple_of(16), 0);
        let ciphertext = aead_seal(&self.send_key, self.send_counter, &padded, &[]);
        let mut out = Vec::with_capacity(TRANSPORT_HEADER_LEN + ciphertext.len());
        out.extend_from_slice(&[TRANSPORT_DATA, 0, 0, 0]);
        out.extend_from_slice(&self.remote_index.to_le_bytes());
        out.extend_from_slice(&self.send_counter.to_le_bytes());
        out.extend_from_slice(&ciphertext);
        self.send_counter += 1;
        Ok(out)
    }

    /// Opens a transport packet. The plaintext keeps its zero padding and the
    /// receiver index and replays are not checked; both are up to the caller.
    /// Packets are refused once the session is older than [`SESSION_LIFETIME`].
    pub fn decrypt(&self, packet: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_at(packet, Instant::now())
    }

    fn decrypt_at(&self, packet: &[u8], now: Instant) -> Result<Vec<u8>> {
        ensure!(
            packet.len() >= TRANSPORT_HEADER_LEN + TAG_LEN,
            "WireGuard packet: too short ({} bytes)",
            packet.len()
        );
        ensure!(
            packet[0] == TRANSPORT_DATA,
            "WireGuard packet: wrong message type {}",
            packet[0]
        );
        ensure!(
            now.saturating_duration_since(self.established) < SESSION_LIFETIME,
            "WireGuard packet: session expired"
        );
        let counter = u64::from_le_bytes(packet[8..16].try_into().unwrap());
        ensure!(
            counter < MESSAGE_LIMIT,
            "WireGuard packet: counter is past the session limit"
        );
        aead_open(
            &self.recv_key,
            counter,
            &packet[TRANSPORT_HEADER_LEN..],
            &[],
        )
        .map_err(|_| anyhow!("WireGuard packet: authentication failed"))
    }
}

impl Drop for TunnelSession {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.recv_key.zeroize();
    }
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    for part in parts {
        Digest::update(&mut hasher, part);
    }
    hasher.finalize().into()
}

/// HMAC-BLAKE2s.
fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block_key = Zeroizing::new([0u8; BLOCK]);
    if key.len() > BLOCK {
        block_key[..32].copy_from_slice(&hash(&[key]));
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }
    let ipad = Zeroizing::new(block_key.map(|b| b ^ 0x36));
    let opad = Zeroizing::new(block_key.map(|b| b ^ 0x5c));
    let inner = Zeroizing::new(hash(&[&ipad[..], data]));
    hash(&[&opad[..], &inner[..]])
}

/// HKDF with HMAC-BLAKE2s, producing `N` (1 to 3) outputs. Every output and
/// intermediate value is wiped when dropped.
fn kdf<const N: usize>(key: &[u8; 32], input: &[u8]) -> [Zeroizing<[u8; 32]>; N] {
    let prk = Zeroizing::new(hmac(key, input));
    let mut out: [Zeroizing<[u8; 32]>; N] = std::array::from_fn(|_| Zeroizing::new([0u8; 32]));
    let mut input = Zeroizing::new(Vec::with_capacity(33));
    for (i, block) in out.iter_mut().enumerate() {
        input.push(i as u8 + 1);
        **block = hmac(&prk[..], &input);
        input.clear();
        input.extend_from_slice(&block[..]);
    }
    out
}

/// Keyed BLAKE2s with a 16-byte output.
fn mac(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut state = <Blake2sMac<U16> as Mac>::new_from_slice(key).expect("blake2s mac key");
    Mac::update(&mut state, data);
    state.finalize().into_bytes().into()
}

fn mac_matches(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let mut state = <Blake2sMac<U16> as Mac>::new_from_slice(key).expect("blake2s mac key");
    Mac::update(&mut state, data);
    state.verify_slice(tag).is_ok()
}

/// WireGuard nonces carry a little-endian counter in the last eight bytes.
fn counter_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

fn aead_seal(key: &[u8; 32], counter: u64, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new_from_slice(key)
        .expect("chacha key")
        .encrypt(
            Nonce::from_slice(&counter_nonce(counter)),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("chacha seal")
}

fn aead_open(key: &[u8; 32], counter: u64, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow!("AEAD: invalid key"))?
        .decrypt(
            Nonce::from_slice(&counter_nonce(counter)),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("AEAD: authentication failed"))
}

fn dh(secret: &[u8; 32], their_public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let shared = StaticSecret::from(*secret).diffie_hellman(&PublicKey::from(*their_public));
    ensure!(shared.was_contributory(), "{LOW_ORDER_POINT}");
    Ok(Zeroizing::new(shared.to_bytes()))
}

fn public_of(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

fn fresh_secret() -> Zeroizing<[u8; 32]> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    fill_random(&mut *bytes);
    bytes
}

fn fill_random(bytes: &mut [u8]) {
    getrandom::getrandom(bytes).expect("OS random number generator unavailable");
}

#[cfg(test)]
mod tests {
    use super::*;
    use snow::{Builder, HandshakeState};

    const RESPONDER_SECRET: [u8; 32] = [0x41; 32];
    const INITIATOR_SECRET: [u8; 32] = [0x42; 32];
    const TIMESTAMP: [u8; 12] = *b"tai64n-stamp";
    const INITIATOR_INDEX: u32 = 0x0102_0304;
    const RESPONDER_INDEX: u32 = 0xa0b0_c0d0;

    fn public(secret: [u8; 32]) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(secret)).to_bytes()
    }

    /// Independent mac1 computation with the `blake2` crate.
    fn mac1(receiver_public: &[u8; 32], covered: &[u8]) -> [u8; 16] {
        let key = Blake2s256::new()
            .chain_update(MAC1_LABEL)
            .chain_update(receiver_public)
            .finalize();
        let mut state = <Blake2sMac<U16> as Mac>::new_from_slice(&key).unwrap();
        Mac::update(&mut state, covered);
        state.finalize().into_bytes().into()
    }

    /// An initiator built on `snow`, which shares no code with the module.
    fn initiator(responder_public: &[u8; 32]) -> HandshakeState {
        Builder::new("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
            .prologue(IDENTIFIER)
            .unwrap()
            .local_private_key(&INITIATOR_SECRET)
            .unwrap()
            .remote_public_key(responder_public)
            .unwrap()
            .psk(2, &ZERO_PSK)
            .unwrap()
            .build_initiator()
            .unwrap()
    }

    fn initiation_message(state: &mut HandshakeState, responder_public: &[u8; 32]) -> Vec<u8> {
        let mut message = vec![0u8; INITIATION_LEN];
        message[0] = HANDSHAKE_INITIATION;
        message[4..8].copy_from_slice(&INITIATOR_INDEX.to_le_bytes());
        let n = state
            .write_message(&TIMESTAMP, &mut message[8..116])
            .unwrap();
        assert_eq!(n, 108, "e + encrypted s + encrypted timestamp");
        let tag = mac1(responder_public, &message[..116]);
        message[116..132].copy_from_slice(&tag);
        message
    }

    /// Completes a handshake and returns the session plus the initiator's
    /// (send, receive) transport keys.
    fn established() -> (TunnelSession, [u8; 32], [u8; 32]) {
        let responder_public = public(RESPONDER_SECRET);
        let mut state = initiator(&responder_public);
        let message = initiation_message(&mut state, &responder_public);

        let (reply, session, timestamp) = accept_initiation(
            &RESPONDER_SECRET,
            &responder_public,
            &message,
            RESPONDER_INDEX,
            &public(INITIATOR_SECRET),
            &[0; 12],
        )
        .unwrap();
        assert_eq!(timestamp, TIMESTAMP);

        assert_eq!(reply[0], HANDSHAKE_RESPONSE);
        assert_eq!(reply[1..4], [0, 0, 0]);
        assert_eq!(reply[4..8], RESPONDER_INDEX.to_le_bytes());
        assert_eq!(reply[8..12], INITIATOR_INDEX.to_le_bytes());
        assert_eq!(reply[60..76], mac1(&public(INITIATOR_SECRET), &reply[..60]));
        assert_eq!(reply[76..92], [0; 16], "no mac2");

        let mut payload = [0u8; 64];
        let n = state
            .read_message(&reply[12..60], &mut payload)
            .expect("initiator accepts response");
        assert_eq!(n, 0);
        assert!(state.is_handshake_finished());
        let (send, recv) = state.dangerously_get_raw_split();
        (session, send, recv)
    }

    fn le_nonce(counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    #[test]
    fn answers_an_initiation_from_an_independent_initiator() {
        let (session, _, _) = established();
        assert_eq!(session.local_index(), RESPONDER_INDEX);
    }

    #[test]
    fn opens_packets_from_the_initiator_keeping_padding() {
        let (session, send, _) = established();
        let cipher = ChaCha20Poly1305::new_from_slice(&send).unwrap();
        let plaintext = b"0123456789abcdef-padded\0\0\0\0\0\0\0\0\0";
        let mut packet = vec![TRANSPORT_DATA, 0, 0, 0];
        packet.extend_from_slice(&RESPONDER_INDEX.to_le_bytes());
        packet.extend_from_slice(&5u64.to_le_bytes());
        packet.extend(
            cipher
                .encrypt(Nonce::from_slice(&le_nonce(5)), plaintext.as_slice())
                .unwrap(),
        );

        assert_eq!(session.decrypt(&packet).unwrap(), plaintext);
    }

    #[test]
    fn sealed_packets_open_for_the_initiator() {
        let (mut session, _, recv) = established();
        let cipher = ChaCha20Poly1305::new_from_slice(&recv).unwrap();

        for (counter, inner) in [b"seventeen bytes!!".as_slice(), b"", b"0123456789abcdef"]
            .into_iter()
            .enumerate()
        {
            let packet = session.encrypt(inner).unwrap();
            assert_eq!(packet[..4], [TRANSPORT_DATA, 0, 0, 0]);
            assert_eq!(packet[4..8], INITIATOR_INDEX.to_le_bytes());
            assert_eq!(packet[8..16], (counter as u64).to_le_bytes());
            let plain = cipher
                .decrypt(Nonce::from_slice(&le_nonce(counter as u64)), &packet[16..])
                .unwrap();
            assert_eq!(plain.len(), inner.len().next_multiple_of(16));
            assert_eq!(&plain[..inner.len()], inner);
            assert!(plain[inner.len()..].iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn rejects_bad_transport_packets() {
        let (mut session, _, _) = established();
        let err = |packet: &[u8]| session.decrypt(packet).unwrap_err().to_string();

        assert_eq!(
            err(&[TRANSPORT_DATA; 31]),
            "WireGuard packet: too short (31 bytes)"
        );
        assert_eq!(err(&[0; 32]), "WireGuard packet: wrong message type 0");
        assert_eq!(
            err(&[TRANSPORT_DATA; 48]),
            "WireGuard packet: authentication failed"
        );

        // Our own packets use the other direction's key.
        let ours = session.encrypt(b"x").unwrap();
        assert!(session.decrypt(&ours).is_err());
    }

    #[test]
    fn rejects_malformed_initiations() {
        let responder_public = public(RESPONDER_SECRET);
        let message = initiation_message(&mut initiator(&responder_public), &responder_public);
        let err = |message: &[u8], public: &[u8; 32]| {
            accept_initiation(
                &RESPONDER_SECRET,
                public,
                message,
                1,
                &self::public(INITIATOR_SECRET),
                &[0; 12],
            )
            .err()
            .unwrap()
            .to_string()
        };

        assert_eq!(
            err(&message[..147], &responder_public),
            "WireGuard initiation: 147 bytes, expected 148"
        );

        let mut wrong_type = message.clone();
        wrong_type[0] = HANDSHAKE_RESPONSE;
        assert_eq!(
            err(&wrong_type, &responder_public),
            "WireGuard initiation: wrong message type 2"
        );

        let mut bad_mac = message.clone();
        bad_mac[20] ^= 1;
        assert_eq!(
            err(&bad_mac, &responder_public),
            "WireGuard initiation: invalid mac1"
        );

        // Addressed to a different responder: mac1 fails first ...
        let other_public = public([0x43; 32]);
        let mut misdirected = initiation_message(&mut initiator(&other_public), &other_public);
        assert_eq!(
            err(&misdirected, &responder_public),
            "WireGuard initiation: invalid mac1"
        );
        // ... and with a mac1 that matches us, the static key does not open.
        let tag = mac1(&responder_public, &misdirected[..116]);
        misdirected[116..132].copy_from_slice(&tag);
        assert_eq!(
            err(&misdirected, &responder_public),
            "WireGuard initiation: cannot decrypt the static key"
        );
    }

    #[test]
    fn rejects_a_low_order_ephemeral_key() {
        let responder_public = public(RESPONDER_SECRET);
        let mut message = vec![0u8; INITIATION_LEN];
        message[0] = HANDSHAKE_INITIATION;
        let tag = mac1(&responder_public, &message[..116]);
        message[116..132].copy_from_slice(&tag);
        let err = accept_initiation(
            &RESPONDER_SECRET,
            &responder_public,
            &message,
            1,
            &public(INITIATOR_SECRET),
            &[0; 12],
        )
        .err()
        .unwrap();
        assert_eq!(err.to_string(), LOW_ORDER_POINT);
    }

    #[test]
    fn each_response_uses_a_fresh_ephemeral_key() {
        let responder_public = public(RESPONDER_SECRET);
        let reply = |_| {
            let message = initiation_message(&mut initiator(&responder_public), &responder_public);
            accept_initiation(
                &RESPONDER_SECRET,
                &responder_public,
                &message,
                1,
                &public(INITIATOR_SECRET),
                &[0; 12],
            )
            .unwrap()
            .0
        };
        assert_ne!(reply(0)[12..44], reply(1)[12..44]);
    }

    fn accept(message: &[u8], expected_peer: &[u8; 32], last_timestamp: &[u8; 12]) -> String {
        accept_initiation(
            &RESPONDER_SECRET,
            &public(RESPONDER_SECRET),
            message,
            1,
            expected_peer,
            last_timestamp,
        )
        .err()
        .unwrap()
        .to_string()
    }

    #[test]
    fn only_the_expected_peer_gets_a_response() {
        let responder_public = public(RESPONDER_SECRET);
        let message = initiation_message(&mut initiator(&responder_public), &responder_public);
        assert_eq!(
            accept(&message, &public([0x44; 32]), &[0; 12]),
            "WireGuard initiation: unexpected peer"
        );
    }

    #[test]
    fn replayed_or_older_initiations_get_no_response() {
        let responder_public = public(RESPONDER_SECRET);
        let message = initiation_message(&mut initiator(&responder_public), &responder_public);
        let peer = public(INITIATOR_SECRET);
        let stale = "WireGuard initiation: replayed or stale timestamp";
        assert_eq!(accept(&message, &peer, &TIMESTAMP), stale);
        assert_eq!(accept(&message, &peer, b"tai64n-stamq"), stale);
        assert_eq!(accept(&message, &peer, &[0xff; 12]), stale);

        let mut older = TIMESTAMP;
        older[11] -= 1;
        assert!(
            accept_initiation(
                &RESPONDER_SECRET,
                &responder_public,
                &message,
                1,
                &peer,
                &older
            )
            .is_ok()
        );
    }

    #[test]
    fn sessions_stop_accepting_packets_after_their_lifetime() {
        let (session, send, _) = established();
        let cipher = ChaCha20Poly1305::new_from_slice(&send).unwrap();
        let mut packet = vec![TRANSPORT_DATA, 0, 0, 0];
        packet.extend_from_slice(&RESPONDER_INDEX.to_le_bytes());
        packet.extend_from_slice(&0u64.to_le_bytes());
        packet.extend(
            cipher
                .encrypt(
                    Nonce::from_slice(&le_nonce(0)),
                    b"0123456789abcdef".as_slice(),
                )
                .unwrap(),
        );

        let almost = session.established + SESSION_LIFETIME - Duration::from_millis(1);
        assert!(session.decrypt_at(&packet, almost).is_ok());
        let expired = session.established + SESSION_LIFETIME;
        assert_eq!(
            session
                .decrypt_at(&packet, expired)
                .unwrap_err()
                .to_string(),
            "WireGuard packet: session expired"
        );
    }

    #[test]
    fn counters_stop_before_the_message_limit() {
        let (mut session, _, _) = established();
        let mut packet = vec![TRANSPORT_DATA, 0, 0, 0];
        packet.extend_from_slice(&RESPONDER_INDEX.to_le_bytes());
        packet.extend_from_slice(&MESSAGE_LIMIT.to_le_bytes());
        packet.extend_from_slice(&[0; 16]);
        assert_eq!(
            session.decrypt(&packet).unwrap_err().to_string(),
            "WireGuard packet: counter is past the session limit"
        );

        session.send_counter = MESSAGE_LIMIT - 1;
        let last = session.encrypt(b"last").unwrap();
        assert_eq!(last[8..16], (MESSAGE_LIMIT - 1).to_le_bytes());
        assert_eq!(
            session.encrypt(b"over").unwrap_err().to_string(),
            "WireGuard packet: session message limit reached"
        );
    }

    #[test]
    fn kdf_matches_hkdf_with_hmac_blake2s() {
        // RFC 5869 HKDF-Expand with BLAKE2s, written out step by step.
        let key = [7u8; 32];
        let prk = hmac(&key, b"input");
        let t1 = hmac(&prk, &[1]);
        let t2 = hmac(&prk, &[&t1[..], &[2]].concat());
        let t3 = hmac(&prk, &[&t2[..], &[3]].concat());
        assert_eq!(kdf::<1>(&key, b"input").map(|k| *k), [t1]);
        assert_eq!(kdf::<2>(&key, b"input").map(|k| *k), [t1, t2]);
        assert_eq!(kdf::<3>(&key, b"input").map(|k| *k), [t1, t2, t3]);
    }

    #[test]
    fn hmac_hashes_keys_longer_than_a_block() {
        // RFC 2104: keys longer than the 64-byte block are replaced by their hash.
        let long_key = [0x0bu8; 80];
        assert_eq!(hmac(&long_key, b"x"), hmac(&hash(&[&long_key]), b"x"));
        let block_key = [0x0bu8; 64];
        assert_ne!(hmac(&block_key, b"x"), hmac(&hash(&[&block_key]), b"x"));
    }
}
