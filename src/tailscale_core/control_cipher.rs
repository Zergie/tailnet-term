//! Noise IK handshake with the control server and the record encryption that
//! follows it.
//!
//! A record on the wire is `[type: u8][length: u16 BE][body]`. The very first
//! client message additionally carries a two-byte protocol version in front.

use anyhow::{Result, anyhow, bail};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use snow::{Builder, HandshakeState};
use zeroize::Zeroizing;

/// Record carrying the client's handshake initiation.
pub const RECORD_INITIATION: u8 = 1;
/// Record carrying the server's handshake response.
pub const RECORD_RESPONSE: u8 = 2;
/// Record carrying a plaintext error message from the server.
pub const RECORD_ERROR: u8 = 3;
/// Record carrying encrypted application data.
pub const RECORD_DATA: u8 = 4;

/// Largest plaintext that fits one record once the 16-byte tag is added.
pub const MAX_PLAINTEXT: usize = u16::MAX as usize - 16;

const PROTOCOL_VERSION: u16 = 1;
const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"Tailscale Control Protocol v1";

/// Handshake state between sending the initiation and reading the response.
pub struct PendingHandshake {
    state: HandshakeState,
}

/// Seals outgoing and opens incoming data records once the handshake is done.
pub struct RecordCipher {
    sealer: ChaCha20Poly1305,
    opener: ChaCha20Poly1305,
    sent: u64,
    received: u64,
}

/// Starts the handshake and returns the state plus the complete first frame
/// (version, record header and Noise message) to send to the server.
pub fn begin_handshake(
    machine_key: &[u8; 32],
    server_key: &[u8; 32],
) -> Result<(PendingHandshake, Vec<u8>)> {
    let params = PATTERN
        .parse()
        .map_err(|err| anyhow!("control handshake: invalid Noise pattern: {err}"))?;
    let mut state = Builder::new(params)
        .prologue(PROLOGUE)
        .and_then(|b| b.local_private_key(machine_key))
        .and_then(|b| b.remote_public_key(server_key))
        .and_then(|b| b.build_initiator())
        .map_err(|err| anyhow!("control handshake: cannot set up the initiator: {err}"))?;

    let mut buf = [0u8; 256];
    let n = state
        .write_message(&[], &mut buf)
        .map_err(|err| anyhow!("control handshake: cannot write the initiation: {err}"))?;

    let mut frame = Vec::with_capacity(5 + n);
    frame.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    frame.push(RECORD_INITIATION);
    frame.extend_from_slice(&(n as u16).to_be_bytes());
    frame.extend_from_slice(&buf[..n]);
    Ok((PendingHandshake { state }, frame))
}

impl PendingHandshake {
    /// Consumes the body of the server's [`RECORD_RESPONSE`] record.
    pub fn finish(mut self, response: &[u8]) -> Result<RecordCipher> {
        let mut buf = [0u8; 256];
        self.state
            .read_message(response, &mut buf)
            .map_err(|err| anyhow!("control handshake: server response rejected: {err}"))?;
        if !self.state.is_handshake_finished() {
            bail!("control handshake: still incomplete after the server response");
        }
        let (send_key, recv_key) = self.state.dangerously_get_raw_split();
        let (send_key, recv_key) = (Zeroizing::new(send_key), Zeroizing::new(recv_key));
        RecordCipher::new(&send_key, &recv_key)
    }
}

impl RecordCipher {
    fn new(send_key: &[u8; 32], recv_key: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            sealer: ChaCha20Poly1305::new_from_slice(send_key)
                .map_err(|_| anyhow!("control handshake: invalid sending key"))?,
            opener: ChaCha20Poly1305::new_from_slice(recv_key)
                .map_err(|_| anyhow!("control handshake: invalid receiving key"))?,
            sent: 0,
            received: 0,
        })
    }

    /// Encrypts `plaintext` and returns a complete [`RECORD_DATA`] record.
    pub fn seal_record(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_PLAINTEXT {
            bail!(
                "control record: {} bytes exceeds the {MAX_PLAINTEXT}-byte limit",
                plaintext.len()
            );
        }
        let nonce = record_nonce(next_counter(&mut self.sent)?);
        let sealed = self
            .sealer
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: b"",
                },
            )
            .map_err(|_| anyhow!("control record: encryption failed"))?;
        let mut out = Vec::with_capacity(3 + sealed.len());
        out.push(RECORD_DATA);
        out.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Decrypts the body of a received [`RECORD_DATA`] record.
    ///
    /// The receive counter advances even when authentication fails, so a
    /// failed record makes the rest of the stream undecryptable.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let counter = next_counter(&mut self.received)?;
        let nonce = record_nonce(counter);
        self.opener
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: b"",
                },
            )
            .map_err(|_| anyhow!("control record {counter}: authentication failed"))
    }
}

/// Returns the current value of a nonce counter and advances it. The last
/// value is never handed out, so a nonce can never repeat.
fn next_counter(counter: &mut u64) -> Result<u64> {
    let current = *counter;
    *counter = current
        .checked_add(1)
        .ok_or_else(|| anyhow!("control record: nonce counter exhausted"))?;
    Ok(current)
}

/// Control records use a big-endian counter in the last eight nonce bytes.
fn record_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    const CLIENT_SECRET: [u8; 32] = [0x11; 32];
    const SERVER_SECRET: [u8; 32] = [0x22; 32];

    fn public(secret: [u8; 32]) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(secret)).to_bytes()
    }

    /// Runs the handshake against an independent `snow` responder and returns
    /// the client cipher plus the responder's (client→server, server→client)
    /// raw keys.
    pub(crate) fn handshake() -> (RecordCipher, [u8; 32], [u8; 32]) {
        let (pending, frame) = begin_handshake(&CLIENT_SECRET, &public(SERVER_SECRET)).unwrap();

        assert_eq!(&frame[..2], &[0, 1], "protocol version");
        assert_eq!(frame[2], RECORD_INITIATION);
        let len = u16::from_be_bytes([frame[3], frame[4]]) as usize;
        assert_eq!(frame.len(), 5 + len);

        let mut responder = Builder::new(PATTERN.parse().unwrap())
            .prologue(PROLOGUE)
            .unwrap()
            .local_private_key(&SERVER_SECRET)
            .unwrap()
            .build_responder()
            .unwrap();
        let mut buf = [0u8; 256];
        responder.read_message(&frame[5..], &mut buf).unwrap();
        assert_eq!(
            responder.get_remote_static(),
            Some(&public(CLIENT_SECRET)[..])
        );
        let n = responder.write_message(&[], &mut buf).unwrap();

        let cipher = pending.finish(&buf[..n]).unwrap();
        let (to_server, to_client) = responder.dangerously_get_raw_split();
        (cipher, to_server, to_client)
    }

    pub(crate) fn be_nonce(counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        nonce
    }

    #[test]
    fn sealed_records_open_with_the_servers_key_and_big_endian_nonces() {
        let (mut cipher, to_server, _) = handshake();
        let server = ChaCha20Poly1305::new_from_slice(&to_server).unwrap();

        for (counter, message) in [b"first".as_slice(), b"second", b"third"]
            .into_iter()
            .enumerate()
        {
            let record = cipher.seal_record(message).unwrap();
            assert_eq!(record[0], RECORD_DATA);
            let len = u16::from_be_bytes([record[1], record[2]]) as usize;
            assert_eq!(len, message.len() + 16);
            assert_eq!(record.len(), 3 + len);
            let plain = server
                .decrypt(Nonce::from_slice(&be_nonce(counter as u64)), &record[3..])
                .unwrap();
            assert_eq!(plain, message);
        }
    }

    #[test]
    fn opens_records_sealed_by_the_server_in_order() {
        let (mut cipher, _, to_client) = handshake();
        let server = ChaCha20Poly1305::new_from_slice(&to_client).unwrap();
        let first = server
            .encrypt(Nonce::from_slice(&be_nonce(0)), b"a".as_slice())
            .unwrap();
        let second = server
            .encrypt(Nonce::from_slice(&be_nonce(1)), b"bc".as_slice())
            .unwrap();

        assert_eq!(cipher.open(&first).unwrap(), b"a");
        assert_eq!(cipher.open(&second).unwrap(), b"bc");
    }

    #[test]
    fn refuses_to_reuse_a_nonce_when_counters_run_out() {
        let (mut cipher, _, _) = handshake();
        cipher.sent = u64::MAX - 1;
        assert!(cipher.seal_record(b"last").is_ok());
        let err = cipher.seal_record(b"one too many").unwrap_err();
        assert_eq!(err.to_string(), "control record: nonce counter exhausted");
        assert_eq!(
            cipher.sent,
            u64::MAX,
            "a refused record does not move the counter"
        );

        cipher.received = u64::MAX;
        let err = cipher.open(&[0; 16]).unwrap_err();
        assert_eq!(err.to_string(), "control record: nonce counter exhausted");
    }

    #[test]
    fn rejects_tampered_or_replayed_records() {
        let (mut cipher, _, to_client) = handshake();
        let server = ChaCha20Poly1305::new_from_slice(&to_client).unwrap();
        let mut record = server
            .encrypt(Nonce::from_slice(&be_nonce(0)), b"hi".as_slice())
            .unwrap();
        record[0] ^= 1;
        let err = cipher.open(&record).unwrap_err().to_string();
        assert!(err == "control record 0: authentication failed", "{err}");

        // The counter has moved on, so even the genuine record no longer opens.
        record[0] ^= 1;
        let err = cipher.open(&record).unwrap_err().to_string();
        assert!(err == "control record 1: authentication failed", "{err}");
    }

    #[test]
    fn enforces_the_record_size_limit() {
        let (mut cipher, _, _) = handshake();
        let record = cipher.seal_record(&vec![0; MAX_PLAINTEXT]).unwrap();
        assert_eq!(u16::from_be_bytes([record[1], record[2]]), u16::MAX);
        assert!(cipher.seal_record(&vec![0; MAX_PLAINTEXT + 1]).is_err());
    }

    #[test]
    fn handshake_fails_for_the_wrong_server_key() {
        let (pending, frame) = begin_handshake(&CLIENT_SECRET, &public([0x33; 32])).unwrap();
        let mut responder = Builder::new(PATTERN.parse().unwrap())
            .prologue(PROLOGUE)
            .unwrap()
            .local_private_key(&SERVER_SECRET)
            .unwrap()
            .build_responder()
            .unwrap();
        let mut buf = [0u8; 256];
        assert!(responder.read_message(&frame[5..], &mut buf).is_err());
        assert!(pending.finish(&[0; 48]).is_err());
    }
}
