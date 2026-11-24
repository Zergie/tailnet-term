use std::{
    error::Error,
    fs,
    io::{self, Write},
    net::Ipv4Addr,
    path::Path,
    ptr::null_mut,
};

use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    },
};

pub type PublicKey = [u8; 32];
pub type Challenge = [u8; 32];
pub const SIGNATURE_LEN: usize = 64;

pub fn keygen(path: &Path) -> Result<(), Box<dyn Error>> {
    // The private key is built in buffers this function owns so it can zero them; ring's
    // `generate_pkcs8` returns a `Document` that cannot be wiped.
    let mut seed = [0; 32];
    getrandom::getrandom(&mut seed).map_err(|error| error.to_string())?;
    let mut pkcs8 = pkcs8_v2(&seed);
    wipe(&mut seed);
    let result = write_key(path, &pkcs8);
    wipe(&mut pkcs8);
    let public_key = result?;
    println!("Client public key: {}", hex(&public_key));
    Ok(())
}

fn write_key(path: &Path, pkcs8: &[u8]) -> Result<PublicKey, Box<dyn Error>> {
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| "invalid generated key")?;
    let protected = dpapi(pkcs8, true)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&protected)?;
    file.sync_all()?;
    Ok(pair.public_key().as_ref().try_into()?)
}

/// PKCS#8 v2 (RFC 8410 OneAsymmetricKey including the public key): the format ring's
/// `Ed25519KeyPair::generate_pkcs8` produces and `from_pkcs8` requires.
fn pkcs8_v2(seed: &[u8; 32]) -> Vec<u8> {
    const PREFIX: [u8; 16] = [
        0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    const PUBLIC_KEY_TAG: [u8; 3] = [0x81, 0x21, 0x00];
    let pair =
        Ed25519KeyPair::from_seed_unchecked(seed).expect("any 32-byte seed is a valid Ed25519 key");
    let mut document = Vec::with_capacity(PREFIX.len() + 32 + PUBLIC_KEY_TAG.len() + 32);
    document.extend_from_slice(&PREFIX);
    document.extend_from_slice(seed);
    document.extend_from_slice(&PUBLIC_KEY_TAG);
    document.extend_from_slice(pair.public_key().as_ref());
    document
}

/// Zeroes secret bytes with volatile writes so the stores are not optimized away.
fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // The pointer comes from a live mutable reference.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

pub fn load_key(path: &Path) -> Result<Ed25519KeyPair, Box<dyn Error>> {
    let protected = fs::read(path)?;
    let mut plain = dpapi(&protected, false)?;
    let key = Ed25519KeyPair::from_pkcs8(&plain).map_err(|_| "invalid private key file".into());
    wipe(&mut plain);
    key
}

pub(crate) fn dpapi(bytes: &[u8], protect: bool) -> io::Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes
            .len()
            .try_into()
            .map_err(|_| io::Error::other("key blob too large"))?,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // DPAPI borrows the input and returns a buffer allocated with LocalAlloc.
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                null_mut(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                null_mut(),
                std::ptr::null(),
                null_mut(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // A successful call owns the returned buffer until LocalFree.
    unsafe {
        let data = std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize);
        let owned = data.to_vec();
        wipe(data);
        LocalFree(output.pbData.cast());
        Ok(owned)
    }
}

pub fn parse_key(value: &str) -> Result<PublicKey, Box<dyn Error>> {
    if value.len() != 64 || !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err("public key must contain 64 hexadecimal characters".into());
    }
    let mut public_key = [0; 32];
    for (index, byte) in public_key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * index..2 * index + 2], 16)?;
    }
    Ok(public_key)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(result, "{byte:02x}").expect("String write");
    }
    result
}

pub fn challenge() -> Result<Challenge, Box<dyn Error>> {
    let mut challenge = [0; 32];
    getrandom::getrandom(&mut challenge).map_err(|error| error.to_string())?;
    Ok(challenge)
}

fn signed_message(server: Ipv4Addr, nonce: &Challenge) -> Vec<u8> {
    let mut message = b"tailnet-terminal/client-auth/v1\0".to_vec();
    message.extend_from_slice(&server.octets());
    message.extend_from_slice(nonce);
    message
}

pub fn sign(key: &Ed25519KeyPair, server: Ipv4Addr, nonce: &Challenge) -> [u8; SIGNATURE_LEN] {
    key.sign(&signed_message(server, nonce))
        .as_ref()
        .try_into()
        .expect("Ed25519 signature length")
}

pub fn verify(key: &PublicKey, server: Ipv4Addr, nonce: &Challenge, signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&ED25519, key)
        .verify(&signed_message(server, nonce), signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_pkcs8_document_ring_generates() {
        let seed = [42; 32];
        let document = pkcs8_v2(&seed);
        let pair = Ed25519KeyPair::from_pkcs8(&document).unwrap();
        let expected = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        assert_eq!(pair.public_key().as_ref(), expected.public_key().as_ref());
        let generated = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let generated = generated.as_ref();
        assert_eq!(generated.len(), document.len());
        assert_eq!(generated[..16], document[..16]);
        assert_eq!(generated[48..51], document[48..51]);
    }

    #[test]
    fn wipe_zeroes_bytes() {
        let mut secret = [7u8; 40];
        wipe(&mut secret);
        assert_eq!(secret, [0; 40]);
    }

    #[test]
    fn signature_is_bound_to_the_server_and_challenge() {
        let private = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let public_key = parse_key(&hex(private.public_key().as_ref())).unwrap();
        let nonce = challenge().unwrap();
        let ip = Ipv4Addr::new(100, 64, 0, 1);
        let signature = sign(&private, ip, &nonce);
        assert!(verify(&public_key, ip, &nonce, &signature));
        assert!(!verify(&public_key, ip, &[0; 32], &signature));
        assert!(!verify(
            &public_key,
            Ipv4Addr::new(100, 64, 0, 2),
            &nonce,
            &signature
        ));
        assert!(!verify(&[0; 32], ip, &nonce, &signature));
    }
}
