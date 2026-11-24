//! HTTP/2 frame layout (RFC 9113 §4) and the frame types and flags we use.

use anyhow::{Result, anyhow, bail};

pub(super) const TYPE_DATA: u8 = 0x0;
pub(super) const TYPE_HEADERS: u8 = 0x1;
pub(super) const TYPE_RST_STREAM: u8 = 0x3;
pub(super) const TYPE_SETTINGS: u8 = 0x4;
pub(super) const TYPE_PUSH_PROMISE: u8 = 0x5;
pub(super) const TYPE_PING: u8 = 0x6;
pub(super) const TYPE_GOAWAY: u8 = 0x7;
pub(super) const TYPE_WINDOW_UPDATE: u8 = 0x8;
pub(super) const TYPE_CONTINUATION: u8 = 0x9;

pub(super) const FLAG_END_STREAM: u8 = 0x1;
pub(super) const FLAG_ACK: u8 = 0x1;
pub(super) const FLAG_END_HEADERS: u8 = 0x4;
pub(super) const FLAG_PADDED: u8 = 0x8;
pub(super) const FLAG_PRIORITY: u8 = 0x20;

pub(super) const HEADER_LEN: usize = 9;
pub(super) const STREAM_ID_MASK: u32 = 0x7fff_ffff;

pub(super) struct Frame {
    pub kind: u8,
    pub flags: u8,
    pub stream: u32,
    /// Payload length as received, padding included; this is what counts
    /// against flow control. Only set for DATA frames.
    pub flow_len: u32,
    /// Payload with padding (and for HEADERS, priority fields) removed.
    pub payload: Vec<u8>,
}

pub(super) fn encode_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = Vec::with_capacity(HEADER_LEN + len);
    out.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&(stream & STREAM_ID_MASK).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Removes the pad-length byte and trailing padding when `FLAG_PADDED` is set.
pub(super) fn strip_padding(mut payload: Vec<u8>, flags: u8) -> Result<Vec<u8>> {
    if flags & FLAG_PADDED == 0 {
        return Ok(payload);
    }
    let pad = *payload
        .first()
        .ok_or_else(|| anyhow!("HTTP/2 PROTOCOL_ERROR: padded frame has no pad length"))?
        as usize;
    if pad >= payload.len() {
        bail!("HTTP/2 PROTOCOL_ERROR: padding length {pad} exceeds the frame payload");
    }
    payload.truncate(payload.len() - pad);
    payload.remove(0);
    Ok(payload)
}

pub(super) fn be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes[..4].try_into().expect("four bytes"))
}

pub(super) fn describe_reset(frame: &Frame) -> String {
    let code = frame.payload.get(..4).map(be_u32).unwrap_or(0);
    format!(
        "HTTP/2 stream {} reset by server: {} (0x{code:x})",
        frame.stream,
        error_name(code)
    )
}

pub(super) fn error_name(code: u32) -> &'static str {
    match code {
        0x0 => "NO_ERROR",
        0x1 => "PROTOCOL_ERROR",
        0x2 => "INTERNAL_ERROR",
        0x3 => "FLOW_CONTROL_ERROR",
        0x4 => "SETTINGS_TIMEOUT",
        0x5 => "STREAM_CLOSED",
        0x6 => "FRAME_SIZE_ERROR",
        0x7 => "REFUSED_STREAM",
        0x8 => "CANCEL",
        0x9 => "COMPRESSION_ERROR",
        0xa => "CONNECT_ERROR",
        0xb => "ENHANCE_YOUR_CALM",
        0xc => "INADEQUATE_SECURITY",
        0xd => "HTTP_1_1_REQUIRED",
        _ => "UNKNOWN_ERROR",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_nine_byte_header() {
        assert_eq!(
            encode_frame(TYPE_DATA, FLAG_END_STREAM, 0x8000_0003, b"hey"),
            [0, 0, 3, 0x0, 0x1, 0, 0, 0, 3, b'h', b'e', b'y'],
            "reserved bit is cleared"
        );
        let big = encode_frame(TYPE_HEADERS, 0, 1, &vec![0; 0x01_0203]);
        assert_eq!(big[..3], [0x01, 0x02, 0x03]);
        assert_eq!(big.len(), 9 + 0x01_0203);
    }

    #[test]
    fn strips_padding_only_when_flagged() {
        assert_eq!(
            strip_padding(vec![2, b'a', b'b', 0, 0], 0).unwrap(),
            [2, b'a', b'b', 0, 0]
        );
        assert_eq!(
            strip_padding(vec![2, b'a', b'b', 0, 0], FLAG_PADDED).unwrap(),
            b"ab"
        );
        assert_eq!(strip_padding(vec![0, b'a'], FLAG_PADDED).unwrap(), b"a");
        assert_eq!(strip_padding(vec![1, 0], FLAG_PADDED).unwrap(), b"");
    }

    #[test]
    fn rejects_bad_padding() {
        let err = |payload: Vec<u8>| strip_padding(payload, FLAG_PADDED).unwrap_err().to_string();
        assert_eq!(
            err(vec![]),
            "HTTP/2 PROTOCOL_ERROR: padded frame has no pad length"
        );
        assert_eq!(
            err(vec![2, 0]),
            "HTTP/2 PROTOCOL_ERROR: padding length 2 exceeds the frame payload"
        );
        assert_eq!(
            err(vec![1]),
            "HTTP/2 PROTOCOL_ERROR: padding length 1 exceeds the frame payload"
        );
    }

    #[test]
    fn describes_resets() {
        let frame = |payload: Vec<u8>| Frame {
            kind: TYPE_RST_STREAM,
            flags: 0,
            stream: 5,
            flow_len: 0,
            payload,
        };
        assert_eq!(
            describe_reset(&frame(vec![0, 0, 0, 0x8])),
            "HTTP/2 stream 5 reset by server: CANCEL (0x8)"
        );
        assert_eq!(
            describe_reset(&frame(vec![0, 0, 1, 0])),
            "HTTP/2 stream 5 reset by server: UNKNOWN_ERROR (0x100)"
        );
        assert_eq!(
            describe_reset(&frame(vec![])),
            "HTTP/2 stream 5 reset by server: NO_ERROR (0x0)"
        );
    }
}
