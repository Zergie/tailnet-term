//! HTTP/2 client (RFC 9113) for the control protocol.
//!
//! It handles exactly what talking to the control server needs: one request
//! at a time, POST with a JSON body, flow control in both directions, and the
//! connection-level frames (SETTINGS, PING, WINDOW_UPDATE, GOAWAY). Server push
//! and the HPACK dynamic table are disabled.

mod frame;
mod hpack;

use std::collections::VecDeque;

use anyhow::{Result, anyhow, bail};

use self::frame::*;
use self::hpack::{find_status, write_header};
use super::control_cipher::{self, RecordCipher};
use super::control_link::ControlLink;

/// Client connection preface (RFC 9113 §3.4).
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Marks an optional payload the server sends ahead of its first frame:
/// the magic, a big-endian u32 length, then that many bytes.
const EARLY_PAYLOAD_MAGIC: &[u8] = b"\xff\xff\xffTS";
const MAX_EARLY_PAYLOAD: usize = 4096;
const MAX_HEADER_BLOCK: usize = 64 * 1024;
/// Largest response body accepted, after which the request fails.
const MAX_RESPONSE_BODY: usize = 16 * 1024 * 1024;
/// While a request body waits for flow control we send no stream-level
/// WINDOW_UPDATE, so an honest server can deliver at most one window of data
/// plus its headers before we read the response. These bound what is held.
const MAX_DEFERRED_BYTES: usize = DEFAULT_WINDOW as usize + MAX_HEADER_BLOCK;
const MAX_DEFERRED_FRAMES: usize = 256;
const DEFAULT_MAX_FRAME_SIZE: u32 = 16384;

/// Initial flow-control window from RFC 9113 §6.9.2.
const DEFAULT_WINDOW: i64 = 65535;
const MAX_WINDOW: i64 = 0x7fff_ffff;
const SETTING_HEADER_TABLE_SIZE: u16 = 0x1;
const SETTING_ENABLE_PUSH: u16 = 0x2;
const SETTING_INITIAL_WINDOW_SIZE: u16 = 0x4;
const SETTING_MAX_FRAME_SIZE: u16 = 0x5;

/// HTTP/2 client issuing one request at a time over a [`RecordPipe`].
pub struct Http2Client {
    pipe: Box<dyn RecordPipe>,
    /// Decrypted bytes not yet consumed as frames.
    inbox: Vec<u8>,
    next_stream: u32,
    authority: String,
    /// Largest frame payload the server accepts.
    max_frame: usize,
    peer_initial_window: i64,
    /// Connection-level send window.
    send_window: i64,
    streams: Vec<StreamWindow>,
    /// Stream frames read while blocked on flow control.
    deferred: VecDeque<Frame>,
    /// Last stream id from a GOAWAY; set once the server is shutting down.
    goaway_last: Option<u32>,
}

/// Send window of a stream that is still open.
struct StreamWindow {
    id: u32,
    window: i64,
}

/// Carries opaque HTTP/2 bytes; `receive` returns whatever arrived next.
trait RecordPipe {
    fn transmit(&mut self, data: &[u8]) -> Result<()>;
    fn receive(&mut self) -> Result<Vec<u8>>;
}

/// [`RecordPipe`] over an encrypted control link.
struct EncryptedPipe {
    link: ControlLink,
    cipher: RecordCipher,
}

impl Http2Client {
    /// Sends the preface and settings and waits for the server's settings.
    /// Also returns the early payload, if the server sent one.
    pub fn establish(
        link: ControlLink,
        cipher: RecordCipher,
        authority: String,
    ) -> Result<(Self, Option<Vec<u8>>)> {
        Self::over_pipe(Box::new(EncryptedPipe { link, cipher }), authority)
    }

    fn over_pipe(pipe: Box<dyn RecordPipe>, authority: String) -> Result<(Self, Option<Vec<u8>>)> {
        let mut client = Http2Client {
            pipe,
            inbox: Vec::new(),
            next_stream: 1,
            authority,
            max_frame: DEFAULT_MAX_FRAME_SIZE as usize,
            peer_initial_window: DEFAULT_WINDOW,
            send_window: DEFAULT_WINDOW,
            streams: Vec::new(),
            deferred: VecDeque::new(),
            goaway_last: None,
        };

        let mut settings = Vec::new();
        for (id, value) in [
            (SETTING_HEADER_TABLE_SIZE, 0),
            (SETTING_ENABLE_PUSH, 0),
            (SETTING_MAX_FRAME_SIZE, DEFAULT_MAX_FRAME_SIZE),
        ] {
            settings.extend_from_slice(&id.to_be_bytes());
            settings.extend_from_slice(&value.to_be_bytes());
        }
        let mut opening = Vec::new();
        opening.extend_from_slice(PREFACE);
        opening.extend_from_slice(&encode_frame(TYPE_SETTINGS, 0, 0, &settings));
        client.pipe.transmit(&opening)?;

        let early = client.read_early_payload()?;

        loop {
            let frame = client.pull_frame()?;
            let got_settings = frame.kind == TYPE_SETTINGS && frame.flags & FLAG_ACK == 0;
            client.handle_frame(frame, 0)?;
            if got_settings {
                break;
            }
        }
        Ok((client, early))
    }

    /// POSTs a JSON `body` to `path` and returns the status and response body.
    pub fn post(&mut self, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
        let stream = self.start_request(path, body)?;
        let result = self.read_response(stream);
        self.forget(stream);
        result
    }

    fn read_response(&mut self, stream: u32) -> Result<(u16, Vec<u8>)> {
        let mut status: Option<u16> = None;
        let mut body: Vec<u8> = Vec::new();
        loop {
            let frame = self.next_frame(stream)?;
            if frame.stream != stream {
                continue;
            }
            match frame.kind {
                TYPE_HEADERS => {
                    if let Some(s) = find_status(&frame.payload)? {
                        status = Some(s);
                    }
                    if frame.flags & FLAG_END_STREAM != 0 {
                        break;
                    }
                }
                TYPE_DATA => {
                    if body.len() + frame.payload.len() > MAX_RESPONSE_BODY {
                        bail!(
                            "HTTP/2 stream {stream}: response body exceeds {MAX_RESPONSE_BODY} bytes"
                        );
                    }
                    body.extend_from_slice(&frame.payload);
                    self.replenish(&frame)?;
                    if frame.flags & FLAG_END_STREAM != 0 {
                        break;
                    }
                }
                TYPE_RST_STREAM => match status {
                    Some(status) => bail!("{} after status {status}", describe_reset(&frame)),
                    None => bail!("{}", describe_reset(&frame)),
                },
                _ => {}
            }
        }
        let status =
            status.ok_or_else(|| anyhow!("HTTP/2 stream {stream}: response has no :status"))?;
        Ok((status, strip_length_prefix(body)))
    }

    fn start_request(&mut self, path: &str, body: &[u8]) -> Result<u32> {
        if let Some(last_stream) = self.goaway_last {
            bail!("HTTP/2: connection is closing (server sent GOAWAY, last stream {last_stream})");
        }
        let stream = self.next_stream;
        if stream > STREAM_ID_MASK {
            bail!("HTTP/2: stream ids exhausted");
        }
        self.next_stream += 2;

        let mut header = Vec::new();
        write_header(&mut header, ":method", "POST");
        write_header(&mut header, ":scheme", "http");
        write_header(&mut header, ":authority", &self.authority);
        write_header(&mut header, ":path", path);
        write_header(&mut header, "content-type", "application/json");
        write_header(&mut header, "content-length", &body.len().to_string());
        write_header(&mut header, "accept", "application/json");

        self.streams.push(StreamWindow {
            id: stream,
            window: self.peer_initial_window,
        });

        let mut out = Vec::new();
        let chunks: Vec<&[u8]> = header.chunks(self.max_frame).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            let kind = if i == 0 {
                TYPE_HEADERS
            } else {
                TYPE_CONTINUATION
            };
            let mut flags = 0;
            if i + 1 == chunks.len() {
                flags |= FLAG_END_HEADERS;
            }
            if i == 0 && body.is_empty() {
                flags |= FLAG_END_STREAM;
            }
            out.extend_from_slice(&encode_frame(kind, flags, stream, chunk));
        }
        self.pipe.transmit(&out)?;

        if !body.is_empty() {
            self.send_body(stream, body)?;
        }
        Ok(stream)
    }

    fn send_body(&mut self, stream: u32, mut body: &[u8]) -> Result<()> {
        while !body.is_empty() {
            let stream_window = self
                .streams
                .iter()
                .find(|s| s.id == stream)
                .map(|s| s.window)
                .ok_or_else(|| {
                    anyhow!("HTTP/2 stream {stream}: closed while sending the request body")
                })?;
            let allowed = self
                .send_window
                .min(stream_window)
                .min(self.max_frame as i64);
            if allowed <= 0 {
                let frame = self.pull_frame()?;
                if let Some(frame) = self.handle_frame(frame, stream)? {
                    if frame.stream == stream {
                        if frame.kind == TYPE_RST_STREAM {
                            bail!("{} while sending the request body", describe_reset(&frame));
                        }
                        let ended = frame.flags & FLAG_END_STREAM != 0;
                        self.deferred.push_back(frame);
                        let held: usize = self.deferred.iter().map(held_bytes).sum();
                        if held > MAX_DEFERRED_BYTES || self.deferred.len() > MAX_DEFERRED_FRAMES {
                            bail!(
                                "HTTP/2 stream {stream}: server sent more than its flow-control \
                                 window while the request body was blocked"
                            );
                        }
                        if ended {
                            self.pipe.transmit(&encode_frame(
                                TYPE_RST_STREAM,
                                0,
                                stream,
                                &0u32.to_be_bytes(),
                            ))?;
                            return Ok(());
                        }
                    }
                }
                continue;
            }
            let n = (allowed as usize).min(body.len());
            let (chunk, remaining) = body.split_at(n);
            let flags = if remaining.is_empty() {
                FLAG_END_STREAM
            } else {
                0
            };
            self.pipe
                .transmit(&encode_frame(TYPE_DATA, flags, stream, chunk))?;
            self.send_window -= n as i64;
            if let Some(s) = self.streams.iter_mut().find(|s| s.id == stream) {
                s.window -= n as i64;
            }
            body = remaining;
        }
        Ok(())
    }

    fn forget(&mut self, stream: u32) {
        self.streams.retain(|s| s.id != stream);
        self.deferred.retain(|queued| queued.stream != stream);
    }

    fn next_frame(&mut self, waiting_for: u32) -> Result<Frame> {
        loop {
            if let Some(frame) = self.deferred.pop_front() {
                return Ok(frame);
            }
            let frame = self.pull_frame()?;
            if let Some(frame) = self.handle_frame(frame, waiting_for)? {
                return Ok(frame);
            }
        }
    }

    fn handle_frame(&mut self, frame: Frame, waiting_for: u32) -> Result<Option<Frame>> {
        match frame.kind {
            TYPE_SETTINGS => {
                if frame.stream != 0 {
                    bail!(
                        "HTTP/2 PROTOCOL_ERROR: SETTINGS frame on stream {}",
                        frame.stream
                    );
                }
                if frame.flags & FLAG_ACK != 0 {
                    if !frame.payload.is_empty() {
                        bail!("HTTP/2 FRAME_SIZE_ERROR: SETTINGS ACK carries a payload");
                    }
                } else {
                    self.apply_settings(&frame.payload)?;
                    self.pipe
                        .transmit(&encode_frame(TYPE_SETTINGS, FLAG_ACK, 0, &[]))?;
                }
                Ok(None)
            }
            TYPE_PING => {
                if frame.stream != 0 {
                    bail!(
                        "HTTP/2 PROTOCOL_ERROR: PING frame on stream {}",
                        frame.stream
                    );
                }
                if frame.payload.len() != 8 {
                    bail!(
                        "HTTP/2 FRAME_SIZE_ERROR: PING payload of {} bytes, expected 8",
                        frame.payload.len()
                    );
                }
                if frame.flags & FLAG_ACK == 0 {
                    self.pipe
                        .transmit(&encode_frame(TYPE_PING, FLAG_ACK, 0, &frame.payload))?;
                }
                Ok(None)
            }
            TYPE_WINDOW_UPDATE => {
                if frame.payload.len() != 4 {
                    bail!(
                        "HTTP/2 FRAME_SIZE_ERROR: WINDOW_UPDATE payload of {} bytes, expected 4",
                        frame.payload.len()
                    );
                }
                let increment = i64::from(be_u32(&frame.payload) & STREAM_ID_MASK);
                if increment == 0 {
                    bail!(
                        "HTTP/2 PROTOCOL_ERROR: WINDOW_UPDATE with zero increment on stream {}",
                        frame.stream
                    );
                }
                let slot = if frame.stream == 0 {
                    Some(&mut self.send_window)
                } else {
                    self.streams
                        .iter_mut()
                        .find(|s| s.id == frame.stream)
                        .map(|s| &mut s.window)
                };
                if let Some(window) = slot {
                    *window += increment;
                    if *window > MAX_WINDOW {
                        bail!(
                            "HTTP/2 FLOW_CONTROL_ERROR: send window of stream {} exceeds 2^31-1",
                            frame.stream
                        );
                    }
                }
                Ok(None)
            }
            TYPE_GOAWAY => {
                if frame.payload.len() < 8 {
                    bail!(
                        "HTTP/2 FRAME_SIZE_ERROR: GOAWAY payload of {} bytes, expected at least 8",
                        frame.payload.len()
                    );
                }
                let bytes = &frame.payload;
                let last_stream = be_u32(bytes) & STREAM_ID_MASK;
                let code = be_u32(&bytes[4..]);
                self.goaway_last = Some(last_stream);
                if code != 0 || waiting_for == 0 || waiting_for > last_stream {
                    let debug = String::from_utf8_lossy(&bytes[8..]);
                    bail!(
                        "HTTP/2 server sent GOAWAY: {} (0x{code:x}), last stream {last_stream}{}{}",
                        error_name(code),
                        if debug.is_empty() { "" } else { ": " },
                        debug
                    );
                }
                Ok(None)
            }
            TYPE_DATA => {
                if frame.stream == 0 {
                    bail!("HTTP/2 PROTOCOL_ERROR: DATA frame on stream 0");
                }
                if frame.flow_len > 0 {
                    self.pipe.transmit(&encode_frame(
                        TYPE_WINDOW_UPDATE,
                        0,
                        0,
                        &frame.flow_len.to_be_bytes(),
                    ))?;
                }
                Ok(Some(frame))
            }
            TYPE_HEADERS => Ok(Some(frame)),
            TYPE_RST_STREAM => {
                if frame.payload.len() != 4 {
                    bail!(
                        "HTTP/2 FRAME_SIZE_ERROR: RST_STREAM payload of {} bytes, expected 4",
                        frame.payload.len()
                    );
                }
                self.streams.retain(|s| s.id != frame.stream);
                Ok(Some(frame))
            }
            TYPE_CONTINUATION => {
                bail!("HTTP/2 PROTOCOL_ERROR: CONTINUATION frame without a preceding HEADERS frame")
            }
            TYPE_PUSH_PROMISE => {
                bail!("HTTP/2 PROTOCOL_ERROR: PUSH_PROMISE received although push is disabled")
            }
            _ => Ok(None),
        }
    }

    fn apply_settings(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() % 6 != 0 {
            bail!(
                "HTTP/2 FRAME_SIZE_ERROR: SETTINGS payload of {} bytes is not a multiple of 6",
                payload.len()
            );
        }
        for s in payload.chunks_exact(6) {
            let id = u16::from_be_bytes([s[0], s[1]]);
            let value = u32::from_be_bytes([s[2], s[3], s[4], s[5]]);
            match id {
                SETTING_INITIAL_WINDOW_SIZE => {
                    let value = i64::from(value);
                    if value > MAX_WINDOW {
                        bail!(
                            "HTTP/2 FLOW_CONTROL_ERROR: initial window size {value} exceeds 2^31-1"
                        );
                    }
                    let delta = value - self.peer_initial_window;
                    for entry in &mut self.streams {
                        entry.window += delta;
                        if entry.window > MAX_WINDOW {
                            bail!(
                                "HTTP/2 FLOW_CONTROL_ERROR: send window of stream {} exceeds 2^31-1",
                                entry.id
                            );
                        }
                    }
                    self.peer_initial_window = value;
                }
                SETTING_MAX_FRAME_SIZE => {
                    if !(16384..=16_777_215).contains(&value) {
                        bail!(
                            "HTTP/2 PROTOCOL_ERROR: max frame size {value} is outside 16384..=16777215"
                        );
                    }
                    self.max_frame = value as usize;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn replenish(&mut self, frame: &Frame) -> Result<()> {
        if frame.flow_len > 0 && frame.flags & FLAG_END_STREAM == 0 {
            self.pipe.transmit(&encode_frame(
                TYPE_WINDOW_UPDATE,
                0,
                frame.stream,
                &frame.flow_len.to_be_bytes(),
            ))?;
        }
        Ok(())
    }

    fn read_exact(&mut self, n: usize) -> Result<Vec<u8>> {
        while self.inbox.len() < n {
            let plain = self.pipe.receive()?;
            self.inbox.extend_from_slice(&plain);
        }
        Ok(self.inbox.drain(..n).collect())
    }

    fn read_early_payload(&mut self) -> Result<Option<Vec<u8>>> {
        let header = self.read_exact(HEADER_LEN)?;
        if &header[..5] == EARLY_PAYLOAD_MAGIC {
            let early_len = be_u32(&header[5..]) as usize;
            if early_len > MAX_EARLY_PAYLOAD {
                bail!("HTTP/2: early payload of {early_len} bytes exceeds {MAX_EARLY_PAYLOAD}");
            }
            let early = self.read_exact(early_len)?;
            Ok(Some(early))
        } else {
            self.inbox.splice(0..0, header);
            Ok(None)
        }
    }

    fn pull_raw_frame(&mut self) -> Result<Frame> {
        let header = self.read_exact(HEADER_LEN)?;
        let len = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
        let kind = header[3];
        let flags = header[4];
        let stream = be_u32(&header[5..]) & STREAM_ID_MASK;
        if len > DEFAULT_MAX_FRAME_SIZE as usize {
            bail!(
                "HTTP/2 FRAME_SIZE_ERROR: {len}-byte frame of type 0x{kind:x} exceeds {DEFAULT_MAX_FRAME_SIZE}"
            );
        }
        let payload = if len > 0 {
            self.read_exact(len)?
        } else {
            Vec::new()
        };
        Ok(Frame {
            kind,
            flags,
            stream,
            flow_len: 0,
            payload,
        })
    }

    fn pull_frame(&mut self) -> Result<Frame> {
        let mut frame = self.pull_raw_frame()?;
        match frame.kind {
            TYPE_DATA => {
                frame.flow_len = frame.payload.len() as u32;
                frame.payload = strip_padding(frame.payload, frame.flags)?;
            }
            TYPE_HEADERS => {
                let mut block = strip_padding(std::mem::take(&mut frame.payload), frame.flags)?;
                if frame.flags & FLAG_PRIORITY != 0 {
                    if block.len() < 5 {
                        bail!(
                            "HTTP/2 FRAME_SIZE_ERROR: HEADERS frame too short for its priority fields"
                        );
                    }
                    block.drain(..5);
                }
                while frame.flags & FLAG_END_HEADERS == 0 {
                    let cont = self.pull_raw_frame()?;
                    if cont.kind != TYPE_CONTINUATION || cont.stream != frame.stream {
                        bail!(
                            "HTTP/2 PROTOCOL_ERROR: expected CONTINUATION on stream {}, got frame type 0x{:x} on stream {}",
                            frame.stream,
                            cont.kind,
                            cont.stream
                        );
                    }
                    if block.len() + cont.payload.len() > MAX_HEADER_BLOCK {
                        bail!("HTTP/2: header block exceeds {MAX_HEADER_BLOCK} bytes");
                    }
                    block.extend_from_slice(&cont.payload);
                    frame.flags |= cont.flags & FLAG_END_HEADERS;
                }
                frame.payload = block;
            }
            _ => {}
        }
        Ok(frame)
    }
}

impl RecordPipe for EncryptedPipe {
    fn transmit(&mut self, data: &[u8]) -> Result<()> {
        for chunk in data.chunks(2048) {
            let sealed = self.cipher.seal_record(chunk)?;
            self.link.write_all(&sealed)?;
        }
        Ok(())
    }

    fn receive(&mut self) -> Result<Vec<u8>> {
        let (kind, record) = self.link.read_record()?;
        match kind {
            control_cipher::RECORD_DATA => self.cipher.open(&record),
            control_cipher::RECORD_ERROR => {
                bail!(
                    "control server error: {}",
                    String::from_utf8_lossy(&record).trim()
                )
            }
            other => bail!("control record: unexpected type {other}"),
        }
    }
}

/// Bytes a held frame accounts for; padding counts, as it does for flow control.
fn held_bytes(frame: &Frame) -> usize {
    (frame.flow_len as usize).max(frame.payload.len())
}

/// Drops a 4-byte length prefix in front of a JSON body, if present.
fn strip_length_prefix(body: Vec<u8>) -> Vec<u8> {
    if body.len() >= 5 && body[0] != b'{' && body[4] == b'{' {
        body[4..].to_vec()
    } else {
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailscale_core::control_cipher::tests::{be_nonce, handshake};
    use crate::tailscale_core::control_link::{negotiate_upgrade, tests::ScriptedIo};
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
    use std::cell::RefCell;
    use std::rc::Rc;

    type Sent = Rc<RefCell<Vec<u8>>>;

    const AUTHORITY: &str = "control.example";
    const DATA: u8 = 0x0;
    const HEADERS: u8 = 0x1;
    const CONTINUATION: u8 = 0x9;
    const END_STREAM: u8 = 0x1;
    const END_HEADERS: u8 = 0x4;

    /// Replays scripted server bytes and records everything the client sends.
    struct ScriptedPipe {
        incoming: VecDeque<Vec<u8>>,
        sent: Sent,
    }

    impl RecordPipe for ScriptedPipe {
        fn transmit(&mut self, data: &[u8]) -> Result<()> {
            self.sent.borrow_mut().extend_from_slice(data);
            Ok(())
        }

        fn receive(&mut self) -> Result<Vec<u8>> {
            self.incoming
                .pop_front()
                .ok_or_else(|| anyhow!("pipe closed"))
        }
    }

    #[derive(Debug, PartialEq)]
    struct Sniffed {
        kind: u8,
        flags: u8,
        stream: u32,
        payload: Vec<u8>,
    }

    /// Frame bytes written out by hand, independent of `encode_frame`.
    fn raw(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut out = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
        out.extend_from_slice(&stream.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn settings(pairs: &[(u16, u32)]) -> Vec<u8> {
        let payload: Vec<u8> = pairs
            .iter()
            .flat_map(|(id, value)| [&id.to_be_bytes()[..], &value.to_be_bytes()[..]].concat())
            .collect();
        raw(0x4, 0, 0, &payload)
    }

    /// Splits client output into frames, independent of the client's parser.
    fn sniff(mut bytes: &[u8]) -> Vec<Sniffed> {
        let mut frames = Vec::new();
        while !bytes.is_empty() {
            let len = (usize::from(bytes[0]) << 16)
                | (usize::from(bytes[1]) << 8)
                | usize::from(bytes[2]);
            frames.push(Sniffed {
                kind: bytes[3],
                flags: bytes[4],
                stream: u32::from_be_bytes(bytes[5..9].try_into().unwrap()),
                payload: bytes[9..9 + len].to_vec(),
            });
            bytes = &bytes[9 + len..];
        }
        frames
    }

    fn sniffed(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Sniffed {
        Sniffed {
            kind,
            flags,
            stream,
            payload: payload.to_vec(),
        }
    }

    fn window_update(stream: u32, increment: u32) -> Sniffed {
        sniffed(0x8, 0, stream, &increment.to_be_bytes())
    }

    fn open(script: &[Vec<u8>]) -> Result<(Http2Client, Option<Vec<u8>>, Sent)> {
        let sent = Sent::default();
        let pipe = ScriptedPipe {
            incoming: script.iter().cloned().collect(),
            sent: sent.clone(),
        };
        let (client, early) = Http2Client::over_pipe(Box::new(pipe), AUTHORITY.to_string())?;
        Ok((client, early, sent))
    }

    /// A client past the handshake; `sent` only holds what follows it.
    fn connected_with(server_settings: Vec<u8>, script: &[Vec<u8>]) -> (Http2Client, Sent) {
        let mut full = vec![server_settings];
        full.extend_from_slice(script);
        let (client, _, sent) = open(&full).unwrap();
        sent.borrow_mut().clear();
        (client, sent)
    }

    fn connected(script: &[Vec<u8>]) -> (Http2Client, Sent) {
        connected_with(settings(&[]), script)
    }

    fn literal(name: &str, value: &str) -> Vec<u8> {
        [
            &[0, name.len() as u8],
            name.as_bytes(),
            &[value.len() as u8],
            value.as_bytes(),
        ]
        .concat()
    }

    fn request_block(path: &str, body_len: usize) -> Vec<u8> {
        [
            literal(":method", "POST"),
            literal(":scheme", "http"),
            literal(":authority", AUTHORITY),
            literal(":path", path),
            literal("content-type", "application/json"),
            literal("content-length", &body_len.to_string()),
            literal("accept", "application/json"),
        ]
        .concat()
    }

    /// Extracts a long (multi-byte length) `:path` value from a request block.
    fn long_path(block: &[u8]) -> String {
        let marker = b"\x05:path\x7f";
        let mut pos = block
            .windows(marker.len())
            .position(|w| w == marker)
            .unwrap()
            + marker.len();
        let (mut len, mut shift) = (0x7f_usize, 0);
        loop {
            let byte = block[pos];
            pos += 1;
            len += usize::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
        String::from_utf8(block[pos..pos + len].to_vec()).unwrap()
    }

    #[test]
    fn opens_with_preface_and_settings_and_acks_the_servers() {
        let (_, early, sent) = open(&[settings(&[])]).unwrap();
        assert_eq!(early, None);

        let sent = sent.borrow();
        assert_eq!(&sent[..24], b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        assert_eq!(
            sniff(&sent[24..]),
            [
                sniffed(
                    0x4,
                    0,
                    0,
                    &[0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 5, 0, 0, 0x40, 0]
                ),
                sniffed(0x4, 0x1, 0, &[]),
            ]
        );
    }

    #[test]
    fn answers_pings_and_ignores_unknown_frames_until_settings_arrive() {
        let (_, _, sent) = open(&[
            raw(0x4, 0x1, 0, &[]),
            raw(0x6, 0, 0, b"12345678"),
            raw(0x6, 0x1, 0, b"ignored!"),
            raw(0x2, 0, 1, &[0; 5]),
            raw(0xa, 0, 0, b"extension"),
            settings(&[(0x3, 100), (0x99, 1)]),
        ])
        .unwrap();
        let frames = sniff(&sent.borrow()[24..]);
        assert_eq!(
            frames[1..],
            [sniffed(0x6, 0x1, 0, b"12345678"), sniffed(0x4, 0x1, 0, &[])]
        );
    }

    #[test]
    fn returns_the_early_payload() {
        let early = b"\xff\xff\xffTS\x00\x00\x00\x07{\"a\":1}";
        let script: Vec<Vec<u8>> = early
            .chunks(3)
            .map(<[u8]>::to_vec)
            .chain([settings(&[])])
            .collect();
        let (_, payload, _) = open(&script).unwrap();
        assert_eq!(payload.as_deref(), Some(&b"{\"a\":1}"[..]));

        let err = open(&[b"\xff\xff\xffTS\x00\x00\x10\x01".to_vec()])
            .err()
            .unwrap();
        assert_eq!(
            err.to_string(),
            "HTTP/2: early payload of 4097 bytes exceeds 4096"
        );
    }

    #[test]
    fn posts_json_and_reads_the_response() {
        let (mut client, sent) = connected(&[
            raw(HEADERS, END_HEADERS, 1, &[0x88]),
            raw(DATA, END_STREAM, 1, b"{\"ok\":true}"),
        ]);
        let response = client.post("/machine/map", b"{}").unwrap();
        assert_eq!(response, (200, b"{\"ok\":true}".to_vec()));
        assert_eq!(
            sniff(&sent.borrow()),
            [
                sniffed(HEADERS, END_HEADERS, 1, &request_block("/machine/map", 2)),
                sniffed(DATA, END_STREAM, 1, b"{}"),
                window_update(0, 11),
            ]
        );
    }

    #[test]
    fn empty_bodies_end_the_stream_with_the_headers() {
        let (mut client, sent) = connected(&[raw(HEADERS, END_HEADERS | END_STREAM, 1, &[0x89])]);
        assert_eq!(client.post("/key", b"").unwrap(), (204, Vec::new()));
        assert_eq!(
            sniff(&sent.borrow()),
            [sniffed(
                HEADERS,
                END_HEADERS | END_STREAM,
                1,
                &request_block("/key", 0)
            )]
        );
    }

    #[test]
    fn replenishes_windows_for_received_data() {
        let (mut client, sent) = connected(&[
            raw(HEADERS, END_HEADERS, 1, &[0x88]),
            raw(DATA, 0, 1, b"abc"),
            raw(DATA, END_STREAM | 0x8, 1, &[2, b'x', 0, 0]),
        ]);
        assert_eq!(client.post("/", b"").unwrap(), (200, b"abcx".to_vec()));
        let frames = sniff(&sent.borrow());
        assert_eq!(
            frames[1..],
            [
                window_update(0, 3),
                window_update(1, 3),
                window_update(0, 4)
            ],
            "padding counts; no stream update once the stream ends"
        );
    }

    #[test]
    fn uses_odd_stream_ids_and_skips_frames_for_old_streams() {
        let (mut client, sent) = connected(&[
            raw(HEADERS, END_HEADERS | END_STREAM, 1, &[0x88]),
            raw(DATA, 0, 1, b"late"),
            raw(HEADERS, END_HEADERS | END_STREAM, 3, &[0x8d]),
        ]);
        assert_eq!(client.post("/a", b"").unwrap().0, 200);
        assert_eq!(client.post("/b", b"").unwrap().0, 404);
        let streams: Vec<u32> = sniff(&sent.borrow())
            .iter()
            .filter(|f| f.kind == HEADERS)
            .map(|f| f.stream)
            .collect();
        assert_eq!(streams, [1, 3]);
    }

    #[test]
    fn reassembles_padded_prioritised_headers_with_continuations() {
        let (mut client, _) = connected(&[
            raw(
                HEADERS,
                0x8 | 0x20,
                1,
                &[1, 0, 0, 0, 0, 16, 0x48, 0x03, b'3', 0xee],
            ),
            raw(CONTINUATION, 0, 1, b"0"),
            raw(CONTINUATION, END_HEADERS, 1, b"2"),
            raw(DATA, END_STREAM, 1, b""),
        ]);
        assert_eq!(client.post("/", b"").unwrap(), (302, Vec::new()));
    }

    #[test]
    fn strips_length_prefixes_from_json_bodies() {
        assert_eq!(strip_length_prefix(b"\x00\x00\x00\x02{}".to_vec()), b"{}");
        assert_eq!(strip_length_prefix(b"{\"a\":{}}".to_vec()), b"{\"a\":{}}");
        assert_eq!(strip_length_prefix(b"plain text".to_vec()), b"plain text");
        assert_eq!(strip_length_prefix(b"abc".to_vec()), b"abc");

        let (mut client, _) = connected(&[
            raw(HEADERS, END_HEADERS, 1, &[0x88]),
            raw(DATA, END_STREAM, 1, b"\x00\x00\x00\x07{\"a\":1}"),
        ]);
        assert_eq!(client.post("/", b"").unwrap().1, b"{\"a\":1}");
    }

    #[test]
    fn reports_resets_and_missing_status() {
        let (mut client, _) = connected(&[
            raw(HEADERS, END_HEADERS, 1, &[0x88]),
            raw(0x3, 0, 1, &[0, 0, 0, 7]),
        ]);
        assert_eq!(
            client.post("/", b"").unwrap_err().to_string(),
            "HTTP/2 stream 1 reset by server: REFUSED_STREAM (0x7) after status 200"
        );

        let (mut client, _) = connected(&[raw(HEADERS, END_HEADERS | END_STREAM, 1, &[])]);
        assert_eq!(
            client.post("/", b"").unwrap_err().to_string(),
            "HTTP/2 stream 1: response has no :status"
        );
    }

    #[test]
    fn graceful_goaway_finishes_the_request_but_refuses_new_ones() {
        let (mut client, _) = connected(&[
            raw(0x7, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 0]),
            raw(HEADERS, END_HEADERS | END_STREAM, 1, &[0x88]),
        ]);
        assert_eq!(client.post("/", b"").unwrap().0, 200);
        assert_eq!(
            client.post("/", b"").unwrap_err().to_string(),
            "HTTP/2: connection is closing (server sent GOAWAY, last stream 1)"
        );
    }

    #[test]
    fn goaway_errors_abort_the_request() {
        let mut payload = vec![0, 0, 0, 1, 0, 0, 0, 0xb];
        payload.extend_from_slice(b"calm down");
        let (mut client, _) = connected(&[raw(0x7, 0, 0, &payload)]);
        assert_eq!(
            client.post("/", b"").unwrap_err().to_string(),
            "HTTP/2 server sent GOAWAY: ENHANCE_YOUR_CALM (0xb), last stream 1: calm down"
        );

        let (mut client, _) = connected(&[raw(0x7, 0, 0, &[0; 8])]);
        assert_eq!(
            client.post("/", b"").unwrap_err().to_string(),
            "HTTP/2 server sent GOAWAY: NO_ERROR (0x0), last stream 0"
        );
    }

    #[test]
    fn request_bodies_wait_for_stream_window_updates() {
        let (mut client, sent) = connected_with(
            settings(&[(0x4, 4)]),
            &[
                raw(0x8, 0, 1, &[0, 0, 0, 6]),
                raw(HEADERS, END_HEADERS | END_STREAM, 1, &[0x88]),
            ],
        );
        assert_eq!(client.post("/", b"0123456789").unwrap().0, 200);
        let frames = sniff(&sent.borrow());
        assert_eq!(
            frames[1..],
            [
                sniffed(DATA, 0, 1, b"0123"),
                sniffed(DATA, END_STREAM, 1, b"456789")
            ]
        );
    }

    #[test]
    fn request_bodies_respect_connection_window_and_frame_size() {
        let (mut client, sent) = connected(&[
            raw(0x8, 0, 0, &4465u32.to_be_bytes()),
            raw(0x8, 0, 1, &4465u32.to_be_bytes()),
            raw(HEADERS, END_HEADERS | END_STREAM, 1, &[0x88]),
        ]);
        assert_eq!(client.post("/", &vec![b'x'; 70_000]).unwrap().0, 200);
        let sizes: Vec<(usize, u8)> = sniff(&sent.borrow())
            .iter()
            .filter(|f| f.kind == DATA)
            .map(|f| (f.payload.len(), f.flags))
            .collect();
        assert_eq!(
            sizes,
            [
                (16384, 0),
                (16384, 0),
                (16384, 0),
                (16383, 0),
                (4465, END_STREAM)
            ]
        );
    }

    #[test]
    fn a_response_while_the_body_is_blocked_resets_our_stream() {
        let (mut client, sent) = connected_with(
            settings(&[(0x4, 0)]),
            &[raw(HEADERS, END_HEADERS | END_STREAM, 1, &[0x8d])],
        );
        assert_eq!(client.post("/", b"abc").unwrap(), (404, Vec::new()));
        let frames = sniff(&sent.borrow());
        assert_eq!(frames[1..], [sniffed(0x3, 0, 1, &[0, 0, 0, 0])]);
    }

    #[test]
    fn a_reset_while_the_body_is_blocked_fails_the_request() {
        let (mut client, _) =
            connected_with(settings(&[(0x4, 0)]), &[raw(0x3, 0, 1, &[0, 0, 0, 8])]);
        assert_eq!(
            client.post("/", b"abc").unwrap_err().to_string(),
            "HTTP/2 stream 1 reset by server: CANCEL (0x8) while sending the request body"
        );
    }

    #[test]
    fn splits_header_blocks_at_the_servers_frame_size() {
        let path = "/".repeat(17_000);
        let (mut client, sent) = connected(&[raw(HEADERS, END_HEADERS | END_STREAM, 1, &[0x88])]);
        client.post(&path, b"{}").unwrap();
        let frames = sniff(&sent.borrow());
        assert_eq!(
            (frames[0].kind, frames[0].flags, frames[0].payload.len()),
            (HEADERS, 0, 16384)
        );
        assert_eq!(
            (frames[1].kind, frames[1].flags),
            (CONTINUATION, END_HEADERS)
        );
        assert_eq!(frames[2].kind, DATA);
        assert_eq!(
            long_path(&[frames[0].payload.as_slice(), &frames[1].payload].concat()),
            path
        );

        let (mut client, sent) = connected_with(
            settings(&[(0x5, 20_000)]),
            &[raw(HEADERS, END_HEADERS | END_STREAM, 1, &[0x88])],
        );
        client.post(&path, b"{}").unwrap();
        let frames = sniff(&sent.borrow());
        assert_eq!((frames[0].kind, frames[0].flags), (HEADERS, END_HEADERS));
        assert_eq!(long_path(&frames[0].payload), path);
        assert_eq!(frames[1].kind, DATA);
    }

    #[test]
    fn stream_window_overflow_from_settings_is_rejected() {
        let (mut client, _) = connected(&[
            raw(0x8, 0, 1, &0x7fff_0000u32.to_be_bytes()),
            settings(&[(0x4, 0x7fff_ffff)]),
        ]);
        assert_eq!(
            client.post("/", b"x").unwrap_err().to_string(),
            "HTTP/2 FLOW_CONTROL_ERROR: send window of stream 1 exceeds 2^31-1"
        );
    }

    #[test]
    fn response_bodies_are_capped() {
        let mut script = vec![raw(HEADERS, END_HEADERS, 1, &[0x88])];
        let full = raw(DATA, 0, 1, &[b'x'; 16384]);
        script.extend(std::iter::repeat_n(full, MAX_RESPONSE_BODY / 16384));
        script.push(raw(DATA, END_STREAM, 1, b"!"));
        let (mut client, _) = connected(&script);
        assert_eq!(
            client.post("/", b"").unwrap_err().to_string(),
            format!("HTTP/2 stream 1: response body exceeds {MAX_RESPONSE_BODY} bytes")
        );

        let mut script = vec![raw(HEADERS, END_HEADERS, 1, &[0x88])];
        script.extend(std::iter::repeat_n(
            raw(DATA, 0, 1, &[b'x'; 16384]),
            MAX_RESPONSE_BODY / 16384,
        ));
        script.push(raw(DATA, END_STREAM, 1, b""));
        let (mut client, _) = connected(&script);
        assert_eq!(client.post("/", b"").unwrap().1.len(), MAX_RESPONSE_BODY);
    }

    #[test]
    fn data_beyond_the_window_while_blocked_is_rejected() {
        let blocked = "HTTP/2 stream 1: server sent more than its flow-control window while the request body was blocked";

        let mut script = vec![raw(HEADERS, END_HEADERS, 1, &[0x88])];
        script.extend(std::iter::repeat_n(raw(DATA, 0, 1, &[0; 16384]), 9));
        let (mut client, _) = connected_with(settings(&[(0x4, 0)]), &script);
        assert_eq!(client.post("/", b"abc").unwrap_err().to_string(), blocked);

        // Padding-only and empty frames count too.
        let script: Vec<Vec<u8>> = std::iter::repeat_n(raw(DATA, 0, 1, b""), 257).collect();
        let (mut client, _) = connected_with(settings(&[(0x4, 0)]), &script);
        assert_eq!(client.post("/", b"abc").unwrap_err().to_string(), blocked);

        // One full window plus headers is still accepted.
        let mut script = vec![raw(HEADERS, END_HEADERS, 1, &[0x88])];
        script.extend(std::iter::repeat_n(raw(DATA, 0, 1, &[0; 16383]), 4));
        script.push(raw(DATA, END_STREAM, 1, &[0; 3]));
        let (mut client, _) = connected_with(settings(&[(0x4, 0)]), &script);
        assert_eq!(client.post("/", b"abc").unwrap().1.len(), 65535);
    }

    #[test]
    fn rejects_protocol_violations() {
        let header_block_overflow = [
            raw(HEADERS, 0, 1, &[0; 16384]),
            raw(CONTINUATION, 0, 1, &[0; 16384]),
            raw(CONTINUATION, 0, 1, &[0; 16384]),
            raw(CONTINUATION, 0, 1, &[0; 16384]),
            raw(CONTINUATION, END_HEADERS, 1, &[0]),
        ]
        .concat();
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (
                raw(DATA, 0, 0, b"x"),
                "HTTP/2 PROTOCOL_ERROR: DATA frame on stream 0",
            ),
            (
                raw(0x5, 0, 1, &[0; 4]),
                "HTTP/2 PROTOCOL_ERROR: PUSH_PROMISE received although push is disabled",
            ),
            (
                raw(CONTINUATION, END_HEADERS, 1, &[]),
                "HTTP/2 PROTOCOL_ERROR: CONTINUATION frame without a preceding HEADERS frame",
            ),
            (
                raw(0x4, 0, 1, &[]),
                "HTTP/2 PROTOCOL_ERROR: SETTINGS frame on stream 1",
            ),
            (
                raw(0x4, 0x1, 0, &[0; 6]),
                "HTTP/2 FRAME_SIZE_ERROR: SETTINGS ACK carries a payload",
            ),
            (
                raw(0x4, 0, 0, &[0; 5]),
                "HTTP/2 FRAME_SIZE_ERROR: SETTINGS payload of 5 bytes is not a multiple of 6",
            ),
            (
                settings(&[(0x5, 16383)]),
                "HTTP/2 PROTOCOL_ERROR: max frame size 16383 is outside 16384..=16777215",
            ),
            (
                settings(&[(0x5, 1 << 24)]),
                "HTTP/2 PROTOCOL_ERROR: max frame size 16777216 is outside 16384..=16777215",
            ),
            (
                settings(&[(0x4, 0x8000_0000)]),
                "HTTP/2 FLOW_CONTROL_ERROR: initial window size 2147483648 exceeds 2^31-1",
            ),
            (
                raw(0x6, 0, 1, &[0; 8]),
                "HTTP/2 PROTOCOL_ERROR: PING frame on stream 1",
            ),
            (
                raw(0x6, 0, 0, &[0; 7]),
                "HTTP/2 FRAME_SIZE_ERROR: PING payload of 7 bytes, expected 8",
            ),
            (
                raw(0x8, 0, 0, &[0; 3]),
                "HTTP/2 FRAME_SIZE_ERROR: WINDOW_UPDATE payload of 3 bytes, expected 4",
            ),
            (
                raw(0x8, 0, 0, &[0x80, 0, 0, 0]),
                "HTTP/2 PROTOCOL_ERROR: WINDOW_UPDATE with zero increment on stream 0",
            ),
            (
                raw(0x8, 0, 0, &[0x7f, 0xff, 0xff, 0xff]),
                "HTTP/2 FLOW_CONTROL_ERROR: send window of stream 0 exceeds 2^31-1",
            ),
            (
                raw(0x7, 0, 0, &[0; 7]),
                "HTTP/2 FRAME_SIZE_ERROR: GOAWAY payload of 7 bytes, expected at least 8",
            ),
            (
                raw(0x7, 0, 0, &[0; 8]),
                "HTTP/2 server sent GOAWAY: NO_ERROR (0x0), last stream 0",
            ),
            (
                raw(0x3, 0, 1, &[0; 3]),
                "HTTP/2 FRAME_SIZE_ERROR: RST_STREAM payload of 3 bytes, expected 4",
            ),
            (
                raw(DATA, 0, 1, &[0; 16385]),
                "HTTP/2 FRAME_SIZE_ERROR: 16385-byte frame of type 0x0 exceeds 16384",
            ),
            (
                raw(DATA, 0x8, 1, &[]),
                "HTTP/2 PROTOCOL_ERROR: padded frame has no pad length",
            ),
            (
                raw(HEADERS, 0x20, 1, &[0; 4]),
                "HTTP/2 FRAME_SIZE_ERROR: HEADERS frame too short for its priority fields",
            ),
            (
                [raw(HEADERS, 0, 1, &[0x88]), raw(DATA, 0, 1, b"x")].concat(),
                "HTTP/2 PROTOCOL_ERROR: expected CONTINUATION on stream 1, got frame type 0x0 on stream 1",
            ),
            (
                [
                    raw(HEADERS, 0, 1, &[0x88]),
                    raw(CONTINUATION, END_HEADERS, 3, &[]),
                ]
                .concat(),
                "HTTP/2 PROTOCOL_ERROR: expected CONTINUATION on stream 1, got frame type 0x9 on stream 3",
            ),
            (
                header_block_overflow,
                "HTTP/2: header block exceeds 65536 bytes",
            ),
        ];
        for (bytes, expected) in cases {
            let err = open(&[bytes]).err().unwrap().to_string();
            assert_eq!(err, expected);
        }
    }

    const SWITCHING: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\n\r\n";

    fn server_record(cipher: &ChaCha20Poly1305, counter: u64, plain: &[u8]) -> Vec<u8> {
        let sealed = cipher
            .encrypt(Nonce::from_slice(&be_nonce(counter)), plain)
            .unwrap();
        [
            &[control_cipher::RECORD_DATA][..],
            &(sealed.len() as u16).to_be_bytes(),
            &sealed,
        ]
        .concat()
    }

    #[test]
    fn runs_over_the_encrypted_control_link() {
        let (cipher, to_server, to_client) = handshake();
        let server = ChaCha20Poly1305::new_from_slice(&to_client).unwrap();
        let mut incoming = SWITCHING.to_vec();
        incoming.extend(server_record(&server, 0, &settings(&[])));
        incoming.extend(server_record(
            &server,
            1,
            &[
                raw(HEADERS, END_HEADERS, 1, &[0x88]),
                raw(DATA, END_STREAM, 1, b"{}"),
            ]
            .concat(),
        ));
        let (io, written) = ScriptedIo::new(&[&incoming]);
        let link = negotiate_upgrade(io, AUTHORITY, "x").unwrap();
        let (mut client, early) = Http2Client::establish(link, cipher, AUTHORITY.into()).unwrap();
        assert_eq!(early, None);
        assert_eq!(
            client.post("/p", &[b'x'; 5000]).unwrap(),
            (200, b"{}".to_vec())
        );

        let written = written.borrow();
        let start = written.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let opener = ChaCha20Poly1305::new_from_slice(&to_server).unwrap();
        let (mut rest, mut plain, mut records) = (&written[start..], Vec::new(), 0u64);
        while !rest.is_empty() {
            assert_eq!(rest[0], control_cipher::RECORD_DATA);
            let len = usize::from(u16::from_be_bytes([rest[1], rest[2]]));
            let chunk = opener
                .decrypt(Nonce::from_slice(&be_nonce(records)), &rest[3..3 + len])
                .unwrap();
            assert!(chunk.len() <= 2048, "records carry at most 2048 bytes");
            plain.extend(chunk);
            records += 1;
            rest = &rest[3 + len..];
        }
        assert!(plain.starts_with(PREFACE));
        let data: usize = sniff(&plain[PREFACE.len()..])
            .iter()
            .filter(|f| f.kind == DATA)
            .map(|f| f.payload.len())
            .sum();
        assert_eq!(data, 5000);
        assert!(records >= 4);
    }

    #[test]
    fn surfaces_control_errors_and_unknown_records() {
        for (record, expected) in [
            (b"\x03\x00\x04nope".to_vec(), "control server error: nope"),
            (vec![9, 0, 0], "control record: unexpected type 9"),
        ] {
            let (cipher, _, _) = handshake();
            let (io, _) = ScriptedIo::new(&[SWITCHING, &record]);
            let link = negotiate_upgrade(io, AUTHORITY, "x").unwrap();
            let err = Http2Client::establish(link, cipher, AUTHORITY.into())
                .err()
                .unwrap();
            assert_eq!(err.to_string(), expected);
        }
    }
}
