//! The sliver of HPACK (RFC 7541) the client needs.
//!
//! Requests are encoded as literals without indexing, so no table is kept.
//! The dynamic table size is advertised as zero, so responses may only use
//! the static table; of their fields only `:status` is decoded.

use anyhow::{Result, anyhow, bail};

/// Number of entries in the HPACK static table.
const STATIC_TABLE_LEN: usize = 61;
/// Static table entries 8..=14 are `:status` with these values.
const STATUS_ENTRIES: std::ops::RangeInclusive<usize> = 8..=14;
const STATIC_STATUS_CODES: [u16; 7] = [200, 204, 206, 304, 400, 404, 500];
/// `:status` Huffman-encoded.
const HUFFMAN_STATUS_NAME: [u8; 5] = [0xb8, 0x84, 0x8d, 0x36, 0xa3];

/// Appends `name: value` as a literal field without indexing and with a new
/// name, Huffman coding off.
pub(super) fn write_header(block: &mut Vec<u8>, name: &str, value: &str) {
    block.push(0x00);
    write_string(block, name.as_bytes());
    write_string(block, value.as_bytes());
}

fn write_string(block: &mut Vec<u8>, s: &[u8]) {
    let len = s.len();
    if len < 0x7f {
        block.push(len as u8);
    } else {
        block.push(0x7f);
        let mut rest = len - 0x7f;
        while rest >= 0x80 {
            block.push(((rest & 0x7f) | 0x80) as u8);
            rest >>= 7;
        }
        block.push(rest as u8);
    }
    block.extend_from_slice(s);
}

/// Returns the `:status` of a response header block, if it has one.
pub(super) fn find_status(block: &[u8]) -> Result<Option<u16>> {
    let malformed = || anyhow!("HTTP/2 COMPRESSION_ERROR: malformed header block");
    let mut pos = 0;
    let mut status = None;
    let mut seen_field = false;
    while let Some(&first) = block.get(pos) {
        if first & 0x80 != 0 {
            // Indexed field.
            let index = read_int(block, &mut pos, 7).ok_or_else(malformed)?;
            if index == 0 || index > STATIC_TABLE_LEN {
                bail!(
                    "HTTP/2 COMPRESSION_ERROR: header index {index} refers to the disabled dynamic table"
                );
            }
            if STATUS_ENTRIES.contains(&index) {
                status = Some(STATIC_STATUS_CODES[index - STATUS_ENTRIES.start()]);
            }
            seen_field = true;
        } else if first & 0xe0 == 0x20 {
            // Dynamic table size update: only "0", and only before any field.
            let size = read_int(block, &mut pos, 5).ok_or_else(malformed)?;
            if seen_field || size != 0 {
                bail!("HTTP/2 COMPRESSION_ERROR: unexpected dynamic table size update to {size}");
            }
        } else {
            // Literal field, with incremental indexing (6-bit prefix) or
            // without/never indexed (4-bit prefix).
            let prefix_bits = if first & 0x40 != 0 { 6 } else { 4 };
            let name_index = read_int(block, &mut pos, prefix_bits).ok_or_else(malformed)?;
            let is_status = if name_index == 0 {
                let (name, huffman) = read_string(block, &mut pos).ok_or_else(malformed)?;
                if huffman {
                    name == HUFFMAN_STATUS_NAME
                } else {
                    name == b":status"
                }
            } else if name_index > STATIC_TABLE_LEN {
                bail!(
                    "HTTP/2 COMPRESSION_ERROR: header name index {name_index} refers to the disabled dynamic table"
                );
            } else {
                STATUS_ENTRIES.contains(&name_index)
            };
            let (value, huffman) = read_string(block, &mut pos).ok_or_else(malformed)?;
            if is_status {
                let parsed = if huffman {
                    decode_huffman_status(value)
                } else if value.len() == 3 && value.iter().all(u8::is_ascii_digit) {
                    std::str::from_utf8(value).ok().and_then(|s| s.parse().ok())
                } else {
                    None
                };
                status = Some(parsed.ok_or_else(|| anyhow!("HTTP/2: invalid :status value"))?);
            }
            seen_field = true;
        }
    }
    Ok(status)
}

/// Prefixed integer (RFC 7541 §5.1), limited to four continuation bytes.
fn read_int(block: &[u8], pos: &mut usize, prefix_bits: u8) -> Option<usize> {
    let mask = (1usize << prefix_bits) - 1;
    let mut value = usize::from(*block.get(*pos)?) & mask;
    *pos += 1;
    if value != mask {
        return Some(value);
    }
    for shift in [0, 7, 14, 21] {
        let byte = *block.get(*pos)?;
        *pos += 1;
        value = value.checked_add(usize::from(byte & 0x7f) << shift)?;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// String literal (RFC 7541 §5.2); returns the raw bytes and the Huffman flag.
fn read_string<'a>(block: &'a [u8], pos: &mut usize) -> Option<(&'a [u8], bool)> {
    let huffman = *block.get(*pos)? & 0x80 != 0;
    let length = read_int(block, pos, 7)?;
    let end = pos.checked_add(length)?;
    let encoded = block.get(*pos..end)?;
    *pos = end;
    Some((encoded, huffman))
}

/// Decodes a Huffman-coded three-digit status. Digits 0-2 have 5-bit codes
/// `00000`..`00010`, digits 3-9 have 6-bit codes `011001`..`011111`; the
/// remainder must be at most seven bits of EOS padding (all ones).
fn decode_huffman_status(encoded: &[u8]) -> Option<u16> {
    let mut code = 0u8;
    let mut bits = 0;
    let mut digits = 0;
    let mut status = 0;
    for byte in encoded {
        for shift in (0..8).rev() {
            code = (code << 1) | ((byte >> shift) & 1);
            bits += 1;
            if digits == 3 {
                if bits > 7 || code != ((1 << bits) - 1) {
                    return None;
                }
                continue;
            }
            let digit = match (bits, code) {
                (5, 0..=2) => code,
                (6, 0x19..=0x1f) => code - 0x16,
                (6, _) => return None,
                _ => continue,
            };
            status = status * 10 + u16::from(digit);
            digits += 1;
            code = 0;
            bits = 0;
        }
    }
    (digits == 3).then_some(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(block: &[u8]) -> Result<Option<u16>> {
        find_status(block)
    }

    fn error(block: &[u8]) -> String {
        find_status(block).unwrap_err().to_string()
    }

    #[test]
    fn decodes_prefixed_integers_from_rfc7541_c1() {
        let read = |bytes: &[u8], prefix| {
            let mut pos = 0;
            read_int(bytes, &mut pos, prefix).map(|v| (v, pos))
        };
        assert_eq!(read(&[0b0000_1010], 5), Some((10, 1)));
        assert_eq!(
            read(&[0b0001_1111, 0b1001_1010, 0b0000_1010], 5),
            Some((1337, 3))
        );
        assert_eq!(read(&[0b0010_1010], 8), Some((42, 1)));
        // The bits above the prefix belong to the representation, not the value.
        assert_eq!(read(&[0b1110_1010], 5), Some((10, 1)));
        assert_eq!(read(&[0x1f, 0x80], 5), None, "truncated");
        assert_eq!(
            read(&[0x1f, 0x80, 0x80, 0x80, 0x80, 0x01], 5),
            None,
            "too long"
        );
        assert_eq!(read(&[], 5), None);
    }

    #[test]
    fn writes_literal_fields_without_indexing() {
        let mut block = Vec::new();
        write_header(&mut block, "accept", "*/*");
        assert_eq!(block, b"\x00\x06accept\x03*/*");
    }

    #[test]
    fn long_strings_use_continuation_bytes() {
        for (len, prefix) in [
            (126, vec![0x7e]),
            (127, vec![0x7f, 0x00]),
            (200, vec![0x7f, 0x49]),
            (300, vec![0x7f, 0xad, 0x01]),
        ] {
            let value = vec![b'x'; len];
            let mut block = Vec::new();
            write_string(&mut block, &value);
            assert_eq!(block[..prefix.len()], prefix, "length {len}");

            let mut pos = 0;
            assert_eq!(
                read_string(&block, &mut pos),
                Some((value.as_slice(), false))
            );
            assert_eq!(pos, block.len());
        }
    }

    #[test]
    fn huffman_status_name_is_status_encoded() {
        // ':' 1011100, 's' 01000, 't' 01001, 'a' 00011, 'u' 101101, then EOS padding.
        let bits = "1011100 01000 01001 00011 01001 101101 01000 11".replace(' ', "");
        let bytes: Vec<u8> = bits
            .as_bytes()
            .chunks(8)
            .map(|byte| u8::from_str_radix(std::str::from_utf8(byte).unwrap(), 2).unwrap())
            .collect();
        assert_eq!(bytes, HUFFMAN_STATUS_NAME);
    }

    #[test]
    fn reads_status_from_the_static_table() {
        assert_eq!(status(&[0x88]).unwrap(), Some(200));
        assert_eq!(status(&[0x89]).unwrap(), Some(204));
        assert_eq!(status(&[0x8d]).unwrap(), Some(404));
        assert_eq!(status(&[0x8e]).unwrap(), Some(500));
        // `content-type: application/json` (literal with indexed name 31) is skipped.
        let mut block = vec![0x5f];
        block.extend_from_slice(b"\x10application/json");
        block.push(0x8b);
        assert_eq!(status(&block).unwrap(), Some(304));
        assert_eq!(status(&block[..block.len() - 1]).unwrap(), None);
        assert_eq!(status(&[]).unwrap(), None);
    }

    #[test]
    fn reads_literal_status_values_from_rfc7541_examples() {
        // C.5.1: literal with incremental indexing, indexed name, plain value.
        assert_eq!(status(b"\x48\x03302").unwrap(), Some(302));
        // C.6.1: the same with a Huffman-coded value.
        assert_eq!(status(&[0x48, 0x82, 0x64, 0x02]).unwrap(), Some(302));
        // Without indexing and never indexed, 4-bit name prefix.
        assert_eq!(status(b"\x08\x03201").unwrap(), Some(201));
        assert_eq!(status(b"\x18\x03201").unwrap(), Some(201));
        // New name, plain and Huffman-coded.
        assert_eq!(status(b"\x00\x07:status\x03418").unwrap(), Some(418));
        let mut block = vec![0x00, 0x85];
        block.extend_from_slice(&HUFFMAN_STATUS_NAME);
        block.extend_from_slice(&[0x82, 0x10, 0x01]);
        assert_eq!(status(&block).unwrap(), Some(200));
    }

    #[test]
    fn accepts_a_leading_zero_table_size_update() {
        assert_eq!(status(&[0x20, 0x88]).unwrap(), Some(200));
        assert_eq!(
            error(&[0x88, 0x20]),
            "HTTP/2 COMPRESSION_ERROR: unexpected dynamic table size update to 0"
        );
        assert_eq!(
            error(&[0x3f, 0xe1, 0x1f]),
            "HTTP/2 COMPRESSION_ERROR: unexpected dynamic table size update to 4096"
        );
    }

    #[test]
    fn rejects_dynamic_table_references() {
        assert_eq!(
            error(&[0x80]),
            "HTTP/2 COMPRESSION_ERROR: header index 0 refers to the disabled dynamic table"
        );
        assert_eq!(
            error(&[0xbe]),
            "HTTP/2 COMPRESSION_ERROR: header index 62 refers to the disabled dynamic table"
        );
        assert_eq!(
            error(b"\x7e\x01x"),
            "HTTP/2 COMPRESSION_ERROR: header name index 62 refers to the disabled dynamic table"
        );
    }

    #[test]
    fn rejects_malformed_blocks_and_values() {
        assert_eq!(
            error(b"\x48\x05302"),
            "HTTP/2 COMPRESSION_ERROR: malformed header block"
        );
        assert_eq!(
            error(b"\x48"),
            "HTTP/2 COMPRESSION_ERROR: malformed header block"
        );
        assert_eq!(
            error(b"\xff"),
            "HTTP/2 COMPRESSION_ERROR: malformed header block"
        );
        assert_eq!(error(b"\x48\x0320x"), "HTTP/2: invalid :status value");
        assert_eq!(error(b"\x48\x042000"), "HTTP/2: invalid :status value");
        assert_eq!(
            error(&[0x48, 0x82, 0x10, 0x00]),
            "HTTP/2: invalid :status value"
        );
    }

    #[test]
    fn decodes_huffman_statuses() {
        assert_eq!(decode_huffman_status(&[0x64, 0x02]), Some(302));
        assert_eq!(decode_huffman_status(&[0x10, 0x01]), Some(200));
        // 4 0 4: 011010 00000 011010, then seven bits of padding.
        assert_eq!(
            decode_huffman_status(&[0b0110_1000, 0b0000_1101, 0b0000_0000]),
            None
        );
        assert_eq!(
            decode_huffman_status(&[0b0110_1000, 0b0000_1101, 0b0111_1111]),
            Some(404)
        );
        assert_eq!(
            decode_huffman_status(&[0x10, 0x00]),
            None,
            "padding must be ones"
        );
        assert_eq!(
            decode_huffman_status(&[0x64, 0x02, 0xff]),
            None,
            "padding longer than 7 bits"
        );
        assert_eq!(decode_huffman_status(&[0x10]), None, "only one digit");
        assert_eq!(
            decode_huffman_status(&[0x1f, 0xff]),
            None,
            "'a' is not a digit"
        );
    }
}
