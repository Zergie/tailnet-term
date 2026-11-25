use std::io;

use windows_sys::Win32::{
    Foundation::HANDLE,
    System::Console::{
        CTRL_C_EVENT, ENABLE_PROCESSED_INPUT, ENHANCED_KEY, GenerateConsoleCtrlEvent,
        GetConsoleMode, INPUT_RECORD, INPUT_RECORD_0, KEY_EVENT, KEY_EVENT_RECORD,
        KEY_EVENT_RECORD_0, LEFT_ALT_PRESSED, LEFT_CTRL_PRESSED, RIGHT_ALT_PRESSED,
        SHIFT_PRESSED, WriteConsoleInputW,
    },
    UI::Input::KeyboardAndMouse::{
        MAPVK_VK_TO_VSC, MapVirtualKeyW, VK_BACK, VK_DELETE, VK_DOWN, VK_END, VK_ESCAPE,
        VK_HOME, VK_INSERT, VK_LEFT, VK_NEXT, VK_PACKET, VK_PRIOR, VK_RETURN, VK_RIGHT,
        VK_TAB, VK_UP, VkKeyScanW,
    },
};

use super::checked;

#[derive(Default)]
pub struct Keyboard {
    utf8_tail: Vec<u8>,
}

impl Keyboard {
    pub fn send(&mut self, console: HANDLE, bytes: &[u8]) -> io::Result<()> {
        let mut input = std::mem::take(&mut self.utf8_tail);
        input.extend_from_slice(bytes);
        let mut input = input.as_slice();
        let mut records = Vec::new();
        while let Some(&byte) = input.first() {
            if byte == 3 {
                let mut mode = 0;
                checked(unsafe { GetConsoleMode(console, &mut mode) })?;
                if mode & ENABLE_PROCESSED_INPUT != 0 {
                    send_records(console, &records)?;
                    records.clear();
                    checked(unsafe { GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) })?;
                    input = &input[1..];
                    continue;
                }
            }
            if byte == 0x1b && matches!(input.get(1), Some(b'[' | b'O')) {
                let sequence = &input[2..];
                if let Some(end) = sequence.iter().position(|byte| (0x40..=0x7e).contains(byte)) {
                    escape_key(&mut records, &sequence[..=end]);
                    input = &sequence[end + 1..];
                    continue;
                }
            }
            let length = match byte {
                0..=0x7f => 1,
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => 1,
            };
            if input.len() < length {
                self.utf8_tail.extend_from_slice(input);
                break;
            }
            let character = std::str::from_utf8(&input[..length])
                .ok()
                .and_then(|text| text.chars().next())
                .unwrap_or('\u{fffd}');
            type_char(&mut records, character);
            input = &input[length..];
        }
        send_records(console, &records)
    }
}

fn type_char(records: &mut Vec<INPUT_RECORD>, character: char) {
    let (key, unit) = match character {
        '\u{08}' | '\u{7f}' => (VK_BACK, 8),
        '\t' => (VK_TAB, 9),
        '\r' | '\n' => (VK_RETURN, 13),
        '\u{1b}' => (VK_ESCAPE, 27),
        '\u{01}'..='\u{1a}' => {
            let control = character as u16;
            keypress(records, u16::from(b'A') + control - 1, control, LEFT_CTRL_PRESSED);
            return;
        }
        _ => {
            for &unit in character.encode_utf16(&mut [0; 2]).iter() {
                let mapping = unsafe { VkKeyScanW(unit) };
                if mapping == -1 {
                    keypress(records, VK_PACKET, unit, 0);
                    continue;
                }
                let mapping = mapping as u16;
                let flags = match (mapping >> 8) & 6 {
                    6 => LEFT_CTRL_PRESSED | RIGHT_ALT_PRESSED,
                    4 => LEFT_ALT_PRESSED,
                    2 => LEFT_CTRL_PRESSED,
                    _ => 0,
                } | if mapping & 0x100 != 0 { SHIFT_PRESSED } else { 0 };
                keypress(records, mapping & 0xff, unit, flags);
            }
            return;
        }
    };
    keypress(records, key, unit, 0);
}

fn escape_key(records: &mut Vec<INPUT_RECORD>, sequence: &[u8]) {
    let (&end, parameters) = sequence.split_last().expect("escape final byte");
    let mut params = parameters.split(|&byte| byte == b';');
    let first = params.next().unwrap_or_default();
    let modifiers = params
        .next()
        .and_then(|param| std::str::from_utf8(param).ok()?.parse::<u32>().ok())
        .unwrap_or(1)
        .saturating_sub(1);
    let (key, unit) = match (end, first) {
        (b'A', _) => (VK_UP, 0),
        (b'B', _) => (VK_DOWN, 0),
        (b'C', _) => (VK_RIGHT, 0),
        (b'D', _) => (VK_LEFT, 0),
        (b'H', _) | (b'~', b"1" | b"7") => (VK_HOME, 0),
        (b'F', _) | (b'~', b"4" | b"8") => (VK_END, 0),
        (b'~', b"2") => (VK_INSERT, 0),
        (b'~', b"3") => (VK_DELETE, 0),
        (b'~', b"5") => (VK_PRIOR, 0),
        (b'~', b"6") => (VK_NEXT, 0),
        (b'Z', _) => return keypress(records, VK_TAB, 9, SHIFT_PRESSED),
        _ => return,
    };
    let mut flags = ENHANCED_KEY;
    for (mask, flag) in [(1, SHIFT_PRESSED), (2, LEFT_ALT_PRESSED), (4, LEFT_CTRL_PRESSED)] {
        if modifiers & mask != 0 {
            flags |= flag;
        }
    }
    keypress(records, key, unit, flags);
}

fn keypress(records: &mut Vec<INPUT_RECORD>, key: u16, unit: u16, flags: u32) {
    let scan = unsafe { MapVirtualKeyW(u32::from(key), MAPVK_VK_TO_VSC) } as u16;
    for down in [1, 0] {
        records.push(INPUT_RECORD {
            EventType: KEY_EVENT as u16,
            Event: INPUT_RECORD_0 {
                KeyEvent: KEY_EVENT_RECORD {
                    bKeyDown: down,
                    wRepeatCount: 1,
                    wVirtualKeyCode: key,
                    wVirtualScanCode: scan,
                    uChar: KEY_EVENT_RECORD_0 { UnicodeChar: unit },
                    dwControlKeyState: flags,
                },
            },
        });
    }
}

fn send_records(console: HANDLE, mut records: &[INPUT_RECORD]) -> io::Result<()> {
    while !records.is_empty() {
        let mut written = 0;
        checked(unsafe {
            WriteConsoleInputW(console, records.as_ptr(), records.len() as u32, &mut written)
        })?;
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        records = &records[written as usize..];
    }
    Ok(())
}
