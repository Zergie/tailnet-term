use std::io::{self, Write};

use windows_sys::Win32::{
    Foundation::HANDLE,
    System::Console::{
        CHAR_INFO, COMMON_LVB_TRAILING_BYTE, CONSOLE_CURSOR_INFO, CONSOLE_SCREEN_BUFFER_INFO,
        COORD, GetConsoleCursorInfo, GetConsoleScreenBufferInfo, GetLargestConsoleWindowSize,
        ReadConsoleOutputW, SMALL_RECT, SetConsoleScreenBufferSize, SetConsoleWindowInfo,
    },
};

use super::checked;

const BUFFER_ROWS: i16 = 4096;

pub fn resize(console: HANDLE, columns: u16, rows: u16) -> io::Result<()> {
    let current = info(console)?;
    let maximum = unsafe { GetLargestConsoleWindowSize(console) };
    if maximum.X <= 0 || maximum.Y <= 0 {
        return Err(io::Error::last_os_error());
    }
    let width = columns.clamp(1, maximum.X.min(240) as u16) as i16;
    let height = rows.clamp(1, maximum.Y.min(120) as u16) as i16;
    let window = current.srWindow;
    // Windows requires the existing window to fit in the new screen buffer.
    if window.Right >= width || window.Bottom >= BUFFER_ROWS {
        set_window(console, window.Right.saturating_sub(window.Left).min(width - 1) + 1,
            (window.Bottom - window.Top + 1).min(height), 0)?;
    }
    checked(unsafe {
        SetConsoleScreenBufferSize(console, COORD { X: width, Y: BUFFER_ROWS })
    })?;
    let cursor_y = current.dwCursorPosition.Y.min(BUFFER_ROWS - 1);
    let top = window.Top.min(BUFFER_ROWS - height).max(cursor_y.saturating_sub(height - 1)).max(0);
    set_window(console, width, height, top)
}

fn set_window(console: HANDLE, width: i16, height: i16, top: i16) -> io::Result<()> {
    let window = SMALL_RECT { Left: 0, Right: width - 1, Top: top, Bottom: top + height - 1 };
    checked(unsafe { SetConsoleWindowInfo(console, 1, &window) })
}

fn info(console: HANDLE) -> io::Result<CONSOLE_SCREEN_BUFFER_INFO> {
    let mut result = CONSOLE_SCREEN_BUFFER_INFO::default();
    checked(unsafe { GetConsoleScreenBufferInfo(console, &mut result) })?;
    Ok(result)
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Cell(u16, u16);

#[derive(Default)]
pub struct Screen {
    default_background: u16,
    size: (usize, usize),
    top: i16,
    cells: Vec<Cell>,
    cursor: (i16, i16, bool),
}

impl Screen {
    pub fn new(console: HANDLE) -> io::Result<Self> {
        Ok(Self {
            default_background: (info(console)?.wAttributes >> 4) & 15,
            ..Self::default()
        })
    }

    pub fn render(&mut self, console: HANDLE, writer: &mut impl Write) -> io::Result<bool> {
        let info = info(console)?;
        let mut cursor_info = CONSOLE_CURSOR_INFO::default();
        checked(unsafe { GetConsoleCursorInfo(console, &mut cursor_info) })?;
        let mut window = info.srWindow;
        let width = (window.Right - window.Left + 1) as usize;
        let height = (window.Bottom - window.Top + 1) as usize;
        let top = window.Top;
        let size = (width, height);
        let reset = self.size != size || top < self.top;
        // Query newly scrolled lines from the underlying buffer as well as the visible window.
        // This preserves lines that appeared and scrolled out between two polls.
        if !reset {
            window.Top = self.top;
        }
        let read_rows = (window.Bottom - window.Top + 1) as usize;
        let mut raw = vec![CHAR_INFO::default(); width * read_rows];
        let original = window;
        checked(unsafe {
            ReadConsoleOutputW(
                console,
                raw.as_mut_ptr(),
                COORD { X: width as i16, Y: read_rows as i16 },
                COORD { X: 0, Y: 0 },
                &mut window,
            )
        })?;
        if window.Left != original.Left || window.Top != original.Top
            || window.Right != original.Right || window.Bottom != original.Bottom
        {
            // A concurrent resize by the shell can clip the read. Retry on the next poll.
            return Ok(false);
        }
        let cells: Vec<Cell> = raw
            .iter()
            .map(|cell| Cell(unsafe { cell.Char.UnicodeChar }, cell.Attributes))
            .collect();
        let scrolled = (top - original.Top) as usize;
        let current = &cells[scrolled * width..];
        let cursor = (
            (info.dwCursorPosition.Y - top).clamp(0, height as i16 - 1),
            (info.dwCursorPosition.X - window.Left).clamp(0, width as i16 - 1),
            cursor_info.bVisible != 0,
        );
        if !reset && scrolled == 0 && self.cells == current && self.cursor == cursor {
            return Ok(false);
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\x1b[?25l\x1b[?7l");
        if reset {
            bytes.extend_from_slice(b"\x1b[2J");
        }
        for row in cells[..scrolled * width].chunks_exact(width) {
            render_row(&mut bytes, 1, row, self.default_background)?;
            write!(&mut bytes, "\x1b[{height};1H\r\n")?;
        }
        for (index, row) in current.chunks_exact(width).enumerate() {
            if reset || scrolled != 0 || self.cells[index * width..(index + 1) * width] != *row {
                render_row(&mut bytes, index + 1, row, self.default_background)?;
            }
        }
        write!(&mut bytes, "\x1b[{};{}H\x1b[?7h", cursor.0 + 1, cursor.1 + 1)?;
        if cursor.2 {
            bytes.extend_from_slice(b"\x1b[?25h");
        }
        writer.write_all(&bytes)?;
        writer.flush()?;
        self.size = size;
        self.top = top;
        self.cursor = cursor;
        self.cells.clear();
        self.cells.extend_from_slice(current);
        Ok(true)
    }
}

fn render_row(output: &mut Vec<u8>, line: usize, cells: &[Cell], default_background: u16) -> io::Result<()> {
    write!(output, "\x1b[{line};1H\x1b[0m\x1b[2K")?;
    let end = cells
        .iter()
        .rposition(|cell| !matches!(cell.0, 0 | 32) || (cell.1 >> 4) & 15 != default_background)
        .map_or(0, |index| index + 1);
    for run in cells[..end].chunk_by(|left, right| left.1 & 0xff == right.1 & 0xff) {
        let color = run[0].1;
        let background = (color >> 4) & 15;
        let background = if background == default_background { 49 } else { ansi_color(background, 40) };
        write!(output, "\x1b[{};{background}m", ansi_color(color & 15, 30))?;
        let units: Vec<_> = run.iter()
            .filter(|cell| cell.1 & COMMON_LVB_TRAILING_BYTE as u16 == 0)
            .map(|cell| if cell.0 == 0 { 32 } else { cell.0 })
            .collect();
        output.extend_from_slice(String::from_utf16_lossy(&units).as_bytes());
    }
    output.extend_from_slice(b"\x1b[0m");
    Ok(())
}

fn ansi_color(color: u16, base: u16) -> u16 {
    // The Win32 low bits are blue, green, red; ANSI uses red, green, blue.
    base + ((color & 1) << 2) + (color & 2) + ((color & 4) >> 2) + if color & 8 != 0 { 60 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwards_default_background_without_painting_a_black_rectangle() {
        let mut output = Vec::new();
        render_row(&mut output, 1, &[Cell(b'x' as u16, 7), Cell(32, 0x47), Cell(32, 7)], 0).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains(";49m"), "{text:?}");
        assert!(!text.contains(";40m"), "{text:?}");
        assert!(text.contains(";41m "), "{text:?}");
    }
}
