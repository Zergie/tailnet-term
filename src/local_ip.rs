//! Tailnet IPv4 address of this PC's installed Tailscale.

use std::{error::Error, net::Ipv4Addr, ptr};

use windows_sys::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, ERROR_SUCCESS},
    NetworkManagement::{
        IpHelper::{
            GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
            GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
        },
        Ndis::IfOperStatusUp,
    },
    Networking::WinSock::{AF_INET, SOCKADDR_IN},
};

use crate::echo::tailnet_ipv4;

/// Interface description of the Tailscale Windows adapter. Users can rename the
/// adapter, but not its description.
const TAILSCALE_DESCRIPTION: &str = "Tailscale Tunnel";

struct Adapter {
    description: String,
    up: bool,
    addresses: Vec<Ipv4Addr>,
}

pub fn run() -> Result<(), Box<dyn Error>> {
    println!("{}", pick(&adapters()?)?);
    Ok(())
}

fn pick(adapters: &[Adapter]) -> Result<Ipv4Addr, &'static str> {
    let mut tailscale = adapters
        .iter()
        .filter(|adapter| adapter.description.starts_with(TAILSCALE_DESCRIPTION))
        .peekable();
    if tailscale.peek().is_none() {
        return Err("no Tailscale adapter found; is Tailscale installed?");
    }
    tailscale
        .filter(|adapter| adapter.up)
        .flat_map(|adapter| adapter.addresses.iter().copied())
        .find(|&address| tailnet_ipv4(address))
        .ok_or("Tailscale is not connected; start Tailscale and log in")
}

fn adapters() -> Result<Vec<Adapter>, Box<dyn Error>> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    // u64 elements keep the buffer aligned for IP_ADAPTER_ADDRESSES_LH.
    let mut buffer = vec![0u64; 2048];
    loop {
        let mut size = u32::try_from(buffer.len() * 8)?;
        let first = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: `first` points to `size` writable, suitably aligned bytes.
        let status =
            unsafe { GetAdaptersAddresses(u32::from(AF_INET), flags, ptr::null(), first, &mut size) };
        match status {
            ERROR_SUCCESS => break,
            ERROR_NO_DATA => return Ok(Vec::new()),
            ERROR_BUFFER_OVERFLOW => buffer.resize((size as usize).div_ceil(8), 0),
            error => return Err(format!("GetAdaptersAddresses failed with error {error}").into()),
        }
    }
    let mut adapters = Vec::new();
    let mut current = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    // SAFETY: GetAdaptersAddresses filled `buffer` with a linked list whose
    // pointers stay valid while `buffer` is alive.
    unsafe {
        while let Some(adapter) = current.as_ref() {
            let mut addresses = Vec::new();
            let mut unicast = adapter.FirstUnicastAddress;
            while let Some(entry) = unicast.as_ref() {
                let socket = entry.Address.lpSockaddr;
                if !socket.is_null() && (*socket).sa_family == AF_INET {
                    let address = &*socket.cast::<SOCKADDR_IN>();
                    addresses.push(Ipv4Addr::from(u32::from_be(address.sin_addr.S_un.S_addr)));
                }
                unicast = entry.Next;
            }
            adapters.push(Adapter {
                description: wide_string(adapter.Description),
                up: adapter.OperStatus == IfOperStatusUp,
                addresses,
            });
            current = adapter.Next;
        }
    }
    Ok(adapters)
}

/// # Safety
/// `text` must be null or point to a NUL-terminated UTF-16 string.
unsafe fn wide_string(text: *const u16) -> String {
    if text.is_null() {
        return String::new();
    }
    let mut length = 0;
    // SAFETY: the caller guarantees NUL termination.
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(description: &str, up: bool, addresses: &[[u8; 4]]) -> Adapter {
        Adapter {
            description: description.to_owned(),
            up,
            addresses: addresses.iter().copied().map(Ipv4Addr::from).collect(),
        }
    }

    #[test]
    fn picks_tailnet_address_of_tailscale_adapter() {
        let adapters = [
            adapter("Realtek USB GbE Family Controller", true, &[[100, 70, 1, 2]]),
            adapter("Tailscale Tunnel", true, &[[169, 254, 3, 4], [100, 108, 6, 69]]),
        ];
        assert_eq!(pick(&adapters), Ok(Ipv4Addr::new(100, 108, 6, 69)));
    }

    #[test]
    fn ignores_carrier_nat_addresses_on_other_adapters() {
        let adapters = [adapter("RZ616 Wi-Fi 6E 160MHz", true, &[[100, 64, 0, 9]])];
        assert!(pick(&adapters).unwrap_err().contains("no Tailscale adapter"));
    }

    #[test]
    fn reports_disconnected_tailscale() {
        let adapters = [adapter("Tailscale Tunnel", false, &[[100, 108, 6, 69]])];
        assert!(pick(&adapters).unwrap_err().contains("not connected"));
        let adapters = [adapter("Tailscale Tunnel", true, &[[169, 254, 3, 4]])];
        assert!(pick(&adapters).unwrap_err().contains("not connected"));
    }
}
