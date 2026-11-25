use std::{
    env,
    error::Error,
    ffi::c_void,
    io,
    ptr::{null, null_mut},
};

use serde_json::{Value, json};
use windows_sys::Win32::Networking::WinHttp::{
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_DISABLE_REDIRECTS, WINHTTP_FLAG_SECURE,
    WINHTTP_OPTION_DISABLE_FEATURE, WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders,
    WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetOption,
    WinHttpSetTimeouts,
};
use windows_sys::core::w;

pub fn create(tags: Vec<String>) -> Result<(), Box<dyn Error>> {
    let api_key = credential("TAILSCALE_API_KEY");
    let client_id = credential("TAILSCALE_OAUTH_CLIENT_ID");
    let client_secret = credential("TAILSCALE_OAUTH_CLIENT_SECRET");
    let oauth = match (api_key.is_some(), client_id, client_secret) {
        (true, None, None) => None,
        (true, _, _) => {
            return Err("set either TAILSCALE_API_KEY or the OAuth credentials, not both".into());
        }
        (false, Some(id), Some(secret)) => Some((id, secret)),
        (false, None, None) => {
            return Err("set TAILSCALE_API_KEY or both TAILSCALE_OAUTH_CLIENT_ID and TAILSCALE_OAUTH_CLIENT_SECRET".into());
        }
        (false, _, _) => {
            return Err("OAuth requires both TAILSCALE_OAUTH_CLIENT_ID and TAILSCALE_OAUTH_CLIENT_SECRET".into());
        }
    };
    for tag in &tags {
        if !tag.starts_with("tag:") || tag.len() <= 4 {
            return Err("tags must have the form tag:NAME".into());
        }
    }
    let token = if let Some((id, secret)) = oauth {
        if tags.is_empty() {
            return Err("OAuth requires at least one tag allowed by the OAuth client".into());
        }
        let body = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}",
            form_value(&id),
            form_value(&secret)
        );
        let response = post(
            "/api/v2/oauth/token",
            "application/x-www-form-urlencoded",
            None,
            body.as_bytes(),
        )?;
        response["access_token"]
            .as_str()
            .filter(|token| !token.is_empty())
            .ok_or("Tailscale returned no OAuth access token")?
            .to_owned()
    } else {
        api_key.expect("validated API credentials")
    };
    if !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err("the Tailscale API token contains invalid characters".into());
    }

    let body = json!({
        "capabilities": { "devices": { "create": {
            "ephemeral": true, "reusable": false, "preauthorized": false, "tags": tags,
        }}},
        "expirySeconds": 86400,
    });
    let response = post(
        "/api/v2/tailnet/-/keys",
        "application/json",
        Some(&token),
        &serde_json::to_vec(&body)?,
    )?;
    let key = response["key"]
        .as_str()
        .filter(|key| key.starts_with("tskey-auth-"))
        .ok_or("Tailscale returned no auth key")?;
    println!("{key}");
    Ok(())
}

fn credential(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn form_value(value: &str) -> String {
    use std::fmt::Write;
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte.into());
        } else {
            write!(&mut encoded, "%{byte:02X}").unwrap();
        }
    }
    encoded
}

struct InternetHandle(*mut c_void);

impl InternetHandle {
    fn new(handle: *mut c_void) -> io::Result<Self> {
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }
}

impl Drop for InternetHandle {
    fn drop(&mut self) {
        unsafe { WinHttpCloseHandle(self.0) };
    }
}

fn checked(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn post(
    path: &str,
    content_type: &str,
    token: Option<&str>,
    body: &[u8],
) -> Result<Value, Box<dyn Error>> {
    let mut headers = format!("Content-Type: {content_type}\r\nAccept: application/json\r\n");
    if let Some(token) = token {
        headers.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    let headers: Vec<u16> = headers.encode_utf16().chain([0]).collect();
    let path_wide: Vec<u16> = path.encode_utf16().chain([0]).collect();
    let length = u32::try_from(body.len())?;

    // WinHTTP owns the handle hierarchy. Each call borrows valid buffers only
    // for its duration because the session is opened in synchronous mode.
    unsafe {
        let session = InternetHandle::new(WinHttpOpen(
            w!("tailnet-term"),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            null(),
            null(),
            0,
        ))?;
        checked(WinHttpSetTimeouts(
            session.0, 10_000, 10_000, 10_000, 10_000,
        ))?;
        let connection =
            InternetHandle::new(WinHttpConnect(session.0, w!("api.tailscale.com"), 443, 0))?;
        let request = InternetHandle::new(WinHttpOpenRequest(
            connection.0,
            w!("POST"),
            path_wide.as_ptr(),
            null(),
            null(),
            null(),
            WINHTTP_FLAG_SECURE,
        ))?;
        checked(WinHttpSetOption(
            request.0,
            WINHTTP_OPTION_DISABLE_FEATURE,
            (&WINHTTP_DISABLE_REDIRECTS as *const u32).cast(),
            size_of::<u32>() as u32,
        ))?;
        checked(WinHttpSendRequest(
            request.0,
            headers.as_ptr(),
            u32::try_from(headers.len() - 1)?,
            body.as_ptr().cast(),
            length,
            length,
            0,
        ))?;
        checked(WinHttpReceiveResponse(request.0, null_mut()))?;
        let mut status = 0u32;
        let mut status_size = size_of::<u32>() as u32;
        checked(WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            null(),
            (&mut status as *mut u32).cast(),
            &mut status_size,
            null_mut(),
        ))?;
        if !(200..300).contains(&status) {
            // Do not echo remote response bodies, which may include credentials.
            return Err(format!("Tailscale API {path} failed (HTTP {status})").into());
        }
        let mut response = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let mut read = 0;
            checked(WinHttpReadData(
                request.0,
                chunk.as_mut_ptr().cast(),
                chunk.len() as u32,
                &mut read,
            ))?;
            if read == 0 {
                break;
            }
            if response.len() + read as usize > 64 * 1024 {
                return Err("Tailscale API response exceeded 64 KiB".into());
            }
            response.extend_from_slice(&chunk[..read as usize]);
        }
        serde_json::from_slice(&response).map_err(|_| "invalid JSON from the Tailscale API".into())
    }
}
