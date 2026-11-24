# tailnet-term

A small Windows PowerShell terminal over Tailscale. The server embeds its Tailnet connection. The client uses an existing Tailscale installation.

## Build

Run `.\Build-TailnetTerm.ps1` to build `target\release\tailnet-term.exe`.
Run `.\Build-PackedTailnetTerm.ps1` to build and verify `target\release\tailnet-term-packed.exe`.

The scripts install missing Rust and MSVC build tools when run online. MSVC setup may request administrator approval. The packed build also downloads and verifies UPX. Use `-Offline` with cached tools and dependencies, or `-Upx <path>` to use a specific UPX executable.


## Connect

1. On the client, run `.\tailnet-term.exe keygen .\client.key`. Keep the private key on the client and copy the printed public key to the server. Run `.\tailnet-term.exe ip` to print the client's Tailnet IPv4 address for the server command below.
2. On the server, set the `TS_AUTH_KEY` environment variable to a valid Tailscale auth key for initial enrollment. Start the server:

   ```powershell
   .\tailnet-term.exe server <client-tailnet-ip> <client-public-key> 'C:\Path\To\pwsh.exe' .\server.state
   ```

3. On the client, use the Tailnet IP printed by the server:

   ```powershell
   .\tailnet-term.exe client <server-tailnet-ip> .\client.key
   ```

Use `exit` to close the session. Reuse the state file when restarting the server. Each connection gets a fresh PowerShell session, and one client can connect at a time.

The server selects a DERP relay automatically. Set `TS_DERP_REGION` to a numeric region ID to override the selection.

The server keeps running when the client restarts or re-logs in to Tailscale, and it reconnects to Tailscale control and the DERP relay after network failures, retrying with a delay of up to 30 seconds. If the client disappears without closing its connection, the server drops the session after about a minute and accepts a new connection.

## Diagnostics

Developer probe commands are not part of the regular build. Build them with `cargo build --features diagnostics`:

- `control` checks the connection to Tailscale control (HTTPS key lookup, Noise handshake, HTTP/2).
- `relay <DERP-HOST>` checks the TLS connection and handshake with a DERP relay.
- `pty-check <SHELL>` runs a shell under ConPTY and checks commands, Ctrl+C, resizing and process cleanup.
