# Repository conventions

Use English for repository content, including documentation, code comments,
CLI messages, and commit messages.

## Engineering priorities

Resolve trade-offs in this order:

1. **Executable size.** Keep each shipped UPX-compressed executable below
   1 MB (1,000,000 bytes), including the legacy-support build.
2. **Connection setup performance.** Minimize the time from initiating a
   connection until the remote session is ready.
3. **Program startup performance.** Minimize the time from launching the
   executable until it is ready to perform the requested operation.
