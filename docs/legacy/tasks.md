# Build and Test Tasks (deployment prep)

## Build
- Windows driver (minifilter): Use WDK/MSBuild; update `kernel_driver_manager.py` paths; ensure `.vcxproj` present. Add CI step: `msbuild RealAntiRansomwareDriver.vcxproj /p:Configuration=Release /p:Platform=x64`.

## Tests
- Linux netlink issuance: run `linux_broker.py` with PQC token connected; exercise rename/unlink/write on protected path and expect allow/deny per token.
- macOS token dropper: run `macos_token_dropper.py` to emit token JSON; ES client should allow with valid token and deny on missing/invalid nonce.
- Windows minifilter IOCTL: use `windows_minifilter_test.ps1` with valid HMAC key; expect STATUS_SUCCESS for valid HMAC, ACCESS_DENIED for invalid.

## TLS
- Broker: set `BROKER_TLS_CERT` and `BROKER_TLS_KEY` env vars; verify gRPC refuses insecure when set.

## Keys and paths
- Run `keygen.py --out-dir keys`; deploy keys to expected locations; provision PQC hardware tokens.
