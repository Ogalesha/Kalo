# Windows packaging (experimental)

The Windows backend has not been validated on Windows hardware yet. Until it
is, the portable ZIP is the only packaging path.

Build the ZIP from a Windows checkout with the MSVC Rust toolchain:

```powershell
powershell -ExecutionPolicy Bypass -File packaging\windows\build-zip.ps1
```

The script runs `cargo build --release --locked` and writes
`dist\kalo-<version>-<arch>.zip` containing `kalo.exe`, `kalo.ico`,
`README.md` and `LICENSE`. Unpack it and run `kalo.exe`. The CI also
publishes a standalone `kalo-windows-x64.exe` in the rolling latest GitHub
release.

There is no installer, Start-menu entry, file association or background OPP
service registration yet. An MSI/WiX package and code signing remain on the
[roadmap](../../TODO.md).
