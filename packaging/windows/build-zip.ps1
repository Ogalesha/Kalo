# Build a portable Windows ZIP for Kalo.
#
# Usage (from a Windows checkout with the MSVC Rust toolchain):
#   powershell -ExecutionPolicy Bypass -File packaging\windows\build-zip.ps1
#
# The backend is experimental; see packaging/windows/README.md.

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $Root

$VersionLine = Select-String -Path "Cargo.toml" -Pattern '^version = "([^"]+)"' |
    Select-Object -First 1
if (-not $VersionLine) {
    throw "cannot read the package version from Cargo.toml"
}
$Version = $VersionLine.Matches[0].Groups[1].Value

$Arch = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
    "X64" { "x64" }
    "Arm64" { "arm64" }
    default { "unknown" }
}

cargo build --release --locked
if ($LASTEXITCODE -ne 0) {
    throw "cargo build failed"
}

$TargetRoot = if ($env:CARGO_BUILD_TARGET) {
    Join-Path "target" $env:CARGO_BUILD_TARGET
} else {
    "target"
}
$Exe = Join-Path $TargetRoot "release\kalo.exe"
if (-not (Test-Path $Exe)) {
    throw "built binary not found at $Exe"
}

$Stage = Join-Path ([System.IO.Path]::GetTempPath()) ("kalo-zip-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Stage | Out-Null
try {
    Copy-Item $Exe $Stage
    Copy-Item "packaging\windows\kalo.ico" $Stage
    Copy-Item "README.md", "LICENSE" $Stage
    New-Item -ItemType Directory -Force -Path "dist" | Out-Null
    $Zip = Join-Path "dist" "kalo-$Version-$Arch.zip"
    if (Test-Path $Zip) {
        Remove-Item $Zip
    }
    Compress-Archive -Path (Join-Path $Stage "*") -DestinationPath $Zip
    Write-Host "Built $Zip"
}
finally {
    Remove-Item -Recurse -Force $Stage
}
