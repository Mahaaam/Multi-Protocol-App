param(
    [switch]$Standalone
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$proj = Join-Path $root 'src\DirectVpnLab\DirectVpnLab.csproj'
$assets = Join-Path $root 'src\DirectVpnLab\Assets\sing-box'

# Ensure NaiveProxy sidecar is present next to sing-box for publish/copy
$cronetTarget = Join-Path $assets 'libcronet.dll'
if (-not (Test-Path $cronetTarget)) {
    $candidates = @(
        (Join-Path $root 'TMP\sing-box-win\sing-box-1.14.4-windows-amd64\libcronet.dll'),
        (Join-Path $root 'TMP\libcronet.dll')
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) {
            Copy-Item $c $cronetTarget -Force
            Write-Host "Copied libcronet.dll -> Assets/sing-box"
            break
        }
    }
}

if (-not (Test-Path $cronetTarget)) {
    Write-Warning "libcronet.dll missing — NaiveProxy (D01/D02) will be unavailable until placed in Assets/sing-box"
}

if ($Standalone) {
    $out = Join-Path $root 'publish-standalone'
    Write-Host "Publishing standalone -> $out"
    dotnet publish $proj -c Release -r win-x64 --self-contained true `
        -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o $out
} else {
    $out = Join-Path $root 'publish'
    Write-Host "Publishing framework-dependent -> $out"
    dotnet publish $proj -c Release -r win-x64 --self-contained false -o $out
}

Write-Host "Done. Output: $out"
Write-Host "EXE requests Administrator via app.manifest (requireAdministrator / UAC)."
Write-Host "Remember: place private credentials under Assets/certs (gitignored)."
Write-Host "Required sidecars: sing-box.exe, wintun.dll, libcronet.dll under Assets/sing-box."
