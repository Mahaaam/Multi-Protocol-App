param(
    [switch]$Standalone
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$proj = Join-Path $root 'src\DirectVpnLab\DirectVpnLab.csproj'

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
Write-Host "Remember: place private credentials under Assets/certs (gitignored)."
