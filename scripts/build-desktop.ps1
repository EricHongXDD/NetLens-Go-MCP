[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version = '0.4.0',
    [string]$Output = 'bin/NetLens.exe'
)

$ErrorActionPreference = 'Stop'
chcp 65001 > $null
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
$previousGOOS, $previousGOARCH, $previousCGO = $env:GOOS, $env:GOARCH, $env:CGO_ENABLED
try {
    $env:GOOS, $env:GOARCH, $env:CGO_ENABLED = 'windows', 'amd64', '0'
    $outputPath = [System.IO.Path]::GetFullPath($Output)
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $outputPath) | Out-Null
    # 将 Common Controls v6 和 DPI 清单编入程序，避免依赖外部 manifest 文件。
    & go run github.com/akavel/rsrc@v0.10.2 -arch amd64 -manifest cmd/netlens-desktop/netlens.manifest -o cmd/netlens-desktop/rsrc_windows_amd64.syso
    if ($LASTEXITCODE -ne 0) { throw 'Desktop manifest compilation failed.' }
    & go build -trimpath -ldflags "-H windowsgui -s -w -X netlens/internal/model.Version=$Version" -o $outputPath ./cmd/netlens-desktop
    if ($LASTEXITCODE -ne 0) { throw 'Native desktop build failed.' }
    Write-Output "Native desktop: $outputPath"
} finally {
    $env:GOOS, $env:GOARCH, $env:CGO_ENABLED = $previousGOOS, $previousGOARCH, $previousCGO
    Pop-Location
}
