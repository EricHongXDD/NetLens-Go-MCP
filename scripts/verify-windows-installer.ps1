[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Installer,
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$ErrorActionPreference = 'Stop'
chcp 65001 > $null
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
# 此脚本只在一次性的 CI Windows runner 中安装，避免影响开发者已安装的实例。
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Installer verification requires an isolated GitHub Actions runner.' }
$installDir = Join-Path $env:RUNNER_TEMP 'NetLens Installer Test'
$shortcut = Join-Path ([Environment]::GetFolderPath('Programs')) 'NetLens/NetLens.lnk'
$process = Start-Process -FilePath (Resolve-Path -LiteralPath $Installer).Path -ArgumentList @(
    '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/DIR=`"$installDir`""
) -Wait -PassThru -WindowStyle Hidden
if ($process.ExitCode -ne 0) { throw "Installer failed with exit code $($process.ExitCode)" }
try {
    $binary = Join-Path $installDir 'NetLens.exe'
    $cli = Join-Path $installDir 'netlens-cli.exe'
    if (-not (Test-Path -LiteralPath $binary)) { throw 'Installed executable missing.' }
    $actualVersion = & $cli version
    if ($LASTEXITCODE -ne 0 -or $actualVersion -ne "NetLens $Version") { throw "Installed version mismatch: $actualVersion" }
    if (-not (Test-Path -LiteralPath $shortcut)) { throw 'Start Menu shortcut missing.' }
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($shortcut)
    if ($link.TargetPath -ne $binary -or $link.Arguments -ne '') { throw 'Start Menu shortcut target or arguments are incorrect.' }
    & (Join-Path $PSScriptRoot 'verify-desktop.ps1') -Binary $binary -Version $Version -DataDir (Join-Path $env:RUNNER_TEMP 'NetLens Native Test')
    & python (Join-Path $PSScriptRoot 'smoke.py') $cli
    if ($LASTEXITCODE -ne 0) { throw 'Installed binary MCP/proxy smoke test failed.' }
    Write-Output 'Installer, native desktop, Start Menu shortcut, version and installed MCP/proxy verified.'
} finally {
    $uninstaller = Join-Path $installDir 'unins000.exe'
    if (Test-Path -LiteralPath $uninstaller) {
        $result = Start-Process -FilePath $uninstaller -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -Wait -PassThru -WindowStyle Hidden
        if ($result.ExitCode -ne 0) { throw 'Uninstaller failed.' }
        if (Test-Path -LiteralPath $shortcut) { throw 'Uninstaller left the Start Menu shortcut behind.' }
        foreach ($name in @('NetLens.exe', 'netlens-cli.exe')) {
            if (Test-Path -LiteralPath (Join-Path $installDir $name)) { throw "Uninstaller left $name behind." }
        }
    }
}
