[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$DataDir
)

$ErrorActionPreference = 'Stop'
chcp 65001 > $null
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
# PE 子系统必须为 Windows GUI，确保开始菜单启动时不弹出控制台。
$bytes = [System.IO.File]::ReadAllBytes($binaryPath)
$peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
if ([BitConverter]::ToUInt16($bytes, $peOffset + 24 + 68) -ne 2) { throw 'Executable is not a Windows GUI program.' }
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$dataPath = (Resolve-Path -LiteralPath $DataDir).Path
$resultPath = Join-Path $dataPath 'desktop-result.json'
if (Test-Path -LiteralPath $resultPath) { Remove-Item -LiteralPath $resultPath }
# 自检会创建真实原生窗口，并在消息循环中操作同一套控件和采集引擎。
$process = Start-Process -FilePath $binaryPath -ArgumentList @('--data-dir', "`"$dataPath`"", '--self-test-result', "`"$resultPath`"") -PassThru -WindowStyle Hidden
if (-not $process.WaitForExit(60000)) {
    $process.Kill()
    throw 'Native desktop self-test timed out.'
}
if ($process.ExitCode -ne 0) { throw "Native desktop failed with exit code $($process.ExitCode)" }
$result = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $result.success -or $result.version -ne $Version) { throw 'Native desktop self-test result or version mismatch.' }
foreach ($check in @('native_window', 'proxy_capture', 'redacted_details', 'native_filtering', 'pause_resume', 'har_export', 'no_web_ui', 'service_shutdown')) {
    if ($result.checks -notcontains $check) { throw "Missing native check: $check" }
}
Write-Output "Native desktop verified: $($result.checks -join ', ')"
