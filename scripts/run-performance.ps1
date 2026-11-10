[CmdletBinding()]
param(
    [ValidateSet('smoke', 'full')][string]$Profile = 'smoke',
    [string]$Configuration = '.runtime/performance-local.json',
    [string]$RunDirectory,
    [switch]$PreflightOnly
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

function Resolve-ProjectPath([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { throw 'A dependency path is missing.' }
    if ([IO.Path]::IsPathRooted($Value)) { return [IO.Path]::GetFullPath($Value) }
    return [IO.Path]::GetFullPath((Join-Path $projectRoot $Value))
}

$settings = Get-Content -LiteralPath (Resolve-ProjectPath $Configuration) -Raw | ConvertFrom-Json
foreach ($name in @('python', 'unity_url', 'opa', 'binary', 'plain_binary', 'model_path')) {
    if ([string]::IsNullOrWhiteSpace([string]$settings.$name)) {
        throw "Configuration field '$name' is required."
    }
}
foreach ($name in @('python', 'opa', 'binary', 'plain_binary', 'model_path')) {
    if (-not (Test-Path -LiteralPath (Resolve-ProjectPath $settings.$name) -PathType Leaf)) {
        throw "Configured dependency '$name' does not name a file."
    }
}
$modelPort = 18325
if ($settings.PSObject.Properties.Name -contains 'model_port') {
    $modelPort = [int]$settings.model_port
    if ($modelPort -lt 1 -or $modelPort -gt 65535) { throw 'model_port must be in 1..65535.' }
}
$polarsThreads = $null
if ($settings.PSObject.Properties.Name -contains 'polars_threads') {
    $polarsThreads = [int]$settings.polars_threads
    if ($polarsThreads -lt 1) { throw 'polars_threads must be a positive integer.' }
}
$python = Resolve-ProjectPath $settings.python
$profileFile = if ($Profile -eq 'full') { 'performance.json' } else { 'performance-smoke.json' }
if ([string]::IsNullOrWhiteSpace($RunDirectory)) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $RunDirectory = "experiments/results/performance-$Profile-$stamp-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
}
$arguments = @(
    '-m', 'experiments.paper_evaluation.performance',
    '--profile', (Join-Path $projectRoot "config/$profileFile"),
    '--run-directory', (Resolve-ProjectPath $RunDirectory),
    '--unity-url', [string]$settings.unity_url,
    '--opa', (Resolve-ProjectPath $settings.opa),
    '--binary', (Resolve-ProjectPath $settings.binary),
    '--plain-binary', (Resolve-ProjectPath $settings.plain_binary),
    '--model-path', (Resolve-ProjectPath $settings.model_path),
    '--port', [string]$modelPort
)
if ($settings.sdk_build_record) {
    $sdkBuildRecord = Resolve-ProjectPath $settings.sdk_build_record
    if (-not (Test-Path -LiteralPath $sdkBuildRecord -PathType Leaf)) {
        throw 'Configured sdk_build_record does not name a file.'
    }
    $arguments += @('--sdk-build-record', $sdkBuildRecord)
}
if ($PreflightOnly) { $arguments += '--preflight-only' }
$previousDistribution = $env:TN_WSL_DISTRO
$previousPolarsThreads = $env:POLARS_MAX_THREADS
try {
    if ($settings.wsl_distribution) { $env:TN_WSL_DISTRO = [string]$settings.wsl_distribution }
    if ($null -ne $polarsThreads) { $env:POLARS_MAX_THREADS = [string]$polarsThreads }
    Push-Location -LiteralPath $projectRoot
    try {
        & $python @arguments
        if ($LASTEXITCODE -ne 0) { throw "Performance runner exited with code $LASTEXITCODE." }
    } finally { Pop-Location }
} finally {
    $env:TN_WSL_DISTRO = $previousDistribution
    $env:POLARS_MAX_THREADS = $previousPolarsThreads
}
