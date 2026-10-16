param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('stable', 'development')]
    [string]$KivyTestTarget
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$manifestPath = Join-Path $repoRoot 'diagnostic/angle-manifest.json'
$evidencePath = Join-Path $repoRoot 'diagnostic/angle-evidence.json'
$nativePath = Join-Path $repoRoot 'diagnostic/native/Release_x64'
$wheelPath = Join-Path $repoRoot 'dist'
$probePath = Join-Path $PSScriptRoot 'angle_dll_probe.py'
$environment = @{}
foreach ($name in @(
    'PYTHONPATH', 'PYTEST_PLUGINS',
    'ANGLE_DIAGNOSTIC_MANIFEST', 'ANGLE_DIAGNOSTIC_OUTPUT'
)) {
    $environment[$name] = [Environment]::GetEnvironmentVariable($name)
}

Push-Location -LiteralPath $repoRoot
try {
    python $probePath prepare --profile $KivyTestTarget --native-dir $nativePath `
        --wheel-dir $wheelPath --manifest $manifestPath
    if ($LASTEXITCODE -ne 0) {
        throw 'Baseline ANGLE artifact/wheel verification failed'
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $wheels = @($manifest.wheels | ForEach-Object { $_.path })
    python -m pip install --no-index --no-deps --force-reinstall @wheels
    if ($LASTEXITCODE -ne 0) {
        throw 'Installing the explicit local ANGLE wheels failed'
    }

    $separator = [IO.Path]::PathSeparator
    $env:PYTHONPATH = "$PSScriptRoot$separator$repoRoot"
    if ($environment['PYTHONPATH']) {
        $env:PYTHONPATH += "$separator$($environment['PYTHONPATH'])"
    }
    $env:PYTEST_PLUGINS = 'angle_dll_probe'
    if ($environment['PYTEST_PLUGINS']) {
        $env:PYTEST_PLUGINS += ",$($environment['PYTEST_PLUGINS'])"
    }
    $env:ANGLE_DIAGNOSTIC_MANIFEST = $manifestPath
    $env:ANGLE_DIAGNOSTIC_OUTPUT = $evidencePath

    # Exercise the real profile/install/test helper. The plugin rejects any
    # subsequent resolver replacement before tests and witnesses loaded DLLs.
    . (Join-Path $PSScriptRoot 'windows_ci.ps1')
    Test-kivy -KivyTestTarget $KivyTestTarget
} finally {
    foreach ($name in $environment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $environment[$name])
    }
    Pop-Location
}
