param(
    [string]$PythonExe = "python"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$nativeDir = Join-Path $root "native\traffic_core"

Write-Host "[traffic_core] install build deps..."
& $PythonExe -m pip install --upgrade pybind11 | Out-Host

Write-Host "[traffic_core] build via setuptools..."
Push-Location $nativeDir
try {
    & $PythonExe setup.py build_ext --inplace | Out-Host
} finally {
    Pop-Location
}

$releasePyd = Get-ChildItem -Path $nativeDir -Recurse -Filter "traffic_core*.pyd" | Select-Object -First 1
if (-not $releasePyd) {
    throw "traffic_core .pyd not produced"
}

$target = Join-Path $root "traffic_core.pyd"
Copy-Item -Path $releasePyd.FullName -Destination $target -Force
Write-Host "[traffic_core] done: $target"
