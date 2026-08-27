param(
    [string]$OutputName = "NetScope_SourceCode"
)

$ErrorActionPreference = "Stop"
$scriptDir = Resolve-Path "$PSScriptRoot"
$root = Resolve-Path "$scriptDir\.."
$output = Join-Path $root "$OutputName.zip"
$rootPath = $root.ToString()
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("netscope_pack_" + [guid]::NewGuid().ToString("N"))
$staging = Join-Path $tempRoot "package"

$includeItems = @(
    "src"
    "tests"
    "scripts"
    "native"
    "virtual_test"
    "models"
    ".github"
    "benchmarks"
    "desktop_main.py"
    "NetScope.spec"
    "requirements.txt"
    "requirements-test.txt"
    "README.md"
    ".gitignore"
    ".bandit"
)

Write-Host "Packaging NetScope project source code ...`n" -ForegroundColor Cyan

if (Test-Path $output) { Remove-Item $output -Force }
New-Item -ItemType Directory -Path $staging -Force | Out-Null

$fileCount = 0

try {
    foreach ($item in $includeItems) {
        $sourcePath = Join-Path $rootPath $item
        if (-not (Test-Path $sourcePath)) {
            Write-Host "  [WARN] $item not found, skipped" -ForegroundColor DarkYellow
            continue
        }

        if (Test-Path $sourcePath -PathType Container) {
            $files = Get-ChildItem -Recurse -File $sourcePath
            foreach ($f in $files) {
                $full = $f.FullName
                $relative = $full.Substring($rootPath.Length).TrimStart('\').TrimStart('/')
                if ($relative -match '__pycache__[/\\]') { continue }
                if ($relative -match '\.pyc$') { continue }
                if ($relative -match '\.pyo$') { continue }
                if ($relative -match '\.pytest_cache') { continue }
                if ($relative -match 'native[/\\]traffic_core[/\\]build[/\\]') { continue }

                $target = Join-Path $staging $relative
                $dir = [System.IO.Path]::GetDirectoryName($target)
                if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
                Copy-Item -Path $full -Destination $target -Force
                $fileCount++
            }
        } else {
            $relative = $item
            $target = Join-Path $staging $relative
            $dir = [System.IO.Path]::GetDirectoryName($target)
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Copy-Item -Path $sourcePath -Destination $target -Force
            $fileCount++
        }
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($staging, $output, [System.IO.Compression.CompressionLevel]::Optimal, $false)
}
finally {
    if (Test-Path $tempRoot) {
        Remove-Item $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$size = (Get-Item $output).Length
$sizeMB = [math]::Round($size / 1MB, 2)

Write-Host "Packaging succeeded!" -ForegroundColor Green
Write-Host "  Files packaged: $fileCount" -ForegroundColor Gray
Write-Host "  Output: $output" -ForegroundColor Yellow
Write-Host "  Size: ${sizeMB} MB" -ForegroundColor Gray
