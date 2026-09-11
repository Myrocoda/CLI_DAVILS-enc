# DAVILS Sprint 1 — Full Smoke Test
# Run from the project directory:
#   .\run_tests.ps1
#
# What this does:
#   1. Installs the cryptography package
#   2. Generates test files (50 MB, 300 MB, 2 GB)
#   3. Encrypts each with package.py (verifying +128 byte delta)
#   4. Verifies each with verify.py (HMAC check + byte-match)
#   5. Builds the three HDD layout variants

param(
    [switch]$SkipGenerate,    # skip generating test files (if already present)
    [switch]$Skip2GB          # skip the 2 GB test (speeds up quick iterations)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Project = Split-Path -Parent $MyInvocation.MyCommand.Path
$TestDir  = Join-Path $Project "test_files"
$KeyFile  = Join-Path $Project "output_key.json"

function Step($msg) {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $msg" -ForegroundColor Cyan
    Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

function Check($exitCode, $label) {
    if ($exitCode -ne 0) {
        Write-Host "FAILED: $label (exit $exitCode)" -ForegroundColor Red
        exit 1
    }
    Write-Host "PASS: $label" -ForegroundColor Green
}

# ── Step 0: Install dependency ───────────────────────────────────────────────
Step "Installing Python dependencies"
pip install -r "$Project\requirements.txt" --quiet
Check $LASTEXITCODE "pip install cryptography"

# ── Step 1: Generate test files ──────────────────────────────────────────────
if (-not $SkipGenerate) {
    Step "Generating test video files"
    $genArgs = @("$Project\generate_test_files.py", "--outdir", $TestDir)
    python @genArgs
    Check $LASTEXITCODE "generate_test_files.py"
} else {
    Write-Host "[skip] Test file generation (--SkipGenerate)" -ForegroundColor Yellow
}

# ── Helper: encrypt + verify a single file ───────────────────────────────────
function Test-File($name, $sizeMB) {
    $inFile  = Join-Path $TestDir "${name}.mp4"
    $outFile = Join-Path $TestDir "${name}.enc"

    Step "Encrypt: $name  (~${sizeMB} MB)"
    python "$Project\package.py" --input $inFile --output $outFile --key $KeyFile
    Check $LASTEXITCODE "package.py on $name"

    Step "Verify: $name"
    python "$Project\verify.py" --input $outFile --key $KeyFile --original $inFile
    Check $LASTEXITCODE "verify.py on $name"
}

# ── Step 2: Encrypt & verify each test size ──────────────────────────────────
Test-File "test_50mb"  50
Test-File "test_300mb" 300
if (-not $Skip2GB) {
    Test-File "test_2gb" 2048
} else {
    Write-Host "[skip] 2 GB test (--Skip2GB)" -ForegroundColor Yellow
}

# ── Step 3: Build HDD layout ─────────────────────────────────────────────────
Step "Building HDD layout variants"
python "$Project\build_hdd_layout.py" --key $KeyFile
Check $LASTEXITCODE "build_hdd_layout.py"

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  ALL SPRINT 1 SMOKE TESTS PASSED" -ForegroundColor Green
Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "Encrypted test files:"
Get-ChildItem $TestDir -Filter "*.enc" | ForEach-Object {
    $mb = [math]::Round($_.Length / 1MB, 1)
    Write-Host "  $($_.Name)  ($mb MB)"
}
Write-Host ""
Write-Host "HDD layout:"
Get-ChildItem (Join-Path $Project "hdd_layout") -Directory | ForEach-Object {
    Write-Host "  hdd_layout\$($_.Name)\"
}
Write-Host ""
Write-Host "Header spec: HEADER_FORMAT.md — hand this to the Android engineer."
Write-Host ""
