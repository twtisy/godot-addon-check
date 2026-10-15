$ErrorActionPreference = 'Stop'
python tools/build_portable.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host 'Portable CLI: dist/addoncheck/addoncheck.cmd. Keep runtime/ and addoncheck/ together.'
Write-Host 'Official Python runtime and its license notices are included.'
