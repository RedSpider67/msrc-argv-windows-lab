# Windows-only measurement of the PowerShell stop-parsing token in
# TaskModuleSqlUtility 0.1.7 SqlPackageOnTargetMachines.ps1 ExecuteCommand.
# Both functions under test are lifted verbatim from the shipped nupkg by the
# PowerShell AST parser, not retyped. Synthetic markers only.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("sp-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force -Path $work | Out-Null

Write-Output "=================================================================="
Write-Output ("PSVersion        : " + $PSVersionTable.PSVersion)
Write-Output ("PSEdition        : " + $PSVersionTable.PSEdition)
Write-Output ("Host             : " + $Host.Name)
Write-Output ("OS               : " + [System.Environment]::OSVersion.VersionString)
Write-Output "=================================================================="

# ---------------------------------------------------------------- the module
$nupkg = Join-Path $here 'taskmodulesqlutility-0.1.7.nupkg'
Write-Output ("nupkg sha256     : " + (Get-FileHash -Algorithm SHA256 $nupkg).Hash.ToLower())
$zip = Join-Path $work 'pkg.zip'
Copy-Item $nupkg $zip
$ext = Join-Path $work 'pkg'
Expand-Archive -Path $zip -DestinationPath $ext -Force
$ps1 = Get-ChildItem -Recurse -Path $ext -Filter 'SqlPackageOnTargetMachines.ps1' | Select-Object -First 1
Write-Output ("module file      : " + $ps1.FullName.Replace($work,'<work>'))
Write-Output ("module sha256    : " + (Get-FileHash -Algorithm SHA256 $ps1.FullName).Hash.ToLower())
Write-Output ("module lines     : " + (Get-Content $ps1.FullName).Count)

$tok = $null; $err = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($ps1.FullName, [ref]$tok, [ref]$err)
$fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
foreach ($name in @('Get-SqlPackageCmdArgs','ExecuteCommand')) {
    $f = $fns | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    if (-not $f) { throw "function $name not found in the shipped module" }
    $text = $f.Extent.Text
    Write-Output ("lifted verbatim  : $name lines $($f.Extent.StartLineNumber)-$($f.Extent.EndLineNumber), $($text.Length) bytes")
    . ([scriptblock]::Create($text))
}

# Print the one line that the whole measurement is about.
$sinkLine = (Get-Content $ps1.FullName) | Select-String -Pattern 'Invoke-Expression' | Select-Object -First 1
Write-Output ("the sink         : line " + $sinkLine.LineNumber + "  " + $sinkLine.Line.Trim())
Write-Output ""

# ------------------------------------------------------- the native receiver
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$argvdump = Join-Path $work 'sqlpackage.exe'
& $csc /nologo /out:$argvdump (Join-Path $here 'argvdump.cs') | Out-Null
if (-not (Test-Path $argvdump)) { throw "failed to build the argv receiver" }
Write-Output ("argv receiver    : " + $argvdump.Replace($work,'<work>') + "  (a real native .exe standing in for SqlPackage.exe)")
Write-Output ""

# -------------------------------------------------------- the process env
# Emulates only the last hop: a variable already present in the child process
# environment. Nothing here claims how it got there.
$env:POC_PLAIN  = 'PLAINVALUE'
$env:POC_SPLIT  = 'x /p:InjectedOption=1 y'
$env:POC_QUOTE  = 'a"b'
$env:POC_NEST   = 'p%POC_PLAIN%q'
$env:POC_ARGV   = 'x" /p:InjectedOption=1 /q:"y'
Remove-Item Env:\POC_UNDEFINED_VAR -ErrorAction SilentlyContinue

$global:MARKER = 'not-executed'
function Get-Marker { $global:MARKER = 'EXECUTED-BY-POWERSHELL'; return 'X' }

function Leg([string]$label, [string]$dacpac) {
    Write-Output ""
    Write-Output "--- $label"
    Write-Output "    committed file name : $dacpac"
    $global:MARKER = 'not-executed'
    $a = Get-SqlPackageCmdArgs -dacpacFile $dacpac -targetMethod 'server' -serverName 'sqlprod01' -databaseName 'Fabrikam' -additionalArguments ''
    Write-Output "    IEX text            : & '$argvdump' --% $a"
    $out = ExecuteCommand -FileName "$argvdump" -Arguments $a
    ($out -split "`r?`n") | Where-Object { $_.Trim() } | ForEach-Object { Write-Output "    $($_.Trim())" }
    Write-Output "    powershell marker   : $global:MARKER"
}

$base = 'C:\agent\_work\r1\a\db'
Leg "CONTROL  ordinary name"                       "$base\Fabrikam.dacpac"
Leg "CONTROL  undefined percent variable"          "$base\Fab%POC_UNDEFINED_VAR%rikam.dacpac"
Leg "CONTROL  metacharacters, no percent"          "$base\Fab;rikam&whoami``id.dacpac"
Leg "CONTROL  powershell subexpression"            "$base\Fab`$(Get-Marker)rikam.dacpac"
Leg "INJECT   defined percent variable"            "$base\Fab%POC_PLAIN%rikam.dacpac"
Leg "INJECT   percent variable carrying spaces"    "$base\Fab%POC_SPLIT%rikam.dacpac"
Leg "INJECT   percent variable carrying a quote"   "$base\Fab%POC_QUOTE%rikam.dacpac"
Leg "INJECT   percent variable carrying percents"  "$base\Fab%POC_NEST%rikam.dacpac"
Leg "INJECT   quote plus space, the argv split"   "$base\Fab%POC_ARGV%rikam.dacpac"

# ---- Harness positive control. Identical code path, the --% token deleted.
function ExecuteCommand_NoStopParsing {
    param(
        [String][Parameter(Mandatory=$true)] $FileName,
        [String][Parameter(Mandatory=$true)] $Arguments
    )
    $ErrorActionPreference = 'SilentlyContinue'
    $result = ""
    Invoke-Expression "& '$FileName' $Arguments"  -ErrorVariable errors | ForEach-Object {
        $result +=  ("$_ " + [Environment]::NewLine)
    }
    $ErrorActionPreference = 'Stop'
    return $result
}
Write-Output ""
Write-Output "--- HARNESS POSITIVE CONTROL  subexpression, --% deleted"
$global:MARKER = 'not-executed'
$d = "$base\Fab`$(Get-Marker)rikam.dacpac"
$a = Get-SqlPackageCmdArgs -dacpacFile $d -targetMethod 'server' -serverName 'sqlprod01' -databaseName 'Fabrikam' -additionalArguments ''
$out = ExecuteCommand_NoStopParsing -FileName "$argvdump" -Arguments $a
($out -split "`r?`n") | Where-Object { $_.Trim() } | ForEach-Object { Write-Output "    $($_.Trim())" }
Write-Output "    powershell marker   : $global:MARKER"

Write-Output ""
Write-Output "DONE"
