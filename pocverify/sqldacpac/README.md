# Proof of concept

Windows only. Both scripts read `Get-SqlPackageCmdArgs` and `ExecuteCommand` out of the published `taskmodulesqlutility-0.1.7.nupkg` next to them, using the PowerShell AST parser, and run those definitions unmodified.

```
powershell -NoProfile -File run.ps1
powershell -NoProfile -File argv.ps1
```

`run.ps1` drives Microsoft's real `SqlPackage.exe`, found under `C:\Program Files\Microsoft SQL Server\*\DAC\bin\`. The target server is a nonexistent local instance, so no database and no network host is contacted. The marker is a diagnostics log that SqlPackage itself writes to a path the injected option chose. Two controls run beside it.

`argv.ps1` replaces SqlPackage with `argvdump.cs`, a program that prints the raw command line and every argv element it received, so the split is visible directly. It runs the metacharacter controls, the undefined-variable control and the stop-parsing-token-deleted positive control.

Steps, expected output and impact are in `../report.md`.
