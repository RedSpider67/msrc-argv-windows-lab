# Proof of concept

Two scripts. Neither contacts a live system, neither deploys anything, and the only payload is a program that writes one marker file.

## proof.js, construction, runs anywhere

Installs the published `azure-pipelines-tasks-webdeployment-common@4.281.0` and `azure-pipelines-task-lib@5.280.3`, calls the shipped `getMSDeployCmdArgs`, splits the result with the shipped `argStringToArray` lifted verbatim out of `deployusingmsdeploy.js`, and prints whether the `-source` token sits inside a cmd.exe quoted region under the shipped option pair and under a control with `windowsVerbatimArguments` omitted.

```
npm install
./run.sh
```

## detonate.ps1 and detonate.js, execution, Windows only

Builds `msdeploy.exe` from `argvdump.cs`, which prints the raw command line and every argv element it received, and `mark.exe` from `mark.cs`, which writes one marker file. It creates a real package file named `app&mark&.zip` on disk, then hands the array to a real `ToolRunner` with the shipped option pair, so a real cmd.exe parses the line.

```
powershell -NoProfile -File detonate.ps1
```

| Case | Options | Result |
|---|---|---|
| Inject | `windowsVerbatimArguments: true, shell: true` | marker written, `msdeploy.exe` reports `ARGC=2` with `-source` truncated at the ampersand |
| Control | `shell: true` only | no marker, `msdeploy.exe` reports `ARGC=4` with the package path intact inside quotes |
| Control | shipped options, ordinary package name | no marker |

The control with the identical bytes and the escaping left on is the one that shows the option pair is the defect rather than the file name.
