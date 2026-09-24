# Proof of concept

Three executed legs. Nothing here touches a live system and nothing here signs, uploads or deletes anything. Every leg runs against the published `azure-pipelines-task-lib@5.280.3` taken from npm. Legs 1 and 2 run anywhere. Leg 3 needs a Windows host, because it puts a real cmd.exe in the path.

Setup, from this directory:

```
npm install
./run.sh
```

`run.sh` calls both legs against `./node_modules/azure-pipelines-task-lib`.

## Leg 1, resolve.js

Materialises the 169 files of Google's `build-tools_r34-windows.zip` from the listing in `build-tools-r34-windows-listing.txt`, then runs the exact `tl.findMatch` call that `Tasks/AndroidSigningV3/androidsigning.ts` line 12 makes. It prints the single match, `apksigner.bat`, and prints `zipalign.exe` as the control, which is the other tool the same task invokes and which does not take the batch-file branch.

Regenerate the listing with:

```
curl -sSLO https://dl.google.com/android/repository/build-tools_r34-windows.zip
unzip -l build-tools_r34-windows.zip | awk 'NR>3 && NF>=4 {print $4}' | grep -v '/$'
```

## Leg 2, construct.js

Rebuilds the argv that `apksigning()` produces at lines 79 to 97, then calls the shipped `_getSpawnFileName`, `_getSpawnArgs` and `_getSpawnOptions` with `process.platform` set to `win32`, so the real Windows branches run rather than a reimplementation of them. Four cases in one run:

| Case | File name | Result |
|---|---|---|
| Control 1 | `app-release.apk` | passes through unquoted, benign |
| Control 2 | `app&calc&.apk` | quoted to `"D:\a\1\s\app&calc&.apk"`, so the ampersand is inert |
| Inject | `app%BUILD_SOURCEVERSIONMESSAGE%.apk` | passes through raw and unquoted |
| Control 3 | same name, `zipalign.exe` | never reaches cmd.exe, arguments stay an array |

Control 2 is the discriminating one. It shows the escaping works on the character that matters and fails only on the percent sign.

## Leg 3, detonate.ps1 and detonate.js (Windows only)

Builds two tiny helper programs from the C source next to them, `argvdump.exe`, which prints the raw command line and every argv element it was handed, and `mark.exe`, which writes one marker file and does nothing else. It then drives the shipped `execSync`, so a real cmd.exe parses the real command line and a real `apksigner.bat` runs.

```
powershell -NoProfile -File detonate.ps1
```

Four cases in one execution, with `BUILD_SOURCEVERSIONMESSAGE` set to `&mark&` in the process environment for all four:

| Case | File name | Tool | Marker written |
|---|---|---|---|
| Control 1 | `app-release.apk` | `apksigner.bat` | no |
| Control 2 | `app&mark&.apk` | `apksigner.bat` | no, the name is quoted and reaches the batch file as inert text |
| Inject | `app%BUILD_SOURCEVERSIONMESSAGE%.apk` | `apksigner.bat` | yes |
| Control 4 | `app%BUILD_SOURCEVERSIONMESSAGE%.apk` | `zipalign.exe` | no, the arguments stay an array and cmd.exe is never involved |

Control 2 is the discriminating one. The identical command, written straight into the file name, is escaped and inert. Delivered through the percent indirection it is not escaped and it runs.

The harness sets the environment variable itself. How the agent puts a pipeline variable into that environment is read from the agent source and is not executed here, and the report says so.
