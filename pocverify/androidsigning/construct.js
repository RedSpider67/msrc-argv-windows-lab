// Leg 2: argument construction.
//
// Reproduces the argv that Tasks/AndroidSigningV3/androidsigning.ts apksigning() builds,
// then calls the shipped azure-pipelines-task-lib functions that turn that argv into the
// bytes handed to CreateProcess. process.platform is flipped to win32 after the ToolRunner
// is constructed, so the real Windows branches of _getSpawnFileName, _getSpawnArgs and
// _getSpawnOptions execute rather than a reimplementation of them.
//
// Usage: node construct.js <path-to-azure-pipelines-task-lib>

const fs = require('fs');
const os = require('os');
const path = require('path');

const tlPath = process.argv[2];
const trmod = require(path.join(tlPath, 'toolrunner.js'));
console.log('azure-pipelines-task-lib version: ' + require(path.join(tlPath, 'package.json')).version);

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tools-'));
const BAT = path.join(dir, 'apksigner.bat');
const EXE = path.join(dir, 'zipalign.exe');
fs.writeFileSync(BAT, ''); fs.writeFileSync(EXE, '');
fs.chmodSync(BAT, 0o755); fs.chmodSync(EXE, 0o755);

// androidsigning.ts:79-97, in order.
function signArgs(apkPath) {
    return ['sign', '--ks', 'D:\\a\\_temp\\release.keystore',
            '--ks-pass', 'pass:' + 'S3cretKeystorePassword',
            '--ks-key-alias', 'release',
            '--verbose',
            apkPath];
}

function show(label, tool, args) {
    const tr = new trmod.ToolRunner(tool);
    tr.arg(args);
    const realPlatform = process.platform;
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
    let fileName, spawnArgs, opts;
    try {
        fileName = tr._getSpawnFileName({});
        spawnArgs = tr._getSpawnArgs({});
        opts = tr._getSpawnOptions({});
    } finally {
        Object.defineProperty(process, 'platform', { value: realPlatform, configurable: true });
    }
    console.log('\n' + label);
    console.log('  tool            : ' + path.basename(tool));
    console.log('  last argv in    : ' + args[args.length - 1]);
    console.log('  spawn file      : ' + path.basename(fileName));
    console.log('  windowsVerbatim : ' + opts.windowsVerbatimArguments);
    console.log('  spawn args      : ' + JSON.stringify(spawnArgs.map(a => a.replace(dir, '<toolsdir>'))));
    return spawnArgs;
}

const ORDINARY = 'D:\\a\\1\\s\\app-release.apk';
const AMPERSAND = 'D:\\a\\1\\s\\app&calc&.apk';
const PERCENT = 'D:\\a\\1\\s\\app%BUILD_SOURCEVERSIONMESSAGE%.apk';

show('CONTROL 1  ordinary committed file name, .bat tool', BAT, signArgs(ORDINARY));
show('CONTROL 2  ampersand in the file name, .bat tool', BAT, signArgs(AMPERSAND));
const injected = show('INJECT     percent-wrapped variable in the file name, .bat tool', BAT, signArgs(PERCENT));
show('CONTROL 3  same file name, .exe tool (zipalign leg of the same task)', EXE, ['-v', '4', PERCENT, PERCENT]);

// Leg 3: what cmd.exe does with the line from the INJECT leg.
// cmd.exe substitutes %NAME% from its own environment while parsing the /C command line,
// before it splits the line on the command separators & && | ||. This step is not executed
// here, because it needs a Windows host. The substitution below is a textual replay of it,
// printed so the resulting command line can be read.
const commitMessage = '&whoami&';
const replayed = injected[0].split('%BUILD_SOURCEVERSIONMESSAGE%').join(commitMessage);
console.log('\nREPLAY (not executed) cmd.exe percent substitution on the INJECT line');
console.log('  BUILD_SOURCEVERSIONMESSAGE = ' + commitMessage);
console.log('  line after substitution    : ' + replayed.replace(dir, '<toolsdir>'));
console.log('  the injected & characters sit outside every quoted region of that line');
