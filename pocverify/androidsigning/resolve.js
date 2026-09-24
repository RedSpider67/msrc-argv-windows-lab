// Leg 1: tool resolution.
//
// Replays findAndroidTool() from Tasks/AndroidSigningV3/androidsigning.ts against a
// build-tools directory materialised from the real Windows package file listing in
// build-tools-r34-windows-listing.txt, and prints what the task would run.
//
// Usage: node resolve.js <path-to-azure-pipelines-task-lib>

const fs = require('fs');
const os = require('os');
const path = require('path');

const tlPath = process.argv[2];
const tl = require(path.join(tlPath, 'task.js'));

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bt-'));
const buildTools = path.join(root, 'build-tools', '34.0.0');
const listing = fs.readFileSync(path.join(__dirname, 'build-tools-r34-windows-listing.txt'), 'utf8')
    .split('\n').map(s => s.trim()).filter(Boolean);

for (const entry of listing) {
    const rel = entry.replace(/^android-14\//, '');
    const dest = path.join(buildTools, rel);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, '');
}

console.log('files materialised from the real package listing: ' + listing.length);
console.log('entries whose name starts with apksigner:');
for (const entry of listing) { if (/apksigner/i.test(entry)) console.log('  ' + entry); }

// The exact call at androidsigning.ts:12.
const tool = 'apksigner';
const toolsList = tl.findMatch(tl.resolve(path.join(root, 'build-tools')), [`${tool}*`, '!*.jar'], null, { matchBase: true });

console.log('\nfindMatch([apksigner*, !*.jar], matchBase) returned ' + toolsList.length + ' path(s):');
for (const t of toolsList) console.log('  ' + path.relative(root, t));

const chosen = toolsList[0];
console.log('\ntask would set toolPath to: ' + path.relative(root, chosen));
console.log('ends with .BAT or .CMD (task-lib _isCmdFile): ' + /\.(bat|cmd)$/i.test(chosen));

// Control: the same call for zipalign, which the same task also runs.
const zipList = tl.findMatch(tl.resolve(path.join(root, 'build-tools')), ['zipalign*', '!*.jar'], null, { matchBase: true });
console.log('\nCONTROL zipalign resolves to: ' + zipList.map(z => path.relative(root, z)).join(', '));
console.log('CONTROL ends with .BAT or .CMD: ' + /\.(bat|cmd)$/i.test(zipList[0]));
