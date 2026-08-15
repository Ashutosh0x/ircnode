// Runs every suite and reports one total. Each suite is a plain script that
// prints "N passed, M failed" and exits non-zero on failure.
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.dirname(fileURLToPath(import.meta.url));
const suites = ['crypto.test.ts', 'e2e.test.ts'];

let total = 0, failed = 0;
const broken: string[] = [];

for (const suite of suites) {
    let out = '';
    let ok = true;
    try {
        out = execFileSync(process.execPath, [path.join(root, suite)], { encoding: 'utf8' });
    } catch (e) {
        ok = false;
        const err = e as { stdout?: string; stderr?: string };
        out = `${err.stdout ?? ''}${err.stderr ?? ''}`;
    }
    const m = out.match(/(\d+) passed, (\d+) failed/);
    const passed = m ? Number(m[1]) : 0;
    const bad = m ? Number(m[2]) : (ok ? 0 : 1);
    total += passed;
    failed += bad;
    if (!ok || bad) broken.push(suite);
    console.log(`${ok && !bad ? 'PASS' : 'FAIL'}  ${suite.padEnd(20)} ${passed} checks`);
    if (!ok || bad) console.log(out.split('\n').filter((l) => /FAIL|Error/.test(l)).slice(0, 8).map((l) => `        ${l}`).join('\n'));
}

console.log(`\n${suites.length} suites, ${total} checks, ${failed} failed`);
if (broken.length) { console.log(`failing: ${broken.join(', ')}`); process.exit(1); }
