// ---------------------------------------------------------------------------
// build.mjs — Bundle the node into one file, then into one executable.
//
// Two steps, because Node's Single Executable Application feature takes a
// SINGLE script and this project is a tree of ES modules:
//
//   1. esbuild flattens src/cli.ts into build/bundle.cjs
//   2. Node's --experimental-sea-config turns that into a blob, and postject
//      injects the blob into a copy of the node binary
//
// ── What this costs, stated plainly ─────────────────────────────────────────
//
// The rest of this project runs straight off the TypeScript, so the code you
// audit is the code that executes. A bundled binary is NOT that: it is a
// derived artifact, and reading it tells you much less than reading src/ does.
//
// So the binary is a convenience for people who will not clone the repo, and
// the mitigation is provenance rather than readability — built only from a
// tagged commit, in CI, with the commit recorded in the binary itself
// (--define below) and SHA-256 published alongside. Anyone who wants the real
// guarantee should still clone and run `npm test`.
// ---------------------------------------------------------------------------

import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, rmSync, writeFileSync, chmodSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';

/* esbuild's JS API rather than its CLI.
   `node_modules/esbuild/bin/esbuild` is the NATIVE binary on Linux and macOS —
   running it through `node` reads an ELF/Mach-O file as JavaScript and dies on
   the first byte with "SyntaxError: Invalid or unexpected token". Windows is
   the exception: there esbuild installs a JS shim at that path, so the CLI
   approach worked locally and only failed in CI. The API has no such
   platform split. */
import { build as esbuild } from 'esbuild';

const ROOT = resolve(import.meta.dirname, '..');
const OUT = join(ROOT, 'build');

const platform = process.platform;
const target = process.env.BUILD_TARGET ?? platform;
const version = JSON.parse(
    execFileSync(process.execPath, ['-p', 'JSON.stringify(require("./package.json"))'], { cwd: ROOT, encoding: 'utf8' }),
).version;

/* Recorded into the binary so a user holding one can say exactly which source
   produced it. An artifact that cannot be traced back to a commit is one
   nobody can verify. */
const commit = (() => {
    try { return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim(); }
    catch { return 'unknown'; }
})();

const exeName = target === 'win32' ? 'ircnode.exe' : 'ircnode';
const exePath = join(OUT, exeName);

console.log(`building ircnode ${version} (${commit.slice(0, 8)}) for ${target}`);

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

/* ============================================================= 1. bundle == */

/* CommonJS output: SEA loads the main script through the CJS loader, so an
   ESM bundle fails at runtime with an import-outside-module error rather than
   at build time. */
await esbuild({
    entryPoints: [join(ROOT, 'src', 'cli.ts')],
    bundle: true,
    platform: 'node',
    target: 'node22',
    format: 'cjs',
    outfile: join(OUT, 'bundle.cjs'),
    // JSON.stringify so the replacement is a valid JS string literal, which is
    // what --define substitutes textually.
    define: {
        __IRCNODE_VERSION__: JSON.stringify(version),
        __IRCNODE_COMMIT__: JSON.stringify(commit),
    },
    logLevel: 'warning',
});

console.log('  bundled  build/bundle.cjs');

/* ============================================================= 2. blob == */

writeFileSync(join(OUT, 'sea-config.json'), JSON.stringify({
    main: 'build/bundle.cjs',
    output: 'build/sea-prep.blob',
    disableExperimentalSEAWarning: true,
    /* Snapshots would start faster but cannot run code that touches the
       filesystem or network at load time, which this does. */
    useSnapshot: false,
    useCodeCache: true,
}, null, 2));

execFileSync(process.execPath, ['--experimental-sea-config', 'build/sea-config.json'], {
    cwd: ROOT, stdio: 'inherit',
});
console.log('  prepared build/sea-prep.blob');

/* ============================================================= 3. inject == */

copyFileSync(process.execPath, exePath);

/* macOS refuses to run a Mach-O whose signature no longer matches its
   contents, and injecting a section invalidates the existing one. Strip first,
   re-sign after — ad-hoc unless a real identity is supplied by CI. */
if (target === 'darwin') {
    try { execFileSync('codesign', ['--remove-signature', exePath], { stdio: 'inherit' }); }
    catch { console.warn('  (codesign --remove-signature failed; continuing)'); }
}

const postjectArgs = [
    join(ROOT, 'node_modules', 'postject', 'dist', 'cli.js'),
    exePath,
    'NODE_SEA_BLOB',
    join(OUT, 'sea-prep.blob'),
    '--sentinel-fuse', 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2',
];
// Mach-O needs the segment named explicitly; ELF and PE do not.
if (target === 'darwin') postjectArgs.push('--macho-segment-name', 'NODE_SEA');

execFileSync(process.execPath, postjectArgs, { cwd: ROOT, stdio: 'inherit' });

if (target === 'darwin') {
    try { execFileSync('codesign', ['--sign', '-', exePath], { stdio: 'inherit' }); }
    catch { console.warn('  (ad-hoc codesign failed; the binary may not launch on macOS)'); }
}

if (target !== 'win32') chmodSync(exePath, 0o755);

console.log(`  injected ${exeName}`);

/* ============================================================= 4. verify == */

/* Run the thing that was just built. A build that produces a file nobody
   executed is not a build that succeeded — this is what catches an ESM bundle
   that cannot load, or a broken injection, before it reaches a release. */
if (target === platform) {
    const out = execFileSync(exePath, ['help'], { encoding: 'utf8' });
    if (!out.includes('ircnode')) throw new Error('built binary did not run correctly');
    console.log('  verified the binary runs');
}

// Intermediates are not artifacts.
rmSync(join(OUT, 'bundle.cjs'), { force: true });
rmSync(join(OUT, 'sea-prep.blob'), { force: true });
rmSync(join(OUT, 'sea-config.json'), { force: true });

if (!existsSync(exePath)) throw new Error('build produced no executable');
console.log(`\ndone: build/${exeName}`);
