// ---------------------------------------------------------------------------
// cli.ts — Entry point.
//
//   ircnode keygen                     create this node's identity
//   ircnode id                         print the public key to share
//   ircnode peers                      list authorised peers
//   ircnode peers add <hex> [name]     authorise a peer
//   ircnode peers remove <hex|nodeid>  revoke a peer
//   ircnode serve [--port N] [--host H] [--connect host:port]
//   ircnode connect <host:port>        dial without listening
//
// Run directly: `node src/cli.ts serve`. Node 22 strips the types.
// ---------------------------------------------------------------------------

import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

import { loadOrCreateIdentity, PeerList, identityKeyPath } from './acl/peers.ts';
import { publicKeyToHex } from './crypto/identity.ts';
import { IrcNode, DEFAULT_HOST, DEFAULT_PORT } from './net/node.ts';
import { parseProxy, DEFAULT_TOR_SOCKS_PORT } from './net/socks5.ts';
import { Tui } from './ui/tui.ts';

const CONFIG_DIR = resolve(process.env['IRCNODE_CONFIG'] ?? 'config');

/* Build stamps, replaced by esbuild's --define when compiled into a binary.
   Read through `typeof` because running from source they do not exist at all,
   and a bare reference would be a ReferenceError before main() is reached.

   The commit matters more than the version: a binary that cannot be traced
   back to a specific source tree is one nobody can verify, and "0.1.0" is
   true of every build ever made from this tag. */
declare const __IRCNODE_VERSION__: string;
declare const __IRCNODE_COMMIT__: string;

const BUILD = {
    version: typeof __IRCNODE_VERSION__ === 'string' ? __IRCNODE_VERSION__ : 'dev',
    commit: typeof __IRCNODE_COMMIT__ === 'string' ? __IRCNODE_COMMIT__ : 'source',
};

function bootstrap() {
    mkdirSync(CONFIG_DIR, { recursive: true });
    const { identity, created } = loadOrCreateIdentity(CONFIG_DIR);
    const peers = new PeerList(CONFIG_DIR);
    return { identity, peers, created };
}

/** Parse `--flag value` pairs; everything else is positional. */
function parseArgs(argv: string[]) {
    const flags: Record<string, string> = {};
    const positional: string[] = [];
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i]!;
        if (arg.startsWith('--')) {
            const key = arg.slice(2);
            const next = argv[i + 1];
            if (next && !next.startsWith('--')) { flags[key] = next; i++; }
            else flags[key] = 'true';
        } else positional.push(arg);
    }
    return { flags, positional };
}

/** "host:port" or just "host". Rejects a malformed port rather than defaulting. */
function parseAddress(input: string): { host: string; port: number } {
    const at = input.lastIndexOf(':');
    if (at === -1) return { host: input, port: DEFAULT_PORT };
    const host = input.slice(0, at) || DEFAULT_HOST;
    const port = Number(input.slice(at + 1));
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`"${input}" does not contain a valid port`);
    }
    return { host, port };
}

/* ============================================================= commands == */

function cmdKeygen(): void {
    const { identity, created } = bootstrap();
    console.log(created ? 'Created a new node identity.' : 'This node already has an identity.');
    console.log(`  node id     ${identity.nodeId}`);
    console.log(`  public key  ${publicKeyToHex(identity.publicKey)}`);
    console.log(`  key file    ${identityKeyPath(CONFIG_DIR)}`);
    if (process.platform === 'win32') {
        /* Said plainly rather than implied. The file is written 0600, but NTFS
           does not enforce POSIX modes, so on Windows that is a request rather
           than a guarantee. Believing otherwise is worse than knowing. */
        console.log('\n  Note: the key file is written 0600, which Windows does not enforce.');
        console.log('  Protect it with NTFS permissions or full-disk encryption.');
    }
}

function cmdId(): void {
    const { identity } = bootstrap();
    console.log(publicKeyToHex(identity.publicKey));
}

function cmdVersion(): void {
    console.log(`ircnode ${BUILD.version}`);
    console.log(`  commit    ${BUILD.commit}`);
    console.log(`  runtime   node ${process.versions.node} (${process.platform}-${process.arch})`);
    console.log(`  handshake SIGMA / Ed25519 / X25519`);
    console.log(`  transport ChaCha20-Poly1305`);
    if (BUILD.commit === 'source') {
        console.log('\nRunning from source — this is the code you can read in src/.');
    } else {
        console.log(`\nVerify this build: https://github.com/Ashutosh0x/ircnode/commit/${BUILD.commit}`);
    }
}

function cmdPeers(positional: string[]): void {
    const { peers } = bootstrap();
    const [action, value, ...rest] = positional;

    if (!action || action === 'list') {
        if (peers.size === 0) {
            console.log('No authorised peers. Nobody can connect.');
            console.log(`Add one:  node src/cli.ts peers add <public-key-hex> <name>`);
            return;
        }
        console.log(`${peers.size} authorised peer(s):`);
        for (const p of peers.list()) {
            console.log(`  ${p.name.padEnd(16)} ${p.nodeId}  ${p.address ?? ''}`);
        }
        return;
    }

    if (action === 'add') {
        if (!value) throw new Error('usage: peers add <public-key-hex> [name] [address]');
        const added = peers.add(value, rest[0] ?? 'unnamed', rest[1]);
        console.log(added ? 'Peer authorised.' : 'That key was already authorised.');
        return;
    }

    if (action === 'remove') {
        if (!value) throw new Error('usage: peers remove <public-key-hex|node-id>');
        console.log(peers.remove(value) ? 'Peer revoked.' : 'No such peer.');
        return;
    }

    throw new Error(`unknown peers action "${action}"`);
}

async function cmdServe(flags: Record<string, string>): Promise<void> {
    const { identity, peers } = bootstrap();
    const port = Number(flags['port'] ?? DEFAULT_PORT);
    const host = flags['host'] ?? DEFAULT_HOST;

    /* --tor is shorthand for --proxy 127.0.0.1:9050, because that is the
       address in every Tor default configuration and asking people to
       remember a port number is a way to make a feature go unused. */
    const proxyFlag = flags['proxy'] ?? (flags['tor'] ? `127.0.0.1:${DEFAULT_TOR_SOCKS_PORT}` : null);
    const proxy = proxyFlag ? parseProxy(proxyFlag) : null;

    const node = new IrcNode({
        identity,
        peers,
        ...(flags['nick'] ? { nickname: flags['nick'] } : {}),
        ...(proxy ? { proxy } : {}),
    });
    const tui = new Tui(node);

    tui.system(`node ${identity.nodeId}`);
    if (proxy) tui.system(`outbound dials go through SOCKS5 ${proxy.host}:${proxy.port}`);
    if (peers.size === 0) {
        /* Worth interrupting for. A node with an empty allowlist looks
           perfectly healthy and refuses every connection, which is an hour of
           debugging the network before suspecting the config. */
        tui.system('allowlist is EMPTY — every connection will be refused. Use /add <pubkey>', 'error');
    }

    tui.on('command', (input) => { void handleInput(node, tui, input); });

    try {
        await node.listen(port, host);
    } catch (e) {
        tui.system((e as Error).message, 'error');
    }

    if (flags['connect']) {
        const { host: h, port: p } = parseAddress(flags['connect']);
        tui.system(`dialling ${h}:${p}…`);
        try {
            const peer = await node.dial(h, p);
            tui.system(`connected to ${peer.name} [${peer.nodeId.slice(0, 8)}]`, 'auth');
        } catch (e) {
            tui.system(`dial failed: ${(e as Error).message}`, 'error');
        }
    }

    tui.render();

    const shutdown = async () => { tui.close(); await node.close(); process.exit(0); };
    process.on('SIGINT', () => void shutdown());
    process.on('SIGTERM', () => void shutdown());
}

/* ============================================================= input == */

async function handleInput(node: IrcNode, tui: Tui, raw: string): Promise<void> {
    const input = raw.trim();
    if (!input) return;

    if (!input.startsWith('/')) {
        const delivered = node.say(tui.activeChannel, input);
        if (delivered === 0) tui.system('nobody in this channel received that — no peers connected', 'error');
        return;
    }

    const [command, ...args] = input.slice(1).split(/\s+/);

    switch ((command ?? '').toLowerCase()) {
        case 'help':
            tui.system('/connect host:port   dial a peer');
            tui.system('/add <pubkey> [name] authorise a peer');
            tui.system('/revoke <id>         revoke and disconnect a peer');
            tui.system('/peers               list connected peers');
            tui.system('/join #channel       join a channel');
            tui.system('/part #channel       leave a channel');
            tui.system('/switch #channel     change the active channel');
            tui.system('/id                  show this node\'s public key');
            tui.system('/quit                shut down');
            break;

        case 'connect': {
            if (!args[0]) { tui.system('usage: /connect host:port', 'error'); break; }
            try {
                const { host, port } = parseAddress(args[0]);
                tui.system(`dialling ${host}:${port}…`);
                const peer = await node.dial(host, port);
                tui.system(`connected to ${peer.name} [${peer.nodeId.slice(0, 8)}]`, 'auth');
            } catch (e) {
                tui.system(`dial failed: ${(e as Error).message}`, 'error');
            }
            break;
        }

        case 'add': {
            if (!args[0]) { tui.system('usage: /add <public-key-hex> [name]', 'error'); break; }
            try {
                const added = node.peers.add(args[0], args[1] ?? 'unnamed');
                tui.system(added ? 'peer authorised' : 'that key was already authorised', 'auth');
            } catch (e) {
                tui.system((e as Error).message, 'error');
            }
            break;
        }

        case 'revoke': {
            if (!args[0]) { tui.system('usage: /revoke <public-key-hex|node-id>', 'error'); break; }
            tui.system(node.revoke(args[0]) ? 'peer revoked and disconnected' : 'no such peer', 'auth');
            break;
        }

        case 'peers': {
            const connected = node.connected;
            if (connected.length === 0) tui.system('no peers connected');
            for (const p of connected) {
                const mins = Math.round((Date.now() - p.since) / 60000);
                tui.system(`${p.name} [${p.nodeId.slice(0, 12)}] ${p.address} ${p.inbound ? 'inbound' : 'outbound'} up ${mins}m`);
            }
            break;
        }

        case 'join':
            if (!args[0]) { tui.system('usage: /join #channel', 'error'); break; }
            if (node.join(args[0])) tui.setActiveChannel(args[0]);
            else tui.system(`"${args[0]}" is not a valid channel name`, 'error');
            break;

        case 'part':
            if (!args[0]) { tui.system('usage: /part #channel', 'error'); break; }
            if (!node.part(args[0])) tui.system('not in that channel', 'error');
            break;

        case 'switch':
            if (!args[0]) { tui.system('usage: /switch #channel', 'error'); break; }
            tui.setActiveChannel(args[0]);
            break;

        case 'id':
            tui.system(publicKeyToHex(node.identity.publicKey));
            break;

        case 'quit':
            tui.close();
            await node.close();
            process.exit(0);
            break;

        default:
            tui.system(`unknown command "/${command}" — try /help`, 'error');
    }
}

/* ============================================================= main == */

function usage(): void {
    console.log(`ircnode — a private, zero-trust IRC node

  keygen                            create this node's identity
  id                                print the public key to share with peers
  version                           build, commit and cipher suite
  peers [list]                      list authorised peers
  peers add <pubkey-hex> [name]     authorise a peer
  peers remove <pubkey|node-id>     revoke a peer
  serve [--port N] [--host H]       run the node with the terminal interface
        [--connect host:port]       …and dial a peer on startup
        [--nick name]
        [--tor]                     dial through Tor (SOCKS5 127.0.0.1:9050)
        [--proxy host:port]         dial through any SOCKS5 proxy

Reaching a peer on another network:
  --tor with a .onion address needs no port forwarding at either end.
  A WireGuard mesh (Tailscale etc.) also works: bind --host to the mesh
  address and dial the peer's mesh address directly.

Config lives in ./config (override with IRCNODE_CONFIG).
The listener binds ${DEFAULT_HOST} unless --host says otherwise.`);
}

async function main(): Promise<void> {
    const { flags, positional } = parseArgs(process.argv.slice(2));
    const command = positional[0];

    switch (command) {
        case 'keygen': return cmdKeygen();
        case 'id': return cmdId();
        case 'version':
        case '--version':
        case '-v':
            return cmdVersion();
        case 'peers': return cmdPeers(positional.slice(1));
        case 'serve': return cmdServe(flags);
        case 'connect':
            if (!positional[1]) throw new Error('usage: connect host:port');
            return cmdServe({ ...flags, connect: positional[1], port: flags['port'] ?? '0' });
        case undefined:
        case 'help':
            return usage();
        default:
            console.error(`unknown command "${command}"\n`);
            usage();
            process.exit(1);
    }
}

main().catch((e: unknown) => {
    console.error(`error: ${(e as Error).message}`);
    process.exit(1);
});
