// End to end, over real TCP sockets on loopback.
//
// The security core is unit-tested in crypto.test.ts. What this proves is that
// the pieces are WIRED correctly — that the authorisation check is actually
// reached by the socket path, that an unauthorised peer is dropped by the real
// server rather than by a function nobody calls, and that a message survives
// the whole handshake -> AEAD -> framing -> IRC stack.
//
// A passing crypto suite and a server that forgot to consult it would look
// identical from the inside. This is the test that tells them apart.

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { generateIdentity, publicKeyToHex } from '../src/crypto/identity.ts';
import { PeerList, loadOrCreateIdentity } from '../src/acl/peers.ts';
import { IrcNode } from '../src/net/node.ts';

let pass = 0;
let fail = 0;
const check = (name: string, ok: boolean): void => {
    ok ? pass++ : fail++;
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
};
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** A config dir holding an allowlist with exactly these keys. */
function makeConfig(allowed: { publicKey: Buffer; name: string }[]): string {
    const dir = mkdtempSync(join(tmpdir(), 'ircnode-'));
    writeFileSync(join(dir, 'allowed-peers.json'), JSON.stringify({
        version: 1,
        peers: allowed.map((p) => ({
            publicKey: publicKeyToHex(p.publicKey),
            name: p.name,
            nodeId: '',
            addedAt: new Date().toISOString(),
        })),
    }));
    return dir;
}

/** A free-ish high port. Each test uses its own to avoid collisions. */
let nextPort = 39400;
const port = () => nextPort++;

const dirs: string[] = [];
const nodes: IrcNode[] = [];

try {
    /* ===================================================== authorised == */
    console.log('\n-- two authorised peers --');
    {
        const alice = generateIdentity();
        const bob = generateIdentity();

        const aliceDir = makeConfig([{ publicKey: bob.publicKey, name: 'bob' }]);
        const bobDir = makeConfig([{ publicKey: alice.publicKey, name: 'alice' }]);
        dirs.push(aliceDir, bobDir);

        const aliceNode = new IrcNode({ identity: alice, peers: new PeerList(aliceDir), nickname: 'alice' });
        const bobNode = new IrcNode({ identity: bob, peers: new PeerList(bobDir), nickname: 'bob' });
        nodes.push(aliceNode, bobNode);

        const p = port();
        await aliceNode.listen(p, '127.0.0.1');
        check('the node listens', aliceNode.isListening);

        const received: string[] = [];
        bobNode.on('line', (l) => { if (l.kind === 'chat') received.push(`${l.from}: ${l.text}`); });
        const aliceReceived: string[] = [];
        aliceNode.on('line', (l) => { if (l.kind === 'chat' && l.from !== 'alice') aliceReceived.push(l.text); });

        const peer = await bobNode.dial('127.0.0.1', p);
        check('an authorised peer completes the handshake', peer.nodeId === alice.nodeId);
        check('the peer is named from the allowlist', peer.name === 'alice');
        check('the dialer records it as outbound', peer.inbound === false);

        await wait(150);
        check('the listener sees one connected peer', aliceNode.connected.length === 1);
        check('the dialer sees one connected peer', bobNode.connected.length === 1);
        check('the listener identifies the dialer', aliceNode.connected[0]!.nodeId === bob.nodeId);

        // Channel membership is announced on connect, so a message routes.
        const delivered = aliceNode.say('#private-p2p', 'hello over an encrypted link');
        check('the message is delivered to one peer', delivered === 1);

        await wait(200);
        check('the peer received it', received.some((r) => r.includes('hello over an encrypted link')));

        // And back the other way — the link is symmetric.
        bobNode.say('#private-p2p', 'reply from bob');
        await wait(200);
        check('a reply travels the other way', aliceReceived.some((t) => t.includes('reply from bob')));

        // Several messages in sequence exercise the AEAD counter.
        for (let i = 0; i < 5; i++) aliceNode.say('#private-p2p', `sequenced ${i}`);
        await wait(300);
        check('sequenced messages all arrive',
            [0, 1, 2, 3, 4].every((i) => received.some((r) => r.includes(`sequenced ${i}`))));

        await aliceNode.close();
        await bobNode.close();
    }

    /* =================================================== unauthorised == */
    console.log('\n-- an unauthorised peer --');
    {
        const host = generateIdentity();
        const stranger = generateIdentity();

        // The host authorises nobody. The stranger authorises the host, so it
        // is the HOST's check that must do the work.
        const hostDir = makeConfig([]);
        const strangerDir = makeConfig([{ publicKey: host.publicKey, name: 'host' }]);
        dirs.push(hostDir, strangerDir);

        const hostNode = new IrcNode({ identity: host, peers: new PeerList(hostDir), nickname: 'host' });
        const strangerNode = new IrcNode({ identity: stranger, peers: new PeerList(strangerDir), nickname: 'stranger' });
        nodes.push(hostNode, strangerNode);

        const rejections: string[] = [];
        hostNode.on('line', (l) => { if (l.kind === 'error') rejections.push(l.text); });

        const p = port();
        await hostNode.listen(p, '127.0.0.1');

        let refused = false;
        try {
            await strangerNode.dial('127.0.0.1', p);
        } catch {
            refused = true;
        }

        check('an unauthorised peer cannot connect', refused);
        await wait(150);
        check('and holds no session', hostNode.connected.length === 0);
        check('the rejection is surfaced, not silent', rejections.length > 0);
        check('the rejection names the reason',
            rejections.some((r) => /not an authorised peer/i.test(r)));

        // A message sent now reaches nobody.
        check('nothing is delivered to a rejected peer', hostNode.say('#private-p2p', 'secret') === 0);

        await hostNode.close();
        await strangerNode.close();
    }

    /* ================================================= one-way trust == */
    console.log('\n-- trust must be mutual --');
    {
        /* The dialer authorises the listener but not vice versa. The listener
           must still refuse: authorisation is not transitive and being trusted
           does not mean trusting back. */
        const listener = generateIdentity();
        const dialer = generateIdentity();

        const listenerDir = makeConfig([]);                                        // trusts nobody
        const dialerDir = makeConfig([{ publicKey: listener.publicKey, name: 'l' }]); // trusts listener
        dirs.push(listenerDir, dialerDir);

        const l = new IrcNode({ identity: listener, peers: new PeerList(listenerDir) });
        const d = new IrcNode({ identity: dialer, peers: new PeerList(dialerDir) });
        nodes.push(l, d);

        const p = port();
        await l.listen(p, '127.0.0.1');

        let refused = false;
        try { await d.dial('127.0.0.1', p); } catch { refused = true; }
        check('one-way trust is not enough', refused);
        check('the listener admits nobody', l.connected.length === 0);

        await l.close();
        await d.close();
    }

    /* ======================================================= revoke == */
    console.log('\n-- revocation --');
    {
        const a = generateIdentity();
        const b = generateIdentity();
        const aDir = makeConfig([{ publicKey: b.publicKey, name: 'b' }]);
        const bDir = makeConfig([{ publicKey: a.publicKey, name: 'a' }]);
        dirs.push(aDir, bDir);

        const aNode = new IrcNode({ identity: a, peers: new PeerList(aDir), nickname: 'a' });
        const bNode = new IrcNode({ identity: b, peers: new PeerList(bDir), nickname: 'b' });
        nodes.push(aNode, bNode);

        const p = port();
        await aNode.listen(p, '127.0.0.1');
        await bNode.dial('127.0.0.1', p);
        await wait(150);
        check('the peer is connected before revocation', aNode.connected.length === 1);

        /* Revoking must drop the LIVE session too. Removing the key alone
           would leave a revoked peer reading the channel until it happened to
           reconnect. */
        const removed = aNode.revoke(b.nodeId);
        check('the key is removed from the allowlist', removed);
        await wait(200);
        check('and the live session is dropped', aNode.connected.length === 0);

        await aNode.close();
        await bNode.close();
    }

    /* ================================================== identity io == */
    console.log('\n-- identity persistence --');
    {
        const dir = mkdtempSync(join(tmpdir(), 'ircnode-id-'));
        dirs.push(dir);

        const first = loadOrCreateIdentity(dir);
        check('an identity is created on first run', first.created);
        const second = loadOrCreateIdentity(dir);
        check('and reloaded on the next', !second.created);
        check('the node id is stable across restarts', first.identity.nodeId === second.identity.nodeId);
    }

    /* ==================================================== peer list == */
    console.log('\n-- peer list --');
    {
        const dir = mkdtempSync(join(tmpdir(), 'ircnode-acl-'));
        dirs.push(dir);
        const list = new PeerList(dir);
        const peer = generateIdentity();

        check('an empty list authorises nobody', !list.isAuthorised(peer.publicKey));
        check('adding a peer works', list.add(publicKeyToHex(peer.publicKey), 'friend'));
        check('the peer is now authorised', list.isAuthorised(peer.publicKey));
        check('adding twice is a no-op', !list.add(publicKeyToHex(peer.publicKey), 'friend'));
        check('the name is recorded', list.nameFor(peer.publicKey) === 'friend');

        // Survives a reload from disk.
        check('the list persists', new PeerList(dir).isAuthorised(peer.publicKey));

        check('removing works', list.remove(publicKeyToHex(peer.publicKey)));
        check('and revokes access', !list.isAuthorised(peer.publicKey));
        check('removing something absent is false', !list.remove('deadbeef'));

        // A malformed file must fail loudly, not silently admit nobody.
        writeFileSync(join(dir, 'allowed-peers.json'), '{ "version": 1, "peers": [ {"publicKey":"zz"} ] }');
        let threw = false;
        try { new PeerList(dir); } catch { threw = true; }
        check('an invalid key in the file is reported', threw);
    }
} finally {
    for (const n of nodes) { try { await n.close(); } catch { /* already closed */ } }
    for (const d of dirs) { try { rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ } }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
