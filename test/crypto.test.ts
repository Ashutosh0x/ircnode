// Security core: identity, handshake, session, framing, IRC grammar.
//
// The tests that matter here are the negative ones. A handshake that succeeds
// between two honest parties proves very little — the question is whether it
// FAILS for a tampered transcript, an unauthorised key, a replayed frame, or a
// peer presenting our own identity. Those are the assertions that would catch
// a regression that silently weakens the protocol.

import { randomBytes } from 'node:crypto';
import {
    generateIdentity, nodeIdFromPublicKey, publicKeyFromHex, publicKeyToHex,
    publicKeysEqual, sign, verify, identityFromPrivateKeyPem, privateKeyToPem,
} from '../src/crypto/identity.ts';
import { HandshakeState, PROTOCOL_VERSION, decodeAuth, encodeAuth } from '../src/crypto/handshake.ts';
import { SendCipher, ReceiveCipher, MAX_PLAINTEXT_BYTES } from '../src/crypto/session.ts';
import { frame, FrameReader, MAX_FRAME_BYTES } from '../src/protocol/framing.ts';
import { parseMessage, serialiseMessage, isValidChannelName, isValidNickname } from '../src/protocol/message.ts';

let pass = 0;
let fail = 0;
export const check = (name: string, ok: boolean): void => {
    ok ? pass++ : fail++;
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
};
const threw = (fn: () => unknown): boolean => {
    try { fn(); return false; } catch { return true; }
};

/** A copy of `buf` with one bit flipped. Used to prove tampering is caught. */
const flipBit = (buf: Buffer, index: number): Buffer => {
    const copy = Buffer.from(buf);
    copy.writeUInt8(copy.readUInt8(index) ^ 1, index);
    return copy;
};

/* ============================================================= identity == */
console.log('\n-- identity --');
{
    const id = generateIdentity();
    check('a public key is 32 bytes', id.publicKey.length === 32);
    check('a node id is 32 hex chars', /^[0-9a-f]{32}$/.test(id.nodeId));
    check('the node id derives from the key', id.nodeId === nodeIdFromPublicKey(id.publicKey));

    const message = Buffer.from('authorise me');
    const sig = sign(id.privateKey, message);
    check('a signature verifies', verify(id.publicKey, message, sig));
    check('a different message does not', !verify(id.publicKey, Buffer.from('authorize me'), sig));

    const other = generateIdentity();
    check('another key does not verify it', !verify(other.publicKey, message, sig));
    check('a tampered signature does not verify',
        !verify(id.publicKey, message, Buffer.concat([sig.subarray(0, 63), Buffer.from([sig[63]! ^ 1])])));
    check('garbage does not throw, it returns false',
        verify(id.publicKey, message, Buffer.alloc(4)) === false);

    // Round-trip through the on-disk format.
    const restored = identityFromPrivateKeyPem(privateKeyToPem(id.privateKey));
    check('an identity survives a PEM round trip', restored.nodeId === id.nodeId);
    check('and keeps the same public key', publicKeysEqual(restored.publicKey, id.publicKey));

    check('hex round-trips', publicKeysEqual(publicKeyFromHex(publicKeyToHex(id.publicKey)), id.publicKey));
    check('a short key is rejected', threw(() => publicKeyFromHex('aabb')));
    check('non-hex is rejected', threw(() => publicKeyFromHex('zz'.repeat(32))));

    check('distinct keys are not equal', !publicKeysEqual(id.publicKey, other.publicKey));
    check('different lengths are not equal', !publicKeysEqual(id.publicKey, Buffer.alloc(16)));
}

/* ============================================================= handshake == */
console.log('\n-- handshake --');

/** Run a full four-message handshake between two parties. */
function runHandshake(
    initiator = generateIdentity(),
    responder = generateIdentity(),
    opts: { initiatorAllows?: (k: Buffer) => boolean; responderAllows?: (k: Buffer) => boolean } = {},
) {
    const allowAll = () => true;
    const i = new HandshakeState(initiator, true);
    const r = new HandshakeState(responder, false);

    const hello = i.clientHello();
    const serverHello = r.serverHello(hello);
    i.consumeServerHello(serverHello);

    // Responder authenticates first.
    const rAuth = r.auth();
    i.verifyPeerAuth(rAuth, opts.initiatorAllows ?? allowAll);

    const iAuth = i.auth();
    r.verifyPeerAuth(iAuth, opts.responderAllows ?? allowAll);

    return { i, r, initiator, responder };
}

{
    const { i, r, initiator, responder } = runHandshake();
    const ik = i.sessionKeys();
    const rk = r.sessionKeys();

    check('both sides derive the same i2r key', ik.initiatorToResponder.equals(rk.initiatorToResponder));
    check('both sides derive the same r2i key', ik.responderToInitiator.equals(rk.responderToInitiator));
    check('the two directions use different keys',
        !ik.initiatorToResponder.equals(ik.responderToInitiator));
    check('both agree on the session id', ik.sessionId.equals(rk.sessionId));

    check('the initiator learns the responder identity', publicKeysEqual(ik.peerPublicKey, responder.publicKey));
    check('the responder learns the initiator identity', publicKeysEqual(rk.peerPublicKey, initiator.publicKey));
    check('peer node ids are reported', ik.peerNodeId === responder.nodeId);

    // Forward secrecy: fresh ephemerals every time.
    const again = runHandshake(initiator, responder);
    check('a second handshake derives different keys',
        !again.i.sessionKeys().initiatorToResponder.equals(ik.initiatorToResponder));
    check('and a different session id', !again.i.sessionKeys().sessionId.equals(ik.sessionId));
}

console.log('\n-- handshake: rejections --');
{
    // THE case this design exists for: authorisation is enforced inside the
    // handshake, so forgetting to check afterwards cannot admit a stranger.
    check('an unauthorised peer is refused', threw(() => runHandshake(
        generateIdentity(), generateIdentity(), { responderAllows: () => false })));
    check('an unauthorised responder is refused by the initiator', threw(() => runHandshake(
        generateIdentity(), generateIdentity(), { initiatorAllows: () => false })));

    // Identity misbinding: a signature must not transfer between exchanges.
    {
        const a = generateIdentity(), b = generateIdentity();
        const h1i = new HandshakeState(a, true);
        const h1r = new HandshakeState(b, false);
        h1i.consumeServerHello(h1r.serverHello(h1i.clientHello()));

        // A second, independent exchange with the same identities.
        const h2i = new HandshakeState(a, true);
        const h2r = new HandshakeState(b, false);
        h2i.consumeServerHello(h2r.serverHello(h2i.clientHello()));

        const authFromExchange1 = h1r.auth();
        check('an auth message from another exchange is refused',
            threw(() => h2i.verifyPeerAuth(authFromExchange1, () => true)));
    }

    // A tampered auth message.
    {
        const a = generateIdentity(), b = generateIdentity();
        const hi = new HandshakeState(a, true);
        const hr = new HandshakeState(b, false);
        hi.consumeServerHello(hr.serverHello(hi.clientHello()));

        const auth = hr.auth();
        const parsed = decodeAuth(auth);

        // Swap in a different static key, keeping signature and MAC.
        const impostor = generateIdentity();
        const forged = encodeAuth(impostor.publicKey, parsed.signature, parsed.mac);
        check('substituting the static key is refused',
            threw(() => hi.verifyPeerAuth(forged, () => true)));

        // Flip a bit in the signature.
        const badSig = flipBit(parsed.signature, 0);
        check('a corrupted signature is refused',
            threw(() => hi.verifyPeerAuth(encodeAuth(parsed.staticKey, badSig, parsed.mac), () => true)));

        // Flip a bit in the MAC.
        const badMac = flipBit(parsed.mac, 0);
        check('a corrupted identity MAC is refused',
            threw(() => hi.verifyPeerAuth(encodeAuth(parsed.staticKey, parsed.signature, badMac), () => true)));
    }

    // Reflection: a peer presenting our own identity.
    {
        const shared = generateIdentity();
        check('a peer using our own identity is refused',
            threw(() => runHandshake(shared, shared)));
    }

    // Protocol version.
    {
        const r = new HandshakeState(generateIdentity(), false);
        const bad = Buffer.alloc(4 + 32 + 32);
        bad.writeUInt32BE(PROTOCOL_VERSION + 1, 0);
        check('a version mismatch is refused', threw(() => r.serverHello(bad)));
    }

    // Degenerate DH: an all-zero ephemeral forces a known shared secret.
    {
        const r = new HandshakeState(generateIdentity(), false);
        const hello = Buffer.concat([
            (() => { const v = Buffer.alloc(4); v.writeUInt32BE(PROTOCOL_VERSION, 0); return v; })(),
            Buffer.alloc(32),          // low-order point
            randomBytes(32),
        ]);
        check('a degenerate x25519 key is refused', threw(() => r.serverHello(hello)));
    }

    // Malformed inputs.
    check('a truncated client hello is refused',
        threw(() => new HandshakeState(generateIdentity(), false).serverHello(Buffer.alloc(10))));
    check('session keys before verification are refused', threw(() => {
        const h = new HandshakeState(generateIdentity(), true);
        h.clientHello();
        return h.sessionKeys();
    }));
    check('a responder cannot send a client hello',
        threw(() => new HandshakeState(generateIdentity(), false).clientHello()));
}

/* ============================================================= session == */
console.log('\n-- secure channel --');
{
    const key = randomBytes(32);
    const send = new SendCipher(key);
    const recv = new ReceiveCipher(key);

    const plain = Buffer.from('PRIVMSG #private-p2p :hello');
    const sealed = send.seal(plain);
    check('a frame round-trips', recv.open(sealed).equals(plain));
    check('the ciphertext is not the plaintext', !sealed.includes(plain));

    const second = send.seal(Buffer.from('second'));
    check('a second frame round-trips', recv.open(second).toString() === 'second');

    // Replay: the sequence number is authenticated, so an old frame is refused.
    check('replaying a frame is refused', threw(() => recv.open(sealed)));

    // Reordering.
    {
        const s = new SendCipher(key);
        const r = new ReceiveCipher(key);
        const f1 = s.seal(Buffer.from('one'));
        const f2 = s.seal(Buffer.from('two'));
        check('a skipped frame is refused', threw(() => r.open(f2)));
        check('and the in-order frame still works', r.open(f1).toString() === 'one');
    }

    // Tampering anywhere in the frame.
    {
        const s = new SendCipher(key);
        const r = new ReceiveCipher(key);
        const f = s.seal(Buffer.from('integrity'));
        for (const [label, index] of [['sequence', 2], ['ciphertext', 10], ['tag', f.length - 1]] as const) {
            const bad = flipBit(f, index);
            check(`a flipped bit in the ${label} is refused`, threw(() => new ReceiveCipher(key).open(bad)));
        }
        check('the untampered frame still opens', r.open(f).toString() === 'integrity');
    }

    // A different key cannot read it.
    {
        const s = new SendCipher(randomBytes(32));
        check('a wrong key cannot open a frame',
            threw(() => new ReceiveCipher(randomBytes(32)).open(s.seal(Buffer.from('x')))));
    }

    check('an oversized plaintext is refused',
        threw(() => new SendCipher(key).seal(Buffer.alloc(MAX_PLAINTEXT_BYTES + 1))));
    check('a short frame is refused', threw(() => new ReceiveCipher(key).open(Buffer.alloc(4))));
    check('a wrong-size key is refused', threw(() => new SendCipher(Buffer.alloc(16))));

    // Nonces must never repeat: sequence numbers advance.
    {
        const s = new SendCipher(key);
        s.seal(Buffer.from('a')); s.seal(Buffer.from('b'));
        check('the send counter advances', s.sequence === 2n);
    }
}

/* ============================================================= framing == */
console.log('\n-- framing --');
{
    const reader = new FrameReader();
    const payload = Buffer.from('a complete message');
    check('a whole frame is read', reader.push(frame(payload))[0]!.equals(payload));

    // The case that breaks naive implementations: one message, many reads.
    {
        const r = new FrameReader();
        const f = frame(Buffer.from('split across reads'));
        const out: Buffer[] = [];
        for (const byte of f) out.push(...r.push(Buffer.from([byte])));
        check('a frame split byte-by-byte reassembles', out.length === 1);
        check('and its content is intact', out[0]!.toString() === 'split across reads');
    }

    // And the opposite: many messages in one read.
    {
        const r = new FrameReader();
        const glued = Buffer.concat([frame(Buffer.from('one')), frame(Buffer.from('two')), frame(Buffer.from('three'))]);
        const out = r.push(glued);
        check('three glued frames all arrive', out.length === 3);
        check('in order', out.map((f) => f.toString()).join(',') === 'one,two,three');
    }

    check('an incomplete frame yields nothing yet', new FrameReader().push(Buffer.from([0, 0, 0, 99])).length === 0);
    check('an empty frame is valid', new FrameReader().push(frame(Buffer.alloc(0)))[0]!.length === 0);

    // Memory bound: a hostile length prefix is refused before allocation.
    {
        const huge = Buffer.alloc(4);
        huge.writeUInt32BE(MAX_FRAME_BYTES + 1, 0);
        check('an oversized announced frame is refused', threw(() => new FrameReader().push(huge)));
    }
    check('sending an oversized frame is refused', threw(() => frame(Buffer.alloc(MAX_FRAME_BYTES + 1))));
}

/* ============================================================= irc grammar == */
console.log('\n-- IRC message grammar --');
{
    const m = parseMessage(':alice!u@h PRIVMSG #chan :hello world\r\n');
    check('a prefix parses', m?.prefix === 'alice!u@h');
    check('a command parses', m?.command === 'PRIVMSG');
    check('params parse', m?.params[0] === '#chan');
    check('trailing keeps its spaces', m?.params[1] === 'hello world');

    check('commands upper-case', parseMessage('privmsg #c :x')?.command === 'PRIVMSG');
    check('a command with no params parses', parseMessage('PING')?.command === 'PING');
    check('an empty line yields null', parseMessage('') === null);
    check('whitespace yields null', parseMessage('   ') === null);

    // IRCv3 tags.
    {
        const t = parseMessage('@time=2026-08-15T10:00:00Z;msgid=abc :n PRIVMSG #c :hi');
        check('tags parse', t?.tags['time'] === '2026-08-15T10:00:00Z');
        check('multiple tags parse', t?.tags['msgid'] === 'abc');
        check('a valueless tag is empty string', parseMessage('@bot :n PING')?.tags['bot'] === '');
        check('tag escapes decode', parseMessage('@k=a\\sb :n PING')?.tags['k'] === 'a b');
    }

    // Serialising.
    check('a line serialises',
        serialiseMessage({ command: 'PRIVMSG', params: ['#c', 'hello world'] }) === 'PRIVMSG #c :hello world\r\n');
    check('a prefix serialises',
        serialiseMessage({ prefix: 'server', command: 'PING', params: [] }) === ':server PING\r\n');
    check('tags serialise', serialiseMessage({ tags: { a: 'b' }, command: 'PING' }).startsWith('@a=b PING'));

    // Round trip.
    {
        const line = serialiseMessage({ prefix: 'alice', command: 'PRIVMSG', params: ['#chan', 'a b c'] });
        const back = parseMessage(line);
        check('a message round-trips', back?.params[1] === 'a b c' && back.prefix === 'alice');
    }

    /* THE injection case. A nickname carrying CRLF would become a second
       message attributed to the server. */
    check('CRLF in a parameter is refused',
        threw(() => serialiseMessage({ command: 'PRIVMSG', params: ['#c', 'x\r\nKICK #c victim'] })));
    check('a bare LF is refused', threw(() => serialiseMessage({ command: 'NICK', params: ['a\nb'] })));
    check('CR in a prefix is refused', threw(() => serialiseMessage({ prefix: 'a\rb', command: 'PING' })));
    check('NUL is refused', threw(() => serialiseMessage({ command: 'PING', params: ['a\0b'] })));
    check('a space in the command is refused', threw(() => serialiseMessage({ command: 'PING PONG' })));
    check('a spaced param before the last is refused',
        threw(() => serialiseMessage({ command: 'X', params: ['a b', 'c'] })));

    // Names.
    check('a channel name validates', isValidChannelName('#private-p2p'));
    check('& channels validate', isValidChannelName('&local'));
    check('a name without a prefix is invalid', !isValidChannelName('private'));
    check('a name with a space is invalid', !isValidChannelName('#a b'));
    check('a name with a comma is invalid', !isValidChannelName('#a,b'));
    check('a bare # is invalid', !isValidChannelName('#'));

    check('a nickname validates', isValidNickname('alice'));
    check('a nickname may hold special chars', isValidNickname('a[]\\`_^{|}'));
    check('a nickname may not start with a digit', !isValidNickname('1alice'));
    check('an empty nickname is invalid', !isValidNickname(''));
    check('a nickname with a space is invalid', !isValidNickname('a b'));
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
