// ---------------------------------------------------------------------------
// identity.ts — Who a node is.
//
// A node's identity is an Ed25519 keypair. Its NODE ID is a hash of the public
// key, not the key itself, so an ID is short enough to read aloud and compare
// by eye while still being bound one-to-one to the key.
//
// This replaces what early Bitcoin did. Bitcoin 0.1–0.6 announced peers by
// base58-encoding the node's IPv4 address into its IRC nickname, so the
// "identity" WAS the address: it changed whenever the address changed, it was
// readable by anyone in the channel, and anyone could claim any of it by
// simply setting a nickname. Nothing was proven. Here the nickname is a
// commitment to a public key, and holding the matching private key is the only
// way to use it.
//
// Everything is Node's built-in crypto. No third-party dependency handles a
// private key in this project.
// ---------------------------------------------------------------------------

import {
    createHash,
    createPrivateKey,
    createPublicKey,
    generateKeyPairSync,
    sign as edSign,
    timingSafeEqual,
    verify as edVerify,
    type KeyObject,
} from 'node:crypto';

/**
 * Domain separation tag.
 *
 * Every signature this project produces covers a label saying what it is for.
 * Without one, a signature obtained in a handshake could be replayed into some
 * other context that also signs raw bytes — the signer only ever promised
 * "I signed these bytes", not "I signed these bytes AS a handshake". The label
 * makes the promise specific.
 */
export const SIG_DOMAIN = 'ircnode/v1/signature';

/** Length of a raw Ed25519 public key, in bytes. */
export const ED25519_PUBLIC_KEY_BYTES = 32;

/** Node IDs are the first 16 bytes of SHA-256 over the raw public key. */
export const NODE_ID_BYTES = 16;

export interface Identity {
    /** Short, human-comparable hex id derived from the public key. */
    readonly nodeId: string;
    /** Raw 32-byte Ed25519 public key. */
    readonly publicKey: Buffer;
    /** Node's own signing key. Never leaves this process. */
    readonly privateKey: KeyObject;
}

export interface PublicIdentity {
    readonly nodeId: string;
    readonly publicKey: Buffer;
}

/* ============================================================= raw keys == */

/**
 * Raw 32-byte public key out of a KeyObject.
 *
 * Node exports Ed25519 keys as DER/SPKI, which wraps the 32 key bytes in an
 * ASN.1 header. The wire format here is the raw key, so the header is removed
 * — and the length is checked rather than assumed, because silently accepting
 * a short key would mean comparing truncated identities later.
 */
export function rawPublicKey(key: KeyObject): Buffer {
    const der = key.export({ type: 'spki', format: 'der' });
    const raw = der.subarray(der.length - ED25519_PUBLIC_KEY_BYTES);
    if (raw.length !== ED25519_PUBLIC_KEY_BYTES) {
        throw new Error(`expected a ${ED25519_PUBLIC_KEY_BYTES}-byte Ed25519 key, got ${raw.length}`);
    }
    return Buffer.from(raw);
}

/** DER prefix for an Ed25519 SPKI public key. Fixed by RFC 8410. */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * Rebuild a KeyObject from a raw 32-byte public key.
 *
 * Verification needs a KeyObject, but peers are stored and transmitted as raw
 * bytes. Wrapping in the fixed SPKI prefix is the documented way back.
 */
export function publicKeyFromRaw(raw: Buffer): KeyObject {
    if (raw.length !== ED25519_PUBLIC_KEY_BYTES) {
        throw new Error(`public key must be ${ED25519_PUBLIC_KEY_BYTES} bytes, got ${raw.length}`);
    }
    return createPublicKey({
        key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
        format: 'der',
        type: 'spki',
    });
}

/* ============================================================= node id == */

/**
 * Node ID for a public key: hex of the first 16 bytes of SHA-256.
 *
 * Truncated deliberately. A full 64-character hex string is unreadable and
 * nobody compares it by eye, which defeats the point of showing it at all.
 * 128 bits is far beyond what a collision search could reach, and the ID is
 * never the thing being verified — the signature is. The ID is a label.
 */
export function nodeIdFromPublicKey(publicKey: Buffer): string {
    return createHash('sha256')
        .update(publicKey)
        .digest()
        .subarray(0, NODE_ID_BYTES)
        .toString('hex');
}

/* ============================================================= generate == */

/** Create a brand-new node identity. */
export function generateIdentity(): Identity {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const raw = rawPublicKey(publicKey);
    return { nodeId: nodeIdFromPublicKey(raw), publicKey: raw, privateKey };
}

/** Rebuild an identity from a stored PKCS#8 private key. */
export function identityFromPrivateKeyPem(pem: string): Identity {
    const privateKey = createPrivateKey(pem);
    if (privateKey.asymmetricKeyType !== 'ed25519') {
        throw new Error(`expected an ed25519 private key, got ${privateKey.asymmetricKeyType}`);
    }
    const raw = rawPublicKey(createPublicKey(privateKey));
    return { nodeId: nodeIdFromPublicKey(raw), publicKey: raw, privateKey };
}

/** Export a private key as PKCS#8 PEM, for writing to disk. */
export function privateKeyToPem(privateKey: KeyObject): string {
    return privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
}

/* ============================================================= sign == */

/**
 * Sign a message under this project's domain tag.
 *
 * The tag and the message are length-prefixed rather than concatenated. Plain
 * concatenation is ambiguous: sign("ab","c") and sign("a","bc") produce the
 * same bytes, so a signature over one pair silently authenticates the other.
 * Prefixing each field with its length makes the encoding injective.
 */
export function sign(privateKey: KeyObject, message: Buffer): Buffer {
    return edSign(null, domainSeparate(message), privateKey);
}

/**
 * Verify a signature made by `sign`.
 *
 * Returns false rather than throwing on malformed input: a bad signature from
 * an unauthenticated peer is an expected event on a public port, not an
 * exceptional one, and every caller has to handle it either way.
 */
export function verify(publicKey: Buffer | KeyObject, message: Buffer, signature: Buffer): boolean {
    try {
        const key = Buffer.isBuffer(publicKey) ? publicKeyFromRaw(publicKey) : publicKey;
        return edVerify(null, domainSeparate(message), key, signature);
    } catch {
        return false;
    }
}

function domainSeparate(message: Buffer): Buffer {
    const label = Buffer.from(SIG_DOMAIN, 'utf8');
    const header = Buffer.alloc(8);
    header.writeUInt32BE(label.length, 0);
    header.writeUInt32BE(message.length, 4);
    return Buffer.concat([header, label, message]);
}

/* ============================================================= compare == */

/**
 * Constant-time public key comparison.
 *
 * `Buffer.equals` returns as soon as it finds a differing byte, so how long it
 * takes leaks how many leading bytes matched. Against an attacker who can
 * submit keys and measure, that turns "guess 32 bytes" into "guess one byte,
 * 32 times". The lengths are checked first because timingSafeEqual throws on a
 * mismatch, and that throw is itself an instant signal.
 */
export function publicKeysEqual(a: Buffer, b: Buffer): boolean {
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
}

/** Hex form of a public key, for config files and display. */
export function publicKeyToHex(publicKey: Buffer): string {
    return publicKey.toString('hex');
}

/** Parse a hex public key, rejecting anything not exactly 32 bytes. */
export function publicKeyFromHex(hex: string): Buffer {
    const clean = String(hex ?? '').trim().toLowerCase();
    if (!/^[0-9a-f]+$/.test(clean)) throw new Error('public key must be hex');
    const buf = Buffer.from(clean, 'hex');
    if (buf.length !== ED25519_PUBLIC_KEY_BYTES) {
        throw new Error(`public key must be ${ED25519_PUBLIC_KEY_BYTES} bytes, got ${buf.length}`);
    }
    return buf;
}
