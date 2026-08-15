// ---------------------------------------------------------------------------
// handshake.ts — Mutual authentication with forward secrecy.
//
// SIGMA ("SIGn-and-MAc", Krawczyk 2003), the construction behind IKEv2 and the
// ancestor of Noise's authenticated patterns.
//
// ── Why not the obvious design ──────────────────────────────────────────────
//
// The tempting handshake, and the one usually proposed, is:
//
//     server -> client:  nonce
//     client -> server:  pubkey, Sign(nonce ‖ server_id ‖ timestamp)
//
// It looks sound. It is not, and the flaw has a name: identity misbinding, the
// weakness that sank Station-to-Station and that SIGMA was designed to fix.
//
// The signature covers a nonce, but nothing ties it to the key exchange that
// the session will actually use. So a party M who is themselves authorised can
// sit between A and B: M runs a key exchange with A, relays A's signature to
// B, and ends up sharing a key with A while B believes it is talking to A. The
// bytes A signed were true — A really did sign that nonce — they just never
// said WHICH session they belonged to.
//
// The fix is to sign the TRANSCRIPT, not a nonce: both ephemeral public keys,
// both static public keys, and both nonces, hashed together. Then a signature
// is valid for exactly one key exchange and cannot be carried into another.
// SIGMA adds a MAC over the signer's identity, keyed from the shared secret,
// which proves the signer actually holds the derived key rather than having
// merely replayed a signature into the flow.
//
// ── The exchange ────────────────────────────────────────────────────────────
//
//   1. I -> R   e_i, n_i, version                        (ephemeral, nonce)
//   2. R -> I   e_r, n_r                                 (ephemeral, nonce)
//                 both derive K = X25519(e, E) -> HKDF -> keys
//   3. R -> I   S_r, Sign_r(H(transcript)), MAC(km_r, S_r)     [encrypted]
//   4. I -> R   S_i, Sign_i(H(transcript)), MAC(km_i, S_i)     [encrypted]
//
// The responder authenticates first so an unauthorised initiator learns
// nothing about who is listening beyond the fact that something is; the
// initiator can abort before revealing its own identity if the responder is
// not the node it expected.
//
// Forward secrecy comes from the ephemeral X25519 keys: they are discarded
// when the connection ends, so a later compromise of a long-term Ed25519 key
// does not decrypt recorded traffic.
// ---------------------------------------------------------------------------

import {
    createHash,
    createHmac,
    diffieHellman,
    generateKeyPairSync,
    hkdfSync,
    randomBytes,
    timingSafeEqual,
    createPublicKey,
    type KeyObject,
} from 'node:crypto';

import {
    ED25519_PUBLIC_KEY_BYTES,
    nodeIdFromPublicKey,
    publicKeysEqual,
    sign,
    verify,
    type Identity,
} from './identity.ts';

/** Wire protocol version. A mismatch aborts before any key material is used. */
export const PROTOCOL_VERSION = 1;

/** Protocol label, mixed into the transcript so this handshake is unique. */
const PROTOCOL_LABEL = 'ircnode/v1/sigma/x25519-ed25519-chacha20poly1305';

export const NONCE_BYTES = 32;
export const X25519_PUBLIC_KEY_BYTES = 32;
const KEY_BYTES = 32;
const MAC_BYTES = 32;

/** An X25519 keypair, live only for the duration of one connection. */
interface Ephemeral {
    readonly publicKey: Buffer;
    readonly privateKey: KeyObject;
}

/** Keys derived from the handshake, one set per direction. */
export interface SessionKeys {
    /** Key for data sent by the initiator, read by the responder. */
    readonly initiatorToResponder: Buffer;
    /** Key for data sent by the responder, read by the initiator. */
    readonly responderToInitiator: Buffer;
    /** Identity of the peer that was actually authenticated. */
    readonly peerPublicKey: Buffer;
    readonly peerNodeId: string;
    /** Transcript hash, usable as a channel binding / session id. */
    readonly sessionId: Buffer;
}

/* ============================================================= ephemeral == */

function generateEphemeral(): Ephemeral {
    const { publicKey, privateKey } = generateKeyPairSync('x25519');
    const der = publicKey.export({ type: 'spki', format: 'der' });
    return {
        publicKey: Buffer.from(der.subarray(der.length - X25519_PUBLIC_KEY_BYTES)),
        privateKey,
    };
}

/** DER prefix for an X25519 SPKI public key. Fixed by RFC 8410. */
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

function x25519PublicFromRaw(raw: Buffer): KeyObject {
    if (raw.length !== X25519_PUBLIC_KEY_BYTES) {
        throw new Error(`x25519 public key must be ${X25519_PUBLIC_KEY_BYTES} bytes`);
    }
    return createPublicKey({
        key: Buffer.concat([X25519_SPKI_PREFIX, raw]),
        format: 'der',
        type: 'spki',
    });
}

/* ============================================================= transcript == */

/**
 * Hash of everything both sides have seen, in a fixed order.
 *
 * This is the value that gets signed, and it is what makes the signature
 * belong to one specific key exchange. Every field is length-prefixed so the
 * encoding is injective — without that, moving a byte from the end of one
 * field to the start of the next produces the same hash, and two different
 * handshakes could share a signature.
 */
function transcriptHash(parts: {
    version: number;
    initiatorEphemeral: Buffer;
    responderEphemeral: Buffer;
    initiatorNonce: Buffer;
    responderNonce: Buffer;
}): Buffer {
    const h = createHash('sha256');

    const field = (b: Buffer) => {
        const len = Buffer.alloc(4);
        len.writeUInt32BE(b.length, 0);
        h.update(len);
        h.update(b);
    };

    field(Buffer.from(PROTOCOL_LABEL, 'utf8'));

    const version = Buffer.alloc(4);
    version.writeUInt32BE(parts.version, 0);
    field(version);

    field(parts.initiatorEphemeral);
    field(parts.responderEphemeral);
    field(parts.initiatorNonce);
    field(parts.responderNonce);

    return h.digest();
}

/* ============================================================= derivation == */

/**
 * Turn the raw DH output into directional keys.
 *
 * HKDF with the transcript hash as salt, so the keys depend on every value
 * exchanged and not only on the DH secret. Separate keys per direction mean a
 * message cannot be reflected back at its sender and still authenticate, and
 * separate MAC keys keep the identity proof independent of the data keys.
 */
function deriveKeys(sharedSecret: Buffer, transcript: Buffer) {
    const derive = (label: string, length: number): Buffer =>
        Buffer.from(hkdfSync('sha256', sharedSecret, transcript, Buffer.from(label, 'utf8'), length));

    return {
        initiatorToResponder: derive('ircnode/v1/key/i2r', KEY_BYTES),
        responderToInitiator: derive('ircnode/v1/key/r2i', KEY_BYTES),
        macInitiator: derive('ircnode/v1/mac/initiator', MAC_BYTES),
        macResponder: derive('ircnode/v1/mac/responder', MAC_BYTES),
    };
}

function identityMac(macKey: Buffer, staticPublicKey: Buffer): Buffer {
    return createHmac('sha256', macKey).update(staticPublicKey).digest();
}

/* ============================================================= messages == */

/*  Wire encodings. Fixed-width fields throughout: every element has a known
    length, so parsing is a series of subarray reads with one total-length
    check and there is no attacker-controlled length to get wrong. */

/** msg 1: version(4) ‖ ephemeral(32) ‖ nonce(32) */
export function encodeClientHello(ephemeral: Buffer, nonce: Buffer): Buffer {
    const version = Buffer.alloc(4);
    version.writeUInt32BE(PROTOCOL_VERSION, 0);
    return Buffer.concat([version, ephemeral, nonce]);
}

export function decodeClientHello(buf: Buffer) {
    if (buf.length !== 4 + X25519_PUBLIC_KEY_BYTES + NONCE_BYTES) {
        throw new Error('malformed client hello');
    }
    return {
        version: buf.readUInt32BE(0),
        ephemeral: buf.subarray(4, 4 + X25519_PUBLIC_KEY_BYTES),
        nonce: buf.subarray(4 + X25519_PUBLIC_KEY_BYTES),
    };
}

/** msg 2: ephemeral(32) ‖ nonce(32) */
export function encodeServerHello(ephemeral: Buffer, nonce: Buffer): Buffer {
    return Buffer.concat([ephemeral, nonce]);
}

export function decodeServerHello(buf: Buffer) {
    if (buf.length !== X25519_PUBLIC_KEY_BYTES + NONCE_BYTES) {
        throw new Error('malformed server hello');
    }
    return {
        ephemeral: buf.subarray(0, X25519_PUBLIC_KEY_BYTES),
        nonce: buf.subarray(X25519_PUBLIC_KEY_BYTES),
    };
}

/** msg 3/4: staticKey(32) ‖ signature(64) ‖ mac(32) */
const AUTH_BYTES = ED25519_PUBLIC_KEY_BYTES + 64 + MAC_BYTES;

export function encodeAuth(staticKey: Buffer, signature: Buffer, mac: Buffer): Buffer {
    if (signature.length !== 64) throw new Error('ed25519 signature must be 64 bytes');
    return Buffer.concat([staticKey, signature, mac]);
}

export function decodeAuth(buf: Buffer) {
    if (buf.length !== AUTH_BYTES) throw new Error('malformed auth message');
    return {
        staticKey: buf.subarray(0, ED25519_PUBLIC_KEY_BYTES),
        signature: buf.subarray(ED25519_PUBLIC_KEY_BYTES, ED25519_PUBLIC_KEY_BYTES + 64),
        mac: buf.subarray(ED25519_PUBLIC_KEY_BYTES + 64),
    };
}

/* ============================================================= state == */

/**
 * Handshake driver.
 *
 * Deliberately a state machine over discrete messages rather than something
 * that owns a socket: it can then be tested end to end in memory, with no
 * network and no timing, and the transport can be anything that moves frames.
 */
export class HandshakeState {
    readonly #identity: Identity;
    readonly #isInitiator: boolean;
    readonly #ephemeral: Ephemeral;
    readonly #nonce: Buffer;

    #transcript: Buffer | null = null;
    #keys: ReturnType<typeof deriveKeys> | null = null;
    #peerStatic: Buffer | null = null;
    #done = false;

    constructor(identity: Identity, isInitiator: boolean) {
        this.#identity = identity;
        this.#isInitiator = isInitiator;
        this.#ephemeral = generateEphemeral();
        this.#nonce = randomBytes(NONCE_BYTES);
    }

    /** msg 1, initiator only. */
    clientHello(): Buffer {
        if (!this.#isInitiator) throw new Error('only the initiator sends a client hello');
        return encodeClientHello(this.#ephemeral.publicKey, this.#nonce);
    }

    /** msg 2, responder only. Consumes msg 1 and fixes the transcript. */
    serverHello(clientHelloBuf: Buffer): Buffer {
        if (this.#isInitiator) throw new Error('only the responder sends a server hello');
        const hello = decodeClientHello(clientHelloBuf);

        /* Version first, before the DH. A peer speaking a different protocol
           has nothing useful to say and should be told so cheaply. */
        if (hello.version !== PROTOCOL_VERSION) {
            throw new Error(`unsupported protocol version ${hello.version}, expected ${PROTOCOL_VERSION}`);
        }

        this.#establish(hello.ephemeral, hello.nonce, Buffer.from(hello.ephemeral));
        return encodeServerHello(this.#ephemeral.publicKey, this.#nonce);
    }

    /** Initiator consumes msg 2 and fixes the same transcript. */
    consumeServerHello(serverHelloBuf: Buffer): void {
        if (!this.#isInitiator) throw new Error('only the initiator consumes a server hello');
        const hello = decodeServerHello(serverHelloBuf);
        this.#establish(hello.ephemeral, hello.nonce, Buffer.from(hello.ephemeral));
    }

    #establish(peerEphemeral: Buffer, peerNonce: Buffer, _raw: Buffer): void {
        const shared = diffieHellman({
            privateKey: this.#ephemeral.privateKey,
            publicKey: x25519PublicFromRaw(peerEphemeral),
        });

        /* An all-zero shared secret means the peer sent a low-order point and
           forced the result, which would let it dictate the session keys.
           X25519 is defined to produce zero in exactly that case, so the check
           is a direct test for the attack. */
        if (shared.every((b) => b === 0)) {
            throw new Error('peer supplied a degenerate x25519 public key');
        }

        this.#transcript = transcriptHash({
            version: PROTOCOL_VERSION,
            initiatorEphemeral: this.#isInitiator ? this.#ephemeral.publicKey : peerEphemeral,
            responderEphemeral: this.#isInitiator ? peerEphemeral : this.#ephemeral.publicKey,
            initiatorNonce: this.#isInitiator ? this.#nonce : peerNonce,
            responderNonce: this.#isInitiator ? peerNonce : this.#nonce,
        });

        this.#keys = deriveKeys(shared, this.#transcript);
    }

    /**
     * msg 3/4: prove who we are, bound to this exchange.
     *
     * The signature is over the transcript hash — every ephemeral key and
     * nonce in this handshake — so it authenticates this session and only
     * this one. The MAC proves we hold the derived key rather than having
     * replayed someone else's signature into the flow.
     */
    auth(): Buffer {
        const { transcript, keys } = this.#requireEstablished();
        const signature = sign(this.#identity.privateKey, transcript);
        const macKey = this.#isInitiator ? keys.macInitiator : keys.macResponder;
        return encodeAuth(this.#identity.publicKey, signature, identityMac(macKey, this.#identity.publicKey));
    }

    /**
     * Verify the peer's auth message.
     *
     * `isAuthorised` is applied here rather than by the caller afterwards so
     * an unauthorised peer cannot be accepted by forgetting to check — the
     * handshake simply does not complete.
     */
    verifyPeerAuth(authBuf: Buffer, isAuthorised: (publicKey: Buffer) => boolean): void {
        const { transcript, keys } = this.#requireEstablished();
        const auth = decodeAuth(authBuf);

        // The peer's role is the opposite of ours.
        const macKey = this.#isInitiator ? keys.macResponder : keys.macInitiator;

        const expectedMac = identityMac(macKey, auth.staticKey);
        if (auth.mac.length !== expectedMac.length || !timingSafeEqual(auth.mac, expectedMac)) {
            throw new Error('handshake failed: identity MAC mismatch');
        }

        if (!verify(auth.staticKey, transcript, auth.signature)) {
            throw new Error('handshake failed: signature does not cover this exchange');
        }

        /* A peer proving it holds a key is not the same as being allowed in.
           Authentication answers "who", authorisation answers "may they" —
           conflating the two is how a correctly-signed stranger gets a
           session. */
        if (!isAuthorised(Buffer.from(auth.staticKey))) {
            throw new Error(`handshake refused: ${nodeIdFromPublicKey(auth.staticKey)} is not an authorised peer`);
        }

        /* Reject a peer presenting our own key. It is either a reflection
           attack or a misconfiguration where two nodes share an identity, and
           both are worth stopping loudly. */
        if (publicKeysEqual(auth.staticKey, this.#identity.publicKey)) {
            throw new Error('handshake refused: peer presented this node\'s own identity');
        }

        this.#peerStatic = Buffer.from(auth.staticKey);
        this.#done = true;
    }

    /** Keys for the established session. Throws unless the peer was verified. */
    sessionKeys(): SessionKeys {
        const { transcript, keys } = this.#requireEstablished();
        if (!this.#done || !this.#peerStatic) {
            throw new Error('handshake is not complete: peer has not been verified');
        }
        return {
            initiatorToResponder: keys.initiatorToResponder,
            responderToInitiator: keys.responderToInitiator,
            peerPublicKey: this.#peerStatic,
            peerNodeId: nodeIdFromPublicKey(this.#peerStatic),
            sessionId: transcript,
        };
    }

    get isInitiator(): boolean {
        return this.#isInitiator;
    }

    #requireEstablished() {
        if (!this.#transcript || !this.#keys) {
            throw new Error('handshake has not reached key agreement yet');
        }
        return { transcript: this.#transcript, keys: this.#keys };
    }
}
