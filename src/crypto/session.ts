// ---------------------------------------------------------------------------
// session.ts — The encrypted channel, once the handshake has agreed keys.
//
// ChaCha20-Poly1305 in one direction per key, with a counter nonce.
//
// ── Nonce reuse is the failure that matters ─────────────────────────────────
//
// Encrypting two different messages under the same key and nonce with any
// stream cipher hands the attacker the XOR of the plaintexts, and for
// Poly1305 it leaks enough to forge authentication tags. It is not a
// degradation, it is total.
//
// Random nonces would seem safer and are not: at 96 bits, birthday collisions
// become a real risk over a long-lived connection, and nothing detects one.
// A counter cannot repeat by construction as long as it never wraps — so it is
// checked against its maximum before every use, and the connection is retired
// rather than allowed to roll over.
//
// Each direction gets its own key, so the two counters are independent and a
// message can never be reflected back at its sender and still authenticate.
//
// ── What the AAD is for ─────────────────────────────────────────────────────
//
// The sequence number is authenticated but not encrypted, and the receiver
// requires it to be exactly the next one expected. That makes deletion,
// reordering and replay of whole frames detectable — an attacker who drops
// frame 5 cannot pass off frame 6 as frame 5, because the tag covers the
// number.
// ---------------------------------------------------------------------------

import { createCipheriv, createDecipheriv } from 'node:crypto';

const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

/**
 * Largest plaintext accepted in one frame.
 *
 * A length prefix arrives from the network before it can be authenticated, so
 * the receiver must be willing to allocate whatever it says. Bounding it means
 * a peer cannot announce a 4GB frame and exhaust memory before a single byte
 * has been verified. 64 KiB is far above any IRC line.
 */
export const MAX_PLAINTEXT_BYTES = 64 * 1024;

/**
 * Retire the session before the counter can wrap.
 *
 * Well below 2^64; reaching it would take longer than any connection should
 * live. The point is that the wrap case is unreachable rather than handled.
 */
const MAX_SEQUENCE = 2n ** 62n;

/** Encrypts outbound frames for one direction. */
export class SendCipher {
    readonly #key: Buffer;
    #sequence = 0n;

    constructor(key: Buffer) {
        if (key.length !== KEY_BYTES) throw new Error(`session key must be ${KEY_BYTES} bytes`);
        this.#key = key;
    }

    /** @returns sequence(8) ‖ ciphertext ‖ tag(16) */
    seal(plaintext: Buffer): Buffer {
        if (plaintext.length > MAX_PLAINTEXT_BYTES) {
            throw new Error(`frame of ${plaintext.length} bytes exceeds the ${MAX_PLAINTEXT_BYTES} limit`);
        }
        if (this.#sequence >= MAX_SEQUENCE) {
            throw new Error('session sequence exhausted; reconnect to establish fresh keys');
        }

        const seq = this.#sequence++;
        const header = sequenceBytes(seq);

        /* 16 is the only tag length ChaCha20-Poly1305 defines, and Node
           produces it by default. `plaintextLength` is required by the CCM
           typings that @types/node maps this cipher onto; it is accurate here
           and the runtime does not need it. */
        const cipher = createCipheriv('chacha20-poly1305', this.#key, nonceFor(seq));
        cipher.setAAD(header, { plaintextLength: plaintext.length });

        const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
        return Buffer.concat([header, ciphertext, cipher.getAuthTag()]);
    }

    get sequence(): bigint {
        return this.#sequence;
    }
}

/** Decrypts inbound frames for one direction. */
export class ReceiveCipher {
    readonly #key: Buffer;
    #expected = 0n;

    constructor(key: Buffer) {
        if (key.length !== KEY_BYTES) throw new Error(`session key must be ${KEY_BYTES} bytes`);
        this.#key = key;
    }

    /**
     * Verify and decrypt one frame.
     *
     * Throws on anything wrong. There is no partial success and no "probably
     * fine": a frame that fails authentication is attacker-controlled, and the
     * only safe response is to stop using the connection.
     */
    open(frame: Buffer): Buffer {
        if (frame.length < 8 + TAG_BYTES) throw new Error('frame is too short to be valid');

        const header = frame.subarray(0, 8);
        const sequence = header.readBigUInt64BE(0);

        /* Strictly the next one. Accepting anything else would permit replay
           of an old frame or silent loss of an intervening one — both of which
           change the meaning of a conversation without breaking any tag. */
        if (sequence !== this.#expected) {
            throw new Error(`frame out of order: expected sequence ${this.#expected}, got ${sequence}`);
        }

        const ciphertext = frame.subarray(8, frame.length - TAG_BYTES);
        const tag = frame.subarray(frame.length - TAG_BYTES);

        if (ciphertext.length > MAX_PLAINTEXT_BYTES) {
            throw new Error(`frame of ${ciphertext.length} bytes exceeds the ${MAX_PLAINTEXT_BYTES} limit`);
        }

        const decipher = createDecipheriv('chacha20-poly1305', this.#key, nonceFor(sequence));
        decipher.setAAD(header, { plaintextLength: ciphertext.length });
        decipher.setAuthTag(tag);

        let plaintext: Buffer;
        try {
            plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        } catch {
            /* Deliberately uninformative. Distinguishing "bad tag" from "bad
               padding" or similar is how padding-oracle attacks start; the
               peer learns only that the frame was rejected. */
            throw new Error('frame failed authentication');
        }

        this.#expected++;
        return plaintext;
    }

    get expectedSequence(): bigint {
        return this.#expected;
    }
}

/** A bidirectional channel: the pair of ciphers for one connection. */
export class SecureSession {
    readonly send: SendCipher;
    readonly receive: ReceiveCipher;
    readonly peerNodeId: string;
    readonly peerPublicKey: Buffer;
    readonly sessionId: Buffer;

    constructor(opts: {
        sendKey: Buffer;
        receiveKey: Buffer;
        peerNodeId: string;
        peerPublicKey: Buffer;
        sessionId: Buffer;
    }) {
        this.send = new SendCipher(opts.sendKey);
        this.receive = new ReceiveCipher(opts.receiveKey);
        this.peerNodeId = opts.peerNodeId;
        this.peerPublicKey = opts.peerPublicKey;
        this.sessionId = opts.sessionId;
    }
}

/* ============================================================= helpers == */

function sequenceBytes(sequence: bigint): Buffer {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(sequence, 0);
    return b;
}

/**
 * 96-bit nonce: four zero bytes then the 64-bit counter.
 *
 * The keys are already unique per direction per connection, so the counter
 * alone is enough to make (key, nonce) unique. The leading zeros are the
 * conventional layout and leave room for a future rekey epoch.
 */
function nonceFor(sequence: bigint): Buffer {
    const nonce = Buffer.alloc(NONCE_BYTES);
    nonce.writeBigUInt64BE(sequence, 4);
    return nonce;
}
