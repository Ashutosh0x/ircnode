// ---------------------------------------------------------------------------
// link.ts — One authenticated, encrypted connection.
//
// Wraps a TCP socket in: handshake -> session -> framed IRC lines. Both the
// listener and the dialer use this, so there is exactly one implementation of
// "how a peer connection behaves" and the two directions cannot drift.
//
// ── The rule this enforces ──────────────────────────────────────────────────
//
// No application byte moves before `verifyPeerAuth` has succeeded. The socket
// is in handshake mode until then and IRC lines are literally unparseable —
// there is no code path that reads a command from an unauthenticated peer,
// because the reader is not looking for commands yet.
//
// That is stronger than checking a flag at the top of a command handler. A
// flag can be forgotten in one branch; a state machine that cannot decode the
// bytes cannot be bypassed by forgetting anything.
// ---------------------------------------------------------------------------

import { EventEmitter } from 'node:events';
import type { Socket } from 'node:net';

import { HandshakeState } from '../crypto/handshake.ts';
import { SecureSession } from '../crypto/session.ts';
import { FrameReader, frame } from '../protocol/framing.ts';
import { parseMessage, serialiseMessage, type IrcMessage } from '../protocol/message.ts';
import type { Identity } from '../crypto/identity.ts';

/** Abandon a handshake that stalls. A half-open socket costs memory. */
const HANDSHAKE_TIMEOUT_MS = 10_000;

/** Drop a peer that has gone silent. IRC PING keeps a live link warm. */
const IDLE_TIMEOUT_MS = 5 * 60 * 1000;

type Phase = 'handshake' | 'confirming' | 'established' | 'closed';

/**
 * Responder's "you are admitted" frame, sent after it has verified the
 * initiator's auth and applied the allowlist.
 *
 * Without it the initiator finishes as soon as it has SENT its own auth — but
 * at that instant the responder has not yet checked it, and may be about to
 * refuse. An unauthorised peer therefore saw a successful connection that was
 * torn down a moment later, and reported itself connected in between.
 *
 * Sealed with the session keys, so receiving it also proves the responder
 * derived the same keys rather than merely completing the signature exchange.
 */
const ACCEPT_MARKER = Buffer.from('ircnode/v1/accepted', 'utf8');

export interface SecureLinkEvents {
    ready: [SecureSession];
    message: [IrcMessage];
    close: [Error | null];
}

export class SecureLink extends EventEmitter<SecureLinkEvents> {
    readonly #socket: Socket;
    readonly #identity: Identity;
    readonly #isAuthorised: (publicKey: Buffer) => boolean;
    readonly #initiator: boolean;

    #handshake: HandshakeState;
    #session: SecureSession | null = null;
    #reader = new FrameReader();
    #phase: Phase = 'handshake';
    #timer: NodeJS.Timeout | null = null;
    /** Responder waits for msg1; initiator waits for msg2 then msg3. */
    #step = 0;

    constructor(opts: {
        socket: Socket;
        identity: Identity;
        isAuthorised: (publicKey: Buffer) => boolean;
        initiator: boolean;
    }) {
        super();
        this.#socket = opts.socket;
        this.#identity = opts.identity;
        this.#isAuthorised = opts.isAuthorised;
        this.#initiator = opts.initiator;
        this.#handshake = new HandshakeState(opts.identity, opts.initiator);

        this.#socket.on('data', (chunk: Buffer) => this.#onData(chunk));
        this.#socket.on('error', (err) => this.destroy(err));
        this.#socket.on('close', () => this.#finish(null));

        this.#arm(HANDSHAKE_TIMEOUT_MS, 'handshake timed out');

        if (this.#initiator) this.#sendFrame(this.#handshake.clientHello());
    }

    get session(): SecureSession | null {
        return this.#session;
    }

    get peerNodeId(): string | null {
        return this.#session?.peerNodeId ?? null;
    }

    get remoteAddress(): string {
        return `${this.#socket.remoteAddress ?? '?'}:${this.#socket.remotePort ?? 0}`;
    }

    /** Send one IRC message. Silently ignored before the link is established. */
    send(msg: { prefix?: string | null; command: string; params?: string[]; tags?: Record<string, string> }): void {
        if (this.#phase !== 'established' || !this.#session) return;
        const line = serialiseMessage(msg);
        this.#sendFrame(this.#session.send.seal(Buffer.from(line, 'utf8')));
    }

    destroy(err: Error | null = null): void {
        if (this.#phase === 'closed') return;
        this.#finish(err);
        this.#socket.destroy();
    }

    /* ============================================================= read == */

    #onData(chunk: Buffer): void {
        if (this.#phase === 'closed') return;

        let frames: Buffer[];
        try {
            frames = this.#reader.push(chunk);
        } catch (e) {
            /* A bad length prefix desynchronises the stream permanently —
               there is no way to find the next boundary, so the connection
               cannot continue. */
            return this.destroy(e as Error);
        }

        for (const f of frames) {
            /* Re-checked per frame: destroy() may have closed the link while
               handling the previous one. Read through a method so the
               narrowing from the check at the top of this function does not
               persist across the loop. */
            if (this.#isClosed()) return;
            try {
                if (this.#phase === 'handshake') this.#onHandshakeFrame(f);
                else if (this.#phase === 'confirming') this.#onConfirmFrame(f);
                else this.#onSessionFrame(f);
            } catch (e) {
                return this.destroy(e as Error);
            }
        }
    }

    #onHandshakeFrame(f: Buffer): void {
        if (this.#initiator) {
            if (this.#step === 0) {
                // msg 2: responder's ephemeral.
                this.#handshake.consumeServerHello(f);
                this.#step = 1;
            } else {
                /* msg 3: the responder proves who it is FIRST. If it is not a
                   node we authorised, we abort without ever sending our own
                   identity — an unauthorised listener learns nothing about
                   who tried to reach it. */
                this.#handshake.verifyPeerAuth(f, this.#isAuthorised);
                this.#sendFrame(this.#handshake.auth());        // msg 4

                /* Keys are ready, but we are NOT connected yet: the responder
                   has still to check us against its own allowlist. Wait for
                   its accept frame before telling anyone this worked. */
                this.#deriveSession();
                this.#phase = 'confirming';
                this.#step = 2;
            }
            return;
        }

        // Responder.
        if (this.#step === 0) {
            this.#sendFrame(this.#handshake.serverHello(f));   // msg 2
            this.#sendFrame(this.#handshake.auth());           // msg 3
            this.#step = 1;
        } else {
            this.#handshake.verifyPeerAuth(f, this.#isAuthorised);   // msg 4
            this.#deriveSession();

            // msg 5: admitted. Only reached once the allowlist has passed.
            const session = this.#session;
            if (!session) throw new Error('internal: session missing after verification');
            this.#sendFrame(session.send.seal(ACCEPT_MARKER));

            this.#ready();
        }
    }

    /** Initiator: the responder's accept frame, decrypted. */
    #onConfirmFrame(f: Buffer): void {
        const session = this.#session;
        if (!session) throw new Error('internal: confirming without a session');

        const plaintext = session.receive.open(f);
        if (!plaintext.equals(ACCEPT_MARKER)) {
            throw new Error('handshake failed: unexpected first frame from responder');
        }
        this.#ready();
    }

    /** Derive directional session keys. Does not mark the link usable. */
    #deriveSession(): void {
        const keys = this.#handshake.sessionKeys();

        /* Directional keys, assigned by role. Getting this backwards makes
           every frame fail to authenticate, which is the correct failure —
           but naming them by role rather than by "mine/theirs" is what keeps
           it obvious which is which. */
        this.#session = new SecureSession({
            sendKey: this.#initiator ? keys.initiatorToResponder : keys.responderToInitiator,
            receiveKey: this.#initiator ? keys.responderToInitiator : keys.initiatorToResponder,
            peerNodeId: keys.peerNodeId,
            peerPublicKey: keys.peerPublicKey,
            sessionId: keys.sessionId,
        });
    }

    /** Both sides have authorised each other. The link is now usable. */
    #ready(): void {
        const session = this.#session;
        if (!session) throw new Error('internal: ready without a session');
        this.#phase = 'established';
        this.#arm(IDLE_TIMEOUT_MS, 'peer idle');
        this.emit('ready', session);
    }

    #onSessionFrame(f: Buffer): void {
        const session = this.#session;
        if (!session) throw new Error('session frame before establishment');

        const plaintext = session.receive.open(f);
        this.#arm(IDLE_TIMEOUT_MS, 'peer idle');

        /* One frame may carry several CRLF-terminated lines. */
        for (const line of plaintext.toString('utf8').split('\r\n')) {
            if (!line.trim()) continue;
            const msg = parseMessage(line);
            if (msg) this.emit('message', msg);
        }
    }

    /* ============================================================= write == */

    #sendFrame(payload: Buffer): void {
        if (this.#socket.destroyed) return;
        this.#socket.write(frame(payload));
    }

    #isClosed(): boolean {
        return this.#phase === 'closed';
    }

    #arm(ms: number, reason: string): void {
        if (this.#timer) clearTimeout(this.#timer);
        this.#timer = setTimeout(() => this.destroy(new Error(reason)), ms);
        this.#timer.unref();
    }

    #finish(err: Error | null): void {
        if (this.#phase === 'closed') return;
        this.#phase = 'closed';
        if (this.#timer) { clearTimeout(this.#timer); this.#timer = null; }
        this.emit('close', err);
    }
}
