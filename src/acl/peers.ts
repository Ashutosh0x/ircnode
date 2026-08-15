// ---------------------------------------------------------------------------
// peers.ts — Who is allowed in, and where the node's own key lives.
//
// The access model is a closed allowlist. There is no "unknown peers may
// connect read-only" tier and no first-use trust: a public key is either
// present in the list or the handshake fails. That is the whole point of the
// design, and every softening of it reintroduces the problem it exists to
// solve.
//
// Compare early Bitcoin, which had no such notion. Any host could join
// #bitcoin00 and announce any address, which is why the channel was trivially
// floodable with fake peers and why operators could see and block the whole
// swarm. Membership there was "showed up"; here it is "holds a key I added".
// ---------------------------------------------------------------------------

import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import {
    generateIdentity,
    identityFromPrivateKeyPem,
    nodeIdFromPublicKey,
    privateKeyToPem,
    publicKeyFromHex,
    publicKeysEqual,
    publicKeyToHex,
    type Identity,
} from '../crypto/identity.ts';

export interface PeerRecord {
    /** Ed25519 public key, hex. The only field that grants access. */
    publicKey: string;
    /** Human label. Advisory only — never used for authorisation. */
    name: string;
    /** Derived from the key; stored so the file is readable at a glance. */
    nodeId: string;
    addedAt: string;
    /** Last known dial address, for convenience. Not a credential. */
    address?: string;
}

export interface PeerFile {
    version: 1;
    peers: PeerRecord[];
}

const KEY_FILENAME = 'node-key.pem';
const PEERS_FILENAME = 'allowed-peers.json';

/* ============================================================= identity == */

/**
 * Load this node's identity, creating one on first run.
 *
 * The key file is written 0600. On Windows the mode is largely advisory, which
 * is stated plainly at the call site rather than papered over — a user who
 * believes the file is protected when it is not is worse off than one who
 * knows it is not.
 */
export function loadOrCreateIdentity(configDir: string): { identity: Identity; created: boolean } {
    const keyPath = join(configDir, KEY_FILENAME);

    if (existsSync(keyPath)) {
        const pem = readFileSync(keyPath, 'utf8');
        return { identity: identityFromPrivateKeyPem(pem), created: false };
    }

    const identity = generateIdentity();
    mkdirSync(dirname(keyPath), { recursive: true });

    /* Written with mode 0600 from the start rather than chmod'ed afterwards.
       Creating world-readable and then tightening leaves a window in which the
       private key is readable by anything on the machine. */
    writeFileSync(keyPath, privateKeyToPem(identity.privateKey), { mode: 0o600 });
    try {
        chmodSync(keyPath, 0o600);
    } catch {
        /* Best effort: some filesystems do not implement it. */
    }

    return { identity, created: true };
}

export function identityKeyPath(configDir: string): string {
    return join(configDir, KEY_FILENAME);
}

/* ============================================================= peers == */

export class PeerList {
    readonly #path: string;
    #peers: PeerRecord[] = [];

    constructor(configDir: string) {
        this.#path = join(configDir, PEERS_FILENAME);
        this.reload();
    }

    get path(): string {
        return this.#path;
    }

    /**
     * Re-read the allowlist from disk.
     *
     * A malformed file throws rather than defaulting to an empty list. An
     * empty list means "admit nobody", which would look like a working node
     * that silently refuses every peer — the operator would debug the network
     * for an hour before suspecting a stray comma.
     */
    reload(): void {
        if (!existsSync(this.#path)) {
            this.#peers = [];
            return;
        }

        let parsed: unknown;
        try {
            parsed = JSON.parse(readFileSync(this.#path, 'utf8'));
        } catch (e) {
            throw new Error(`${this.#path} is not valid JSON: ${(e as Error).message}`);
        }

        const file = parsed as Partial<PeerFile>;
        if (!file || !Array.isArray(file.peers)) {
            throw new Error(`${this.#path} is missing a "peers" array`);
        }

        /* Every key is parsed and length-checked at load. A truncated or
           mistyped key that only failed later would fail at handshake time,
           where it reads as "that peer cannot connect" rather than "your
           config is wrong". */
        this.#peers = file.peers.map((p, i) => {
            try {
                publicKeyFromHex(p.publicKey);
            } catch (e) {
                throw new Error(`peer #${i + 1} (${p.name ?? 'unnamed'}) has an invalid public key: ${(e as Error).message}`);
            }
            return {
                publicKey: p.publicKey.trim().toLowerCase(),
                name: p.name || 'unnamed',
                nodeId: p.nodeId || nodeIdFromPublicKey(publicKeyFromHex(p.publicKey)),
                addedAt: p.addedAt || new Date().toISOString(),
                ...(p.address ? { address: p.address } : {}),
            };
        });
    }

    /**
     * Is this key authorised?
     *
     * Compared in constant time against every entry, and every entry is
     * checked even after a match. Returning early would make the answer
     * arrive sooner for a key near the top of the file, which leaks position
     * to anyone who can time connection attempts.
     */
    isAuthorised(publicKey: Buffer): boolean {
        let found = false;
        for (const peer of this.#peers) {
            if (publicKeysEqual(publicKey, publicKeyFromHex(peer.publicKey))) found = true;
        }
        return found;
    }

    find(publicKey: Buffer): PeerRecord | null {
        for (const peer of this.#peers) {
            if (publicKeysEqual(publicKey, publicKeyFromHex(peer.publicKey))) return peer;
        }
        return null;
    }

    /** Display name for a key, falling back to its node id. */
    nameFor(publicKey: Buffer): string {
        return this.find(publicKey)?.name ?? nodeIdFromPublicKey(publicKey).slice(0, 8);
    }

    list(): readonly PeerRecord[] {
        return this.#peers;
    }

    get size(): number {
        return this.#peers.length;
    }

    /** Authorise a peer. Returns false if the key was already present. */
    add(publicKeyHex: string, name: string, address?: string): boolean {
        const key = publicKeyFromHex(publicKeyHex);
        if (this.isAuthorised(key)) return false;

        this.#peers.push({
            publicKey: publicKeyToHex(key),
            name: name || 'unnamed',
            nodeId: nodeIdFromPublicKey(key),
            addedAt: new Date().toISOString(),
            ...(address ? { address } : {}),
        });
        this.#save();
        return true;
    }

    /**
     * Revoke a peer. Returns false if it was not listed.
     *
     * Revocation takes effect on the next handshake. An already-open session
     * is not torn down here — the server owns live connections and drops them
     * separately, because a peer list has no way to reach a socket.
     */
    remove(publicKeyHexOrNodeId: string): boolean {
        const needle = publicKeyHexOrNodeId.trim().toLowerCase();
        const before = this.#peers.length;
        this.#peers = this.#peers.filter(
            (p) => p.publicKey !== needle && p.nodeId !== needle,
        );
        if (this.#peers.length === before) return false;
        this.#save();
        return true;
    }

    /**
     * Write the list atomically.
     *
     * Temp file then rename: rename is atomic within a filesystem, so a crash
     * mid-write leaves the previous good list intact. Writing in place risks a
     * truncated file, and a truncated allowlist fails closed — every peer
     * locked out at once, at whatever moment the power went.
     */
    #save(): void {
        mkdirSync(dirname(this.#path), { recursive: true });
        const file: PeerFile = { version: 1, peers: this.#peers };
        const tmp = `${this.#path}.tmp`;
        writeFileSync(tmp, JSON.stringify(file, null, 2) + '\n', { mode: 0o600 });
        renameSync(tmp, this.#path);
    }
}
