// ---------------------------------------------------------------------------
// node.ts — The node: a listener, outbound peer links, and channel state.
//
// Every peer connection is symmetric once established. A node both listens and
// dials, and a link established either way carries the same IRC traffic — so
// there is no "server" whose loss ends the conversation, which was the single
// point of failure that killed Bitcoin's IRC bootstrap when LFnet went down.
//
// ── Binding ─────────────────────────────────────────────────────────────────
//
// The listener binds 127.0.0.1 unless told otherwise. A zero-trust handshake
// makes a wider bind survivable, but "survivable" and "intended" are different
// things: a default that exposes a port to the local network is a default that
// will surprise somebody. Widening it is a deliberate flag.
// ---------------------------------------------------------------------------

import { EventEmitter } from 'node:events';
import { createServer, connect, type Server, type Socket } from 'node:net';

import type { Identity } from '../crypto/identity.ts';
import { nodeIdFromPublicKey } from '../crypto/identity.ts';
import type { PeerList } from '../acl/peers.ts';
import { SecureLink } from './link.ts';
import { isValidChannelName, type IrcMessage } from '../protocol/message.ts';

export const DEFAULT_PORT = 6697;
export const DEFAULT_HOST = '127.0.0.1';

/** Bound so a peer cannot exhaust memory by joining channels forever. */
const MAX_CHANNELS_PER_PEER = 64;

export interface ConnectedPeer {
    readonly link: SecureLink;
    readonly nodeId: string;
    readonly publicKey: Buffer;
    readonly name: string;
    readonly address: string;
    readonly since: number;
    readonly inbound: boolean;
    readonly channels: Set<string>;
}

export interface ChatLine {
    at: number;
    kind: 'system' | 'chat' | 'auth' | 'error';
    channel: string | null;
    from: string;
    text: string;
}

export interface NodeEvents {
    line: [ChatLine];
    peers: [readonly ConnectedPeer[]];
    listening: [{ host: string; port: number }];
}

export class IrcNode extends EventEmitter<NodeEvents> {
    readonly identity: Identity;
    readonly peers: PeerList;
    readonly nickname: string;

    #server: Server | null = null;
    /* Every socket this node owns, accepted or dialled.
       net.Server has no closeAllConnections() — that is http.Server — and
       server.close() waits for every live connection before its callback
       fires. A socket that connected and never finished a handshake is not in
       #links, so without this set it is never destroyed and close() hangs. */
    #sockets = new Set<Socket>();
    #links = new Map<SecureLink, ConnectedPeer>();
    #channels = new Set<string>(['#private-p2p']);
    #host = DEFAULT_HOST;
    #port = DEFAULT_PORT;

    constructor(opts: { identity: Identity; peers: PeerList; nickname?: string }) {
        super();
        this.identity = opts.identity;
        this.peers = opts.peers;
        this.nickname = opts.nickname || `node-${opts.identity.nodeId.slice(0, 8)}`;
    }

    get host(): string { return this.#host; }
    get port(): number { return this.#port; }
    get channels(): readonly string[] { return [...this.#channels]; }
    get connected(): readonly ConnectedPeer[] { return [...this.#links.values()]; }
    get isListening(): boolean { return this.#server?.listening ?? false; }

    /* ============================================================= listen == */

    async listen(port = DEFAULT_PORT, host = DEFAULT_HOST): Promise<void> {
        this.#port = port;
        this.#host = host;

        return new Promise((resolve, reject) => {
            const server = createServer((socket) => this.#accept(socket));
            server.on('error', (err) => {
                /* A port already in use is the common case and deserves a
                   sentence a person can act on, not an errno. */
                const e = err as NodeJS.ErrnoException;
                reject(e.code === 'EADDRINUSE'
                    ? new Error(`port ${port} is already in use — another node may be running`)
                    : err);
            });
            server.listen(port, host, () => {
                this.#server = server;
                this.emit('listening', { host, port });
                this.#system(`listening on ${host}:${port} — ${this.peers.size} authorised peer(s)`);
                resolve();
            });
        });
    }

    #accept(socket: Socket): void {
        this.#track(socket);
        const link = new SecureLink({
            socket,
            identity: this.identity,
            isAuthorised: (key) => this.peers.isAuthorised(key),
            initiator: false,
        });
        this.#wire(link, true);
    }

    /* ============================================================= dial == */

    /** Connect out to a peer. Resolves once the handshake has completed. */
    async dial(host: string, port = DEFAULT_PORT): Promise<ConnectedPeer> {
        return new Promise((resolve, reject) => {
            const socket = connect({ host, port });
            socket.setNoDelay(true);
            this.#track(socket);

            const link = new SecureLink({
                socket,
                identity: this.identity,
                isAuthorised: (key) => this.peers.isAuthorised(key),
                initiator: true,
            });

            /* #wire FIRST. Its 'ready' handler is what creates the peer
               record, and EventEmitter runs listeners in registration order —
               so registering this promise's handler first meant it looked up a
               record that did not exist yet, read undefined, and resolved
               nothing. The dial then hung until the handshake timeout with no
               error to show for it. */
            this.#wire(link, false);

            let settled = false;
            link.once('ready', () => {
                const peer = this.#links.get(link);
                if (settled) return;
                settled = true;
                if (peer) resolve(peer);
                else reject(new Error('internal: peer record missing after handshake'));
            });
            link.once('close', (err) => {
                if (!settled) {
                    settled = true;
                    reject(err ?? new Error(`connection to ${host}:${port} closed during handshake`));
                }
            });
            socket.on('error', (err) => {
                if (!settled) { settled = true; reject(err); }
            });
        });
    }

    /* ============================================================= links == */

    #wire(link: SecureLink, inbound: boolean): void {
        link.on('ready', (session) => {
            const name = this.peers.nameFor(session.peerPublicKey);
            const peer: ConnectedPeer = {
                link,
                nodeId: session.peerNodeId,
                publicKey: session.peerPublicKey,
                name,
                address: link.remoteAddress,
                since: Date.now(),
                inbound,
                channels: new Set(),
            };
            this.#links.set(link, peer);

            this.#emit({
                at: Date.now(), kind: 'auth', channel: null, from: 'AUTH_OK',
                text: `${name} [${session.peerNodeId.slice(0, 8)}] verified — ${inbound ? 'inbound' : 'outbound'} ${link.remoteAddress}`,
            });
            this.emit('peers', this.connected);

            // Announce our channels so the peer can route messages to us.
            for (const channel of this.#channels) link.send({ command: 'JOIN', params: [channel] });
        });

        link.on('message', (msg) => this.#onMessage(link, msg));

        link.on('close', (err) => {
            const peer = this.#links.get(link);
            this.#links.delete(link);
            if (peer) {
                this.#emit({
                    at: Date.now(), kind: 'system', channel: null, from: 'SYSTEM',
                    text: `${peer.name} [${peer.nodeId.slice(0, 8)}] disconnected${err ? `: ${err.message}` : ''}`,
                });
                this.emit('peers', this.connected);
            } else if (err) {
                /* No peer record means the handshake never completed — an
                   unauthorised or malformed connection attempt. Worth showing:
                   it is the security boundary doing its job, and silence here
                   would hide a peer whose key was never added. */
                this.#emit({
                    at: Date.now(), kind: 'error', channel: null, from: 'REJECTED',
                    text: `${link.remoteAddress}: ${err.message}`,
                });
            }
        });
    }

    /* ============================================================= irc == */

    #onMessage(link: SecureLink, msg: IrcMessage): void {
        const peer = this.#links.get(link);
        if (!peer) return;   // unreachable: messages only flow post-handshake

        switch (msg.command) {
            case 'PRIVMSG': {
                const [target, text] = msg.params;
                if (!target || text === undefined) return;
                this.#emit({
                    at: Date.now(),
                    kind: 'chat',
                    channel: target.startsWith('#') || target.startsWith('&') ? target : null,
                    from: peer.name,
                    text,
                });
                break;
            }

            case 'JOIN': {
                const channel = msg.params[0];
                if (!channel || !isValidChannelName(channel)) return;
                if (peer.channels.size >= MAX_CHANNELS_PER_PEER) return;
                peer.channels.add(channel);
                this.#emit({
                    at: Date.now(), kind: 'system', channel,
                    from: 'SYSTEM', text: `${peer.name} joined ${channel}`,
                });
                this.emit('peers', this.connected);
                break;
            }

            case 'PART': {
                const channel = msg.params[0];
                if (!channel) return;
                peer.channels.delete(channel);
                this.#emit({
                    at: Date.now(), kind: 'system', channel,
                    from: 'SYSTEM', text: `${peer.name} left ${channel}`,
                });
                this.emit('peers', this.connected);
                break;
            }

            case 'PING':
                link.send({ command: 'PONG', params: msg.params.slice(0, 1) });
                break;

            case 'PONG':
                break;

            case 'QUIT':
                link.destroy(null);
                break;

            default:
                /* Unknown commands are ignored rather than answered. An error
                   reply to every unrecognised line is an amplification vector
                   and tells a prober what this node implements. */
                break;
        }
    }

    /* ============================================================= send == */

    /** Send a message to a channel, to every peer that has joined it. */
    say(channel: string, text: string): number {
        if (!text.trim()) return 0;

        let delivered = 0;
        for (const peer of this.#links.values()) {
            /* Only to peers in the channel. Broadcasting to everyone would
               make channels decorative — a peer that never joined would still
               receive the traffic. */
            if (!peer.channels.has(channel)) continue;
            peer.link.send({ command: 'PRIVMSG', params: [channel, text] });
            delivered++;
        }

        this.#emit({ at: Date.now(), kind: 'chat', channel, from: this.nickname, text });
        return delivered;
    }

    join(channel: string): boolean {
        if (!isValidChannelName(channel)) return false;
        this.#channels.add(channel);
        for (const peer of this.#links.values()) peer.link.send({ command: 'JOIN', params: [channel] });
        this.#system(`joined ${channel}`);
        return true;
    }

    part(channel: string): boolean {
        if (!this.#channels.delete(channel)) return false;
        for (const peer of this.#links.values()) peer.link.send({ command: 'PART', params: [channel] });
        this.#system(`left ${channel}`);
        return true;
    }

    /**
     * Revoke a peer and drop it if connected.
     *
     * Both halves matter. Removing the key alone stops the NEXT handshake but
     * leaves the current session running, so a revoked peer would keep reading
     * the channel until it happened to reconnect.
     */
    revoke(identifier: string): boolean {
        const removed = this.peers.remove(identifier);
        const needle = identifier.trim().toLowerCase();

        for (const peer of [...this.#links.values()]) {
            if (peer.nodeId === needle || peer.publicKey.toString('hex') === needle) {
                peer.link.destroy(new Error('access revoked'));
            }
        }
        return removed;
    }

    async close(): Promise<void> {
        for (const peer of [...this.#links.values()]) peer.link.destroy(null);
        this.#links.clear();

        // Including half-open sockets that never reached a handshake.
        for (const socket of [...this.#sockets]) socket.destroy();
        this.#sockets.clear();

        const server = this.#server;
        this.#server = null;
        if (!server) return;

        await new Promise<void>((resolve) => server.close(() => resolve()));
    }

    /** Remember a socket so close() can guarantee it is destroyed. */
    #track(socket: Socket): void {
        this.#sockets.add(socket);
        socket.once('close', () => this.#sockets.delete(socket));
    }

    /* ============================================================= events == */

    #system(text: string): void {
        this.#emit({ at: Date.now(), kind: 'system', channel: null, from: 'SYSTEM', text });
    }

    #emit(line: ChatLine): void {
        this.emit('line', line);
    }

    /** Node id for a raw key. Exposed for display code. */
    static nodeId(publicKey: Buffer): string {
        return nodeIdFromPublicKey(publicKey);
    }
}
