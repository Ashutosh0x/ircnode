// ---------------------------------------------------------------------------
// socks5.ts — Dial through a SOCKS5 proxy (RFC 1928).
//
// This is what makes Tor usable, and Tor is the answer to the reachability
// problem: two peers behind ordinary home routers, neither able to accept an
// inbound connection, with no port forwarding and no dynamic DNS.
//
// ── Why a proxy is required at all ──────────────────────────────────────────
//
// `.onion` is not a DNS name. Node's net.connect() tries to resolve it and
// gets ENOTFOUND, because resolution happens inside the Tor network and
// nowhere else. The address has to be handed to Tor as a STRING for Tor to
// resolve, which is exactly what SOCKS5's domain-name address type is for.
//
// ── The leak this avoids ────────────────────────────────────────────────────
//
// ATYP=3 (domain name) is used unconditionally, never ATYP=1 (IPv4). Resolving
// the hostname locally and sending an IP would ask the local resolver — the
// ISP's, usually — for the name of the host being contacted, which defeats the
// point of the proxy before a single byte of payload is sent. For a `.onion`
// it does not merely leak, it cannot work.
//
// No dependencies: the protocol is a greeting, a reply, a request and a reply.
// ---------------------------------------------------------------------------

import { connect, type Socket } from 'node:net';

const SOCKS_VERSION = 0x05;
const CMD_CONNECT = 0x01;
const RSV = 0x00;
const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x03;
const ATYP_IPV6 = 0x04;
const AUTH_NONE = 0x00;
const AUTH_USERPASS = 0x02;

/** Tor's default SOCKS port. */
export const DEFAULT_TOR_SOCKS_PORT = 9050;

/** RFC 1928 reply codes, as sentences rather than numbers. */
const REPLY_ERRORS: Record<number, string> = {
    0x01: 'general SOCKS server failure',
    0x02: 'connection not allowed by ruleset',
    0x03: 'network unreachable',
    0x04: 'host unreachable — for a .onion this usually means the service is offline',
    0x05: 'connection refused by the destination',
    0x06: 'TTL expired',
    0x07: 'command not supported by the proxy',
    0x08: 'address type not supported by the proxy',
};

export interface Socks5Options {
    proxyHost: string;
    proxyPort: number;
    destHost: string;
    destPort: number;
    /** Tor uses these to isolate circuits, not to authenticate. */
    username?: string;
    password?: string;
    timeoutMs?: number;
}

/**
 * Open a TCP connection to `destHost:destPort` through a SOCKS5 proxy.
 *
 * Resolves with a connected socket positioned at the start of the tunnelled
 * stream — the caller can use it exactly as if it had dialled directly, which
 * is why SecureLink needs no knowledge of any of this.
 */
export function socks5Connect(opts: Socks5Options): Promise<Socket> {
    const timeoutMs = opts.timeoutMs ?? 30_000;

    return new Promise((resolve, reject) => {
        const socket = connect({ host: opts.proxyHost, port: opts.proxyPort });
        socket.setNoDelay(true);

        let settled = false;
        const fail = (err: Error) => {
            if (settled) return;
            settled = true;
            socket.destroy();
            reject(err);
        };
        /**
         * Hand the socket over, replaying anything the destination already
         * sent.
         *
         * Negotiation reads via 'readable' + read() rather than 'data', which
         * keeps the stream in PAUSED mode throughout — and that is what makes
         * unshift() work. Attaching a 'data' handler switches a stream to
         * flowing mode permanently; unshifting into a flowing stream that has
         * no consumer attached yet discards the bytes, and the caller's first
         * read then waits forever for a frame that was already delivered and
         * thrown away.
         */
        const done = (leftover: Buffer) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            socket.removeListener('readable', onReadable);
            socket.removeListener('error', onError);
            if (leftover.length > 0) socket.unshift(leftover);
            resolve(socket);
        };

        /* Tor builds a circuit before answering, which can take many seconds
           on a first connection. The timeout is generous for that reason —
           and it is here rather than on the caller because a stalled SOCKS
           negotiation leaves a socket that nothing else will ever close. */
        const timer = setTimeout(
            () => fail(new Error(`SOCKS5 proxy ${opts.proxyHost}:${opts.proxyPort} did not respond in ${timeoutMs}ms`)),
            timeoutMs,
        );

        const onError = (err: Error) => fail(
            new Error(`SOCKS5 proxy ${opts.proxyHost}:${opts.proxyPort}: ${err.message}`),
        );
        socket.on('error', onError);

        type Phase = 'greeting' | 'auth' | 'request';
        let phase: Phase = 'greeting';
        let buffer = Buffer.alloc(0);

        const onReadable = () => {
            const chunk = socket.read() as Buffer | null;
            if (chunk === null) return;
            buffer = Buffer.concat([buffer, chunk]);

            try {
                for (;;) {
                    if (phase === 'greeting') {
                        if (buffer.length < 2) return;
                        const [version, method] = [buffer[0]!, buffer[1]!];
                        if (version !== SOCKS_VERSION) throw new Error(`proxy replied with SOCKS version ${version}, expected 5`);
                        buffer = buffer.subarray(2);

                        if (method === AUTH_NONE) {
                            phase = 'request';
                            socket.write(buildRequest(opts.destHost, opts.destPort));
                            continue;
                        }
                        if (method === AUTH_USERPASS) {
                            if (!opts.username) throw new Error('proxy requires username/password authentication');
                            phase = 'auth';
                            socket.write(buildUserPass(opts.username, opts.password ?? ''));
                            continue;
                        }
                        if (method === 0xff) throw new Error('proxy rejected every authentication method offered');
                        throw new Error(`proxy chose unsupported authentication method 0x${method.toString(16)}`);
                    }

                    if (phase === 'auth') {
                        if (buffer.length < 2) return;
                        const status = buffer[1]!;
                        buffer = buffer.subarray(2);
                        if (status !== 0x00) throw new Error('proxy rejected the supplied credentials');
                        phase = 'request';
                        socket.write(buildRequest(opts.destHost, opts.destPort));
                        continue;
                    }

                    // phase === 'request'
                    if (buffer.length < 5) return;
                    const [version, reply, , atyp] = [buffer[0]!, buffer[1]!, buffer[2]!, buffer[3]!];
                    if (version !== SOCKS_VERSION) throw new Error(`proxy replied with SOCKS version ${version}, expected 5`);
                    if (reply !== 0x00) {
                        throw new Error(REPLY_ERRORS[reply] ?? `proxy returned reply code 0x${reply.toString(16)}`);
                    }

                    /* The bound address must be consumed before the tunnelled
                       stream begins; its length depends on the address type,
                       and reading it wrong desynchronises everything after. */
                    const addrLen = atyp === ATYP_IPV4 ? 4
                        : atyp === ATYP_IPV6 ? 16
                        : atyp === ATYP_DOMAIN ? 1 + buffer[4]!
                        : -1;
                    if (addrLen < 0) throw new Error(`proxy replied with unknown address type 0x${atyp.toString(16)}`);

                    const total = 4 + addrLen + 2;   // header + address + port
                    if (buffer.length < total) return;

                    /* Anything the destination already sent arrives glued to
                       the SOCKS reply. Handing it back makes the socket look
                       to the caller exactly like a direct connection — drop it
                       and the first frame of the handshake vanishes. */
                    done(buffer.subarray(total));
                    return;
                }
            } catch (e) {
                fail(e as Error);
            }
        };

        socket.on('readable', onReadable);
        socket.on('connect', () => {
            // Offer both no-auth and username/password; the proxy picks.
            socket.write(Buffer.from([SOCKS_VERSION, 0x02, AUTH_NONE, AUTH_USERPASS]));
        });
    });
}

/* ============================================================= encoding == */

function buildRequest(host: string, port: number): Buffer {
    const name = Buffer.from(host, 'utf8');
    if (name.length > 255) throw new Error('destination hostname is too long for SOCKS5');

    /* ATYP_DOMAIN always — see the header. Tor must resolve the name itself,
       and for a .onion nothing else can. */
    const buf = Buffer.alloc(4 + 1 + name.length + 2);
    buf[0] = SOCKS_VERSION;
    buf[1] = CMD_CONNECT;
    buf[2] = RSV;
    buf[3] = ATYP_DOMAIN;
    buf[4] = name.length;
    name.copy(buf, 5);
    buf.writeUInt16BE(port, 5 + name.length);
    return buf;
}

function buildUserPass(username: string, password: string): Buffer {
    const u = Buffer.from(username, 'utf8');
    const p = Buffer.from(password, 'utf8');
    if (u.length > 255 || p.length > 255) throw new Error('SOCKS5 credentials are too long');
    return Buffer.concat([
        Buffer.from([0x01, u.length]), u,
        Buffer.from([p.length]), p,
    ]);
}

/** "host:port" → parts, defaulting to Tor's SOCKS port. */
export function parseProxy(input: string): { host: string; port: number } {
    const raw = String(input ?? '').trim();
    if (!raw) throw new Error('proxy address is empty');
    const at = raw.lastIndexOf(':');
    if (at === -1) return { host: raw, port: DEFAULT_TOR_SOCKS_PORT };
    const host = raw.slice(0, at) || '127.0.0.1';
    const port = Number(raw.slice(at + 1));
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`"${raw}" does not contain a valid proxy port`);
    }
    return { host, port };
}
