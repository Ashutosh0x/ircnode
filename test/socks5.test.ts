// SOCKS5 outbound dialling.
//
// Verified against a real SOCKS5 server implemented below rather than a mock,
// because the failure modes that matter are wire-format ones: a bound address
// whose length is read wrong desynchronises everything after it, and payload
// that arrives glued to the SOCKS reply is silently lost if it is not pushed
// back onto the socket.
//
// The property that matters most for Tor is that the DESTINATION HOSTNAME goes
// out as a string (ATYP=3). Resolving it locally would ask the ISP's resolver
// who is being contacted — and for a .onion it cannot work at all, since the
// name only resolves inside Tor.

import { createServer, type Server, type Socket } from 'node:net';
import { socks5Connect, parseProxy, DEFAULT_TOR_SOCKS_PORT } from '../src/net/socks5.ts';

let pass = 0, fail = 0;
const check = (n: string, c: boolean): void => { c ? pass++ : fail++; console.log(`${c ? 'PASS' : 'FAIL'}  ${n}`); };
const threw = async (fn: () => Promise<unknown>): Promise<boolean> => {
    try { await fn(); return false; } catch { return true; }
};

/** What the proxy observed, so tests can assert on the wire format. */
interface Observed { host: string; port: number; atyp: number; usedAuth: boolean; }

/**
 * A real SOCKS5 server. `behaviour` lets a test force a specific reply code or
 * authentication method.
 */
function socksServer(opts: {
    onRequest?: (o: Observed) => void;
    replyCode?: number;
    requireAuth?: boolean;
    replyAtyp?: number;
    /** Bytes to send immediately after the reply, as a destination would. */
    greeting?: string;
} = {}): Promise<{ server: Server; port: number }> {
    const server = createServer((socket: Socket) => {
        let phase: 'greet' | 'auth' | 'request' = 'greet';
        let usedAuth = false;
        let buf = Buffer.alloc(0);

        socket.on('data', (chunk) => {
            buf = Buffer.concat([buf, chunk]);

            if (phase === 'greet') {
                if (buf.length < 2) return;
                const n = buf[1]!;
                if (buf.length < 2 + n) return;
                buf = buf.subarray(2 + n);
                if (opts.requireAuth) { socket.write(Buffer.from([0x05, 0x02])); phase = 'auth'; }
                else { socket.write(Buffer.from([0x05, 0x00])); phase = 'request'; }
                if (buf.length === 0) return;
            }

            if (phase === 'auth') {
                if (buf.length < 2) return;
                const ulen = buf[1]!;
                if (buf.length < 2 + ulen + 1) return;
                const plen = buf[2 + ulen]!;
                if (buf.length < 3 + ulen + plen) return;
                buf = buf.subarray(3 + ulen + plen);
                usedAuth = true;
                socket.write(Buffer.from([0x01, 0x00]));
                phase = 'request';
                if (buf.length === 0) return;
            }

            if (phase === 'request') {
                if (buf.length < 5) return;
                const atyp = buf[3]!;
                let host = '';
                let offset = 4;
                if (atyp === 0x03) {
                    const len = buf[4]!;
                    if (buf.length < 5 + len + 2) return;
                    host = buf.subarray(5, 5 + len).toString('utf8');
                    offset = 5 + len;
                } else if (atyp === 0x01) {
                    if (buf.length < 4 + 4 + 2) return;
                    host = [...buf.subarray(4, 8)].join('.');
                    offset = 8;
                }
                const port = buf.readUInt16BE(offset);
                opts.onRequest?.({ host, port, atyp, usedAuth });

                const code = opts.replyCode ?? 0x00;
                const replyAtyp = opts.replyAtyp ?? 0x01;
                const addr = replyAtyp === 0x03
                    ? Buffer.concat([Buffer.from([4]), Buffer.from('host')])
                    : replyAtyp === 0x04 ? Buffer.alloc(16) : Buffer.alloc(4);
                const reply = Buffer.concat([
                    Buffer.from([0x05, code, 0x00, replyAtyp]), addr, Buffer.from([0x00, 0x50]),
                ]);

                // Glue the destination's first bytes to the reply, as a real
                // proxy does when the far side speaks first.
                socket.write(opts.greeting ? Buffer.concat([reply, Buffer.from(opts.greeting)]) : reply);
            }
        });
        socket.on('error', () => { /* client hangs up on failure paths */ });
    });

    return new Promise((resolve) => {
        server.listen(0, '127.0.0.1', () => {
            resolve({ server, port: (server.address() as { port: number }).port });
        });
    });
}

const servers: Server[] = [];

try {
    /* ========================================================= happy path == */
    console.log('\n-- connecting through a proxy --');
    {
        let seen: Observed | null = null;
        const { server, port } = await socksServer({ onRequest: (o) => { seen = o; } });
        servers.push(server);

        const socket = await socks5Connect({
            proxyHost: '127.0.0.1', proxyPort: port,
            destHost: 'example.onion', destPort: 39840,
        });
        check('the tunnel opens', !socket.destroyed);

        const o = seen as Observed | null;
        check('the destination host reaches the proxy', o?.host === 'example.onion');
        check('the destination port reaches the proxy', o?.port === 39840);

        /* THE property Tor depends on: the name is sent as a name. Resolving
           locally would leak it to the ISP's resolver, and a .onion has no
           DNS entry to resolve at all. */
        check('the hostname is sent as a domain, not resolved locally', o?.atyp === 0x03);
        socket.destroy();
    }

    /* ============================================================= framing == */
    console.log('\n-- reply framing --');
    {
        // Data glued to the SOCKS reply must survive.
        const { server, port } = await socksServer({ greeting: 'HELLO-FROM-PEER' });
        servers.push(server);
        const socket = await socks5Connect({
            proxyHost: '127.0.0.1', proxyPort: port, destHost: 'a.onion', destPort: 1,
        });
        const first = await new Promise<string>((resolve) => {
            socket.once('data', (d: Buffer) => resolve(d.toString()));
        });
        check('bytes sent with the reply are not lost', first === 'HELLO-FROM-PEER');
        socket.destroy();
    }
    {
        // A domain-type bound address is longer than IPv4; misreading its
        // length would swallow the first bytes of the stream.
        const { server, port } = await socksServer({ replyAtyp: 0x03, greeting: 'AFTER-DOMAIN-ADDR' });
        servers.push(server);
        const socket = await socks5Connect({
            proxyHost: '127.0.0.1', proxyPort: port, destHost: 'b.onion', destPort: 1,
        });
        const first = await new Promise<string>((resolve) => {
            socket.once('data', (d: Buffer) => resolve(d.toString()));
        });
        check('a domain-type bound address is consumed correctly', first === 'AFTER-DOMAIN-ADDR');
        socket.destroy();
    }
    {
        const { server, port } = await socksServer({ replyAtyp: 0x04, greeting: 'AFTER-IPV6' });
        servers.push(server);
        const socket = await socks5Connect({
            proxyHost: '127.0.0.1', proxyPort: port, destHost: 'c.onion', destPort: 1,
        });
        const first = await new Promise<string>((resolve) => {
            socket.once('data', (d: Buffer) => resolve(d.toString()));
        });
        check('an IPv6 bound address is consumed correctly', first === 'AFTER-IPV6');
        socket.destroy();
    }

    /* =============================================================== auth == */
    console.log('\n-- authentication --');
    {
        let seen: Observed | null = null;
        const { server, port } = await socksServer({ requireAuth: true, onRequest: (o) => { seen = o; } });
        servers.push(server);
        const socket = await socks5Connect({
            proxyHost: '127.0.0.1', proxyPort: port, destHost: 'd.onion', destPort: 1,
            username: 'circuit-a', password: 'x',
        });
        check('username/password authentication succeeds', (seen as Observed | null)?.usedAuth === true);
        socket.destroy();
    }
    {
        const { server, port } = await socksServer({ requireAuth: true });
        servers.push(server);
        check('a proxy demanding auth with no credentials fails', await threw(() =>
            socks5Connect({ proxyHost: '127.0.0.1', proxyPort: port, destHost: 'e.onion', destPort: 1 })));
    }

    /* ============================================================ failures == */
    console.log('\n-- failure reporting --');
    {
        // 0x04 is what Tor returns for an offline onion service — the single
        // most likely error in real use, so it must not be a bare number.
        const { server, port } = await socksServer({ replyCode: 0x04 });
        servers.push(server);
        let message = '';
        try {
            await socks5Connect({ proxyHost: '127.0.0.1', proxyPort: port, destHost: 'f.onion', destPort: 1 });
        } catch (e) { message = (e as Error).message; }
        check('a host-unreachable reply is refused', message.length > 0);
        check('and explains what it means for a .onion', /offline/i.test(message));
    }
    {
        const { server, port } = await socksServer({ replyCode: 0x02 });
        servers.push(server);
        let message = '';
        try {
            await socks5Connect({ proxyHost: '127.0.0.1', proxyPort: port, destHost: 'g.onion', destPort: 1 });
        } catch (e) { message = (e as Error).message; }
        check('a ruleset rejection is reported in words', /not allowed/i.test(message));
    }
    {
        check('an unreachable proxy fails rather than hanging', await threw(() =>
            socks5Connect({
                proxyHost: '127.0.0.1', proxyPort: 1, destHost: 'h.onion', destPort: 1, timeoutMs: 3000,
            })));
    }
    {
        // A proxy that accepts and says nothing must not leak the socket.
        const silent = createServer(() => { /* never replies */ });
        servers.push(silent);
        await new Promise<void>((r) => silent.listen(0, '127.0.0.1', () => r()));
        const p = (silent.address() as { port: number }).port;
        const started = Date.now();
        check('a silent proxy times out', await threw(() =>
            socks5Connect({ proxyHost: '127.0.0.1', proxyPort: p, destHost: 'i.onion', destPort: 1, timeoutMs: 1500 })));
        check('and does so promptly', Date.now() - started < 5000);
    }

    /* ============================================================== parse == */
    console.log('\n-- proxy address parsing --');
    {
        check('host:port parses', parseProxy('127.0.0.1:9050').port === 9050);
        check('a bare host defaults to the Tor port', parseProxy('localhost').port === DEFAULT_TOR_SOCKS_PORT);
        check('the host is kept', parseProxy('proxy.local:1080').host === 'proxy.local');
        check('an empty address is rejected', await threw(async () => parseProxy('')));
        check('a bad port is rejected', await threw(async () => parseProxy('127.0.0.1:notaport')));
        check('an out-of-range port is rejected', await threw(async () => parseProxy('127.0.0.1:99999')));
    }
} finally {
    for (const s of servers) { try { s.close(); } catch { /* already closed */ } }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
