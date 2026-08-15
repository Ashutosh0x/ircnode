// ---------------------------------------------------------------------------
// tui.ts — The terminal interface.
//
// Built on node:readline and ANSI escapes, with no UI dependency.
//
// Ink (React for the terminal) is the usual choice and was the obvious one
// here. It is not used, for two reasons specific to this project:
//
//   1. It brings React and roughly a hundred transitive packages into a tool
//      whose entire premise is that the supply chain is the attack surface.
//      A private-key handling process with 100 dependencies has 100 authors.
//   2. JSX needs a build step. Node 22 strips TypeScript types natively but
//      cannot compile JSX, so adding it would mean the code that runs is no
//      longer the code you read — which is exactly the property a security
//      tool should keep.
//
// The layout is a full-screen split: header, sidebar, scrollback, input,
// status. Redrawn on change rather than diffed; at terminal sizes the whole
// screen is a few kilobytes and a full repaint is imperceptible.
// ---------------------------------------------------------------------------

import { createInterface, type Interface } from 'node:readline';
import { EventEmitter } from 'node:events';

import type { ChatLine, ConnectedPeer, IrcNode } from '../net/node.ts';

/* ANSI. Written out rather than pulled from chalk — this is the whole of what
   the interface needs, and it is less code than the import would be. */
const ESC = '\x1b[';
const A = {
    reset: `${ESC}0m`,
    bold: `${ESC}1m`,
    dim: `${ESC}2m`,
    clear: `${ESC}2J`,
    home: `${ESC}H`,
    hideCursor: `${ESC}?25l`,
    showCursor: `${ESC}?25h`,
    to: (row: number, col: number) => `${ESC}${row};${col}H`,
    clearLine: `${ESC}2K`,
};

/** Tokyo Night-ish. Muted so the security states stand out against it. */
const C = {
    frame: `${ESC}38;5;60m`,
    label: `${ESC}38;5;110m`,
    accent: `${ESC}38;5;141m`,
    ok: `${ESC}38;5;114m`,
    warn: `${ESC}38;5;180m`,
    bad: `${ESC}38;5;203m`,
    dim: `${ESC}38;5;244m`,
    text: `${ESC}38;5;253m`,
    me: `${ESC}38;5;117m`,
};

const SIDEBAR_WIDTH = 34;
const MAX_SCROLLBACK = 1000;

export class Tui extends EventEmitter<{ command: [string] }> {
    readonly #node: IrcNode;
    readonly #rl: Interface;
    #lines: ChatLine[] = [];
    #peers: readonly ConnectedPeer[] = [];
    #active: string;
    #status = 'starting';
    #closed = false;

    constructor(node: IrcNode) {
        super();
        this.#node = node;
        this.#active = node.channels[0] ?? '#private-p2p';

        this.#rl = createInterface({ input: process.stdin, output: process.stdout, prompt: '' });

        node.on('line', (line) => this.#push(line));
        node.on('peers', (peers) => { this.#peers = peers; this.render(); });
        node.on('listening', ({ host, port }) => {
            this.#status = `LISTENING ${host}:${port}`;
            this.render();
        });

        this.#rl.on('line', (input) => {
            this.emit('command', input);
            this.render();
        });

        /* Ctrl+C closes rather than killing, so sockets get shut down and the
           terminal is restored. A TUI that leaves the cursor hidden and the
           screen scrambled has failed at its last job. */
        this.#rl.on('SIGINT', () => this.close());
        process.stdout.on('resize', () => this.render());
    }

    get activeChannel(): string {
        return this.#active;
    }

    setActiveChannel(channel: string): void {
        this.#active = channel;
        this.render();
    }

    /** Add a line locally without routing it through the node. */
    system(text: string, kind: ChatLine['kind'] = 'system'): void {
        this.#push({ at: Date.now(), kind, channel: null, from: 'SYSTEM', text });
    }

    #push(line: ChatLine): void {
        this.#lines.push(line);
        if (this.#lines.length > MAX_SCROLLBACK) this.#lines.shift();
        this.render();
    }

    /* ============================================================= draw == */

    render(): void {
        if (this.#closed) return;

        const cols = Math.max(process.stdout.columns ?? 100, 60);
        const rows = Math.max(process.stdout.rows ?? 30, 12);
        const feedWidth = cols - SIDEBAR_WIDTH - 3;
        const bodyRows = rows - 5;   // header, separator, input, status

        /* Control codes are NOT part of the line array. They were, and the
           array is joined with '\n' — so clear/home/hide-cursor each got a
           newline after them, which pushed every frame three rows down and
           undid the cursor-home immediately after issuing it. */
        const out: string[] = [];

        // ── header ──
        const id = this.#node.identity.nodeId;
        out.push(
            `${C.accent}${A.bold} SECURE IRC NODE ${A.reset}`
            + `${C.dim}│${A.reset} ${C.label}node${A.reset} ${id.slice(0, 8)}…${id.slice(-4)} `
            + `${C.dim}│${A.reset} ${this.#statusBadge()} `
            + `${C.dim}│${A.reset} ${C.label}acl${A.reset} ${C.ok}STRICT${A.reset} ${C.dim}(${this.#node.peers.size} authorised)${A.reset}`,
        );
        out.push(`${C.frame}${'─'.repeat(cols)}${A.reset}`);

        // ── body: sidebar + feed ──
        const sidebar = this.#sidebar(bodyRows);
        const feed = this.#feed(feedWidth, bodyRows);

        for (let i = 0; i < bodyRows; i++) {
            const left = pad(sidebar[i] ?? '', SIDEBAR_WIDTH);
            out.push(`${left}${C.frame}│${A.reset} ${feed[i] ?? ''}`);
        }

        // ── input + status ──
        out.push(`${C.frame}${'─'.repeat(cols)}${A.reset}`);
        out.push(
            `${C.dim}[${A.reset}${C.accent}${this.#active}${A.reset}${C.dim}]${A.reset} `
            + `${this.#rl.line ?? ''}`,
        );
        out.push(
            `${C.dim} ^C quit  │  /help commands  │  /join #ch  │  /peers  │  `
            + `${C.ok}E2E ChaCha20-Poly1305${C.dim}  │  ${this.#peers.length} peer(s) online${A.reset}`,
        );

        // One write: clear, home, hide, the frame. A single syscall also stops
        // the terminal showing a half-drawn screen.
        process.stdout.write(`${A.clear}${A.home}${A.hideCursor}${out.join('\n')}`);

        /* Park the cursor at the end of the input line so typing appears where
           the user is looking. Without this it sits wherever the last write
           left it, which reads as a frozen interface. */
        const promptWidth = this.#active.length + 3;
        process.stdout.write(A.to(rows - 1, promptWidth + (this.#rl.line?.length ?? 0) + 1));
        process.stdout.write(A.showCursor);
    }

    #statusBadge(): string {
        if (this.#status.startsWith('LISTENING')) return `${C.ok}● ${this.#status}${A.reset}`;
        if (this.#status.startsWith('ERROR')) return `${C.bad}● ${this.#status}${A.reset}`;
        return `${C.warn}● ${this.#status}${A.reset}`;
    }

    #sidebar(rows: number): string[] {
        const out: string[] = [];

        out.push(`${C.label}${A.bold} CHANNELS${A.reset}`);
        for (const channel of this.#node.channels) {
            const active = channel === this.#active;
            out.push(active
                ? `  ${C.accent}▸ ${channel}${A.reset}`
                : `  ${C.dim}  ${channel}${A.reset}`);
        }

        out.push('');
        out.push(`${C.label}${A.bold} PEERS ${A.reset}${C.dim}(${this.#peers.length})${A.reset}`);
        if (this.#peers.length === 0) {
            out.push(`  ${C.dim}none connected${A.reset}`);
        }
        for (const peer of this.#peers) {
            const arrow = peer.inbound ? '←' : '→';
            out.push(`  ${C.ok}✔${A.reset} ${C.text}${truncate(peer.name, 14)}${A.reset} ${C.dim}${arrow}${A.reset}`);
            out.push(`    ${C.dim}${peer.nodeId.slice(0, 12)}…${A.reset}`);
        }

        out.push('');
        out.push(`${C.label}${A.bold} SECURITY${A.reset}`);
        out.push(`  ${C.dim}allowlist${A.reset}  ${C.ok}enforced${A.reset}`);
        out.push(`  ${C.dim}handshake${A.reset}  ${C.ok}SIGMA${A.reset}`);
        out.push(`  ${C.dim}cipher${A.reset}     ${C.ok}ChaCha20${A.reset}`);
        out.push(`  ${C.dim}forward sec${A.reset} ${C.ok}X25519${A.reset}`);

        return out.slice(0, rows);
    }

    #feed(width: number, rows: number): string[] {
        /* Lines for this channel, plus everything without one — system and
           security events are not channel-scoped and must never be hidden by
           whichever tab happens to be selected. */
        const visible = this.#lines.filter((l) => l.channel === null || l.channel === this.#active);

        const rendered: string[] = [];
        for (const line of visible) {
            const time = new Date(line.at).toTimeString().slice(0, 8);
            const colour = line.kind === 'auth' ? C.ok
                : line.kind === 'error' ? C.bad
                : line.kind === 'system' ? C.warn
                : line.from === this.#node.nickname ? C.me
                : C.text;

            const who = line.kind === 'chat' ? `<${line.from}>` : `${line.from}`;
            const head = `${C.dim}${time}${A.reset} ${colour}${who}${A.reset} `;
            const headWidth = time.length + who.length + 2;

            // Wrap the body so a long message does not smear the layout.
            for (const [i, chunk] of wrap(line.text, Math.max(width - headWidth, 20)).entries()) {
                rendered.push(i === 0 ? `${head}${colour}${chunk}${A.reset}` : `${' '.repeat(headWidth)}${colour}${chunk}${A.reset}`);
            }
        }

        // Newest at the bottom, like every chat client.
        return rendered.slice(-rows);
    }

    close(): void {
        if (this.#closed) return;
        this.#closed = true;
        process.stdout.write(`${A.showCursor}${A.reset}\n`);
        this.#rl.close();
    }
}

/* ============================================================= helpers == */

/** Pad to a visible width, ignoring ANSI escapes when measuring. */
function pad(text: string, width: number): string {
    const visible = stripAnsi(text).length;
    return visible >= width ? text : text + ' '.repeat(width - visible);
}

function truncate(text: string, max: number): string {
    return text.length <= max ? text : text.slice(0, max - 1) + '…';
}

function stripAnsi(text: string): string {
    // eslint-disable-next-line no-control-regex
    return text.replace(/\x1b\[[0-9;]*m/g, '');
}

/** Wrap on word boundaries, breaking a word only when it cannot fit. */
export function wrap(text: string, width: number): string[] {
    const words = String(text ?? '').split(/\s+/).filter(Boolean);
    if (words.length === 0) return [''];

    const lines: string[] = [];
    let current = '';

    for (const word of words) {
        if (word.length > width) {
            if (current) { lines.push(current); current = ''; }
            for (let i = 0; i < word.length; i += width) lines.push(word.slice(i, i + width));
            continue;
        }
        if (!current) current = word;
        else if (current.length + 1 + word.length <= width) current += ` ${word}`;
        else { lines.push(current); current = word; }
    }
    if (current) lines.push(current);
    return lines;
}
