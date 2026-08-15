// ---------------------------------------------------------------------------
// message.ts — IRC message parsing and serialising.
//
// The grammar is RFC 1459 / 2812 with IRCv3 message tags:
//
//     [@tags] [:prefix] COMMAND [params...] [:trailing]
//
// ── The injection problem, which is the whole reason this is careful ────────
//
// IRC frames messages with CRLF. So a parameter that contains CR or LF is not
// a parameter — it is two messages. A node that echoes a nickname or a channel
// topic straight back into a line lets whoever chose that string inject
// arbitrary commands into the stream, attributed to the server:
//
//     nick = "evil\r\nKICK #chan someone"
//
// Every serialiser here rejects CR and LF rather than stripping them.
// Stripping silently changes the message into something the sender did not
// write and the reader cannot detect; refusing makes the bug visible at the
// point it happens.
//
// NUL is refused for the same reason — it truncates in any C-based client that
// might eventually read this stream.
// ---------------------------------------------------------------------------

/** RFC 2812 limits a message to 512 bytes including the trailing CRLF. */
export const MAX_MESSAGE_BYTES = 512;

/** IRCv3 caps the tag section separately. */
export const MAX_TAGS_BYTES = 8191;

export interface IrcMessage {
    /** IRCv3 tags. A tag with no value is the empty string. */
    tags: Record<string, string>;
    /** Sender, without the leading colon. */
    prefix: string | null;
    /** Always upper-cased: IRC commands are case-insensitive. */
    command: string;
    /** Middle params plus the trailing param, in order. */
    params: string[];
}

/* ============================================================= parse == */

/**
 * Parse one IRC line.
 *
 * Tolerant of extra spaces because real servers emit them. Returns null for
 * anything unusable rather than throwing: a malformed line from a peer is an
 * expected event, and every caller would otherwise wrap this in a try.
 */
export function parseMessage(line: string): IrcMessage | null {
    let rest = String(line ?? '').replace(/\r?\n$/, '');
    if (!rest.trim()) return null;

    const tags: Record<string, string> = {};

    // @key=value;key2 — tags come first when present.
    if (rest.startsWith('@')) {
        const end = rest.indexOf(' ');
        if (end === -1) return null;
        const tagPart = rest.slice(1, end);
        rest = rest.slice(end + 1).replace(/^ +/, '');

        for (const pair of tagPart.split(';')) {
            if (!pair) continue;
            const eq = pair.indexOf('=');
            const key = eq === -1 ? pair : pair.slice(0, eq);
            const rawValue = eq === -1 ? '' : pair.slice(eq + 1);
            if (key) tags[key] = unescapeTagValue(rawValue);
        }
    }

    // :prefix
    let prefix: string | null = null;
    if (rest.startsWith(':')) {
        const end = rest.indexOf(' ');
        if (end === -1) return null;
        prefix = rest.slice(1, end);
        rest = rest.slice(end + 1).replace(/^ +/, '');
    }

    if (!rest) return null;

    /* The trailing parameter is the only one that may contain spaces, and it
       is introduced by " :". Split there first so the rest can be tokenised
       naively — doing it the other way round shatters the trailing text. */
    let trailing: string | null = null;
    const trailingAt = rest.indexOf(' :');
    if (rest.startsWith(':')) {
        trailing = rest.slice(1);
        rest = '';
    } else if (trailingAt !== -1) {
        trailing = rest.slice(trailingAt + 2);
        rest = rest.slice(0, trailingAt);
    }

    const tokens = rest.split(' ').filter(Boolean);
    const command = tokens.shift();
    if (!command) return null;

    const params = tokens;
    if (trailing !== null) params.push(trailing);

    return { tags, prefix, command: command.toUpperCase(), params };
}

/* ============================================================= serialise == */

/**
 * Build an IRC line, CRLF included.
 *
 * @throws if any field contains CR, LF or NUL. See the header: these are
 *   message separators, and accepting them turns one message into several.
 */
export function serialiseMessage(msg: {
    tags?: Record<string, string>;
    prefix?: string | null;
    command: string;
    params?: string[];
}): string {
    const parts: string[] = [];

    const tags = msg.tags ?? {};
    const tagKeys = Object.keys(tags);
    if (tagKeys.length > 0) {
        const encoded = tagKeys
            .map((k) => {
                rejectControlChars(k, 'tag key');
                const v = tags[k] ?? '';
                rejectControlChars(v, `tag value for ${k}`);
                return v === '' ? k : `${k}=${escapeTagValue(v)}`;
            })
            .join(';');
        if (encoded.length > MAX_TAGS_BYTES) throw new Error('tag section is too long');
        parts.push(`@${encoded}`);
    }

    if (msg.prefix) {
        rejectControlChars(msg.prefix, 'prefix');
        if (/\s/.test(msg.prefix)) throw new Error('prefix must not contain whitespace');
        parts.push(`:${msg.prefix}`);
    }

    rejectControlChars(msg.command, 'command');
    if (!msg.command.trim() || /\s/.test(msg.command)) {
        throw new Error('command must be a single non-empty token');
    }
    parts.push(msg.command.toUpperCase());

    const params = msg.params ?? [];
    params.forEach((param, i) => {
        const value = String(param ?? '');
        rejectControlChars(value, `parameter ${i + 1}`);

        const isLast = i === params.length - 1;
        /* A parameter containing a space, or starting with ':', or empty, can
           only be expressed as the trailing parameter — and there is only one
           of those, at the end. Anywhere else it is unrepresentable, and
           emitting it anyway would produce a line that parses back into
           something different from what was passed in. */
        const needsTrailing = value === '' || value.includes(' ') || value.startsWith(':');
        if (needsTrailing && !isLast) {
            throw new Error(`parameter ${i + 1} needs to be trailing but is not last`);
        }
        parts.push(needsTrailing ? `:${value}` : value);
    });

    return parts.join(' ') + '\r\n';
}

/**
 * Reject the characters that would break framing.
 *
 * Named separately so the error says which field was at fault; a bare
 * "invalid characters" on a 400-byte line is not a debuggable message.
 */
function rejectControlChars(value: string, field: string): void {
    const s = String(value ?? '');
    if (s.includes('\r') || s.includes('\n')) {
        throw new Error(`${field} must not contain CR or LF — that would inject a second IRC message`);
    }
    if (s.includes('\0')) {
        throw new Error(`${field} must not contain a NUL byte`);
    }
}

/* IRCv3 tag values escape the characters that would otherwise break the
   tag grammar. The mapping is defined by the spec, not chosen here. */
function escapeTagValue(value: string): string {
    return value
        .replace(/\\/g, '\\\\')
        .replace(/;/g, '\\:')
        .replace(/ /g, '\\s')
        .replace(/\r/g, '\\r')
        .replace(/\n/g, '\\n');
}

function unescapeTagValue(value: string): string {
    let out = '';
    for (let i = 0; i < value.length; i++) {
        if (value[i] !== '\\') { out += value[i]; continue; }
        const next = value[++i];
        if (next === undefined) break;      // trailing backslash is dropped
        out += next === ':' ? ';'
            : next === 's' ? ' '
            : next === 'r' ? '\r'
            : next === 'n' ? '\n'
            : next === '\\' ? '\\'
            : next;
    }
    return out;
}

/* ============================================================= validation == */

/**
 * Is this a usable channel name?
 *
 * Prefix, length and the characters the RFC forbids. Applied on every JOIN so
 * a name that could not be echoed back safely is refused at the door rather
 * than at the point of echoing it.
 */
export function isValidChannelName(name: string): boolean {
    const s = String(name ?? '');
    if (s.length < 2 || s.length > 50) return false;
    if (!'#&'.includes(s[0] ?? '')) return false;
    return !/[\s,\0\r\n:]/.test(s.slice(1));
}

/** Is this a usable nickname? Letters, digits and the RFC's special set. */
export function isValidNickname(nick: string): boolean {
    const s = String(nick ?? '');
    if (s.length < 1 || s.length > 30) return false;
    return /^[A-Za-z[\]\\`_^{|}][A-Za-z0-9[\]\\`_^{|}-]*$/.test(s);
}
