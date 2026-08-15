// ---------------------------------------------------------------------------
// framing.ts — Turning a TCP byte stream back into messages.
//
// TCP has no message boundaries. A 200-byte write can arrive as one read, or
// as 200 reads of one byte, or glued to the next write. Any code that assumes
// one `data` event equals one message works perfectly on localhost and fails
// the moment there is a real network in the way.
//
// So every message is prefixed with its 32-bit length, and the reader
// accumulates until it has that many bytes.
//
// The length arrives from the network before anything about it can be
// verified, so it is bounded before it is trusted: a peer that claims a 4 GB
// frame is refused rather than allocated for. That bound is the difference
// between a hostile peer wasting its own time and a hostile peer exhausting
// this process's memory.
// ---------------------------------------------------------------------------

const LENGTH_PREFIX_BYTES = 4;

/** Hard ceiling on one frame, covering the AEAD overhead of a max plaintext. */
export const MAX_FRAME_BYTES = 128 * 1024;

/** Prefix a payload with its length. */
export function frame(payload: Buffer): Buffer {
    if (payload.length > MAX_FRAME_BYTES) {
        throw new Error(`frame of ${payload.length} bytes exceeds the ${MAX_FRAME_BYTES} limit`);
    }
    const header = Buffer.alloc(LENGTH_PREFIX_BYTES);
    header.writeUInt32BE(payload.length, 0);
    return Buffer.concat([header, payload]);
}

/**
 * Reassembles frames from arbitrary chunks of a stream.
 *
 * Stateful by necessity: a frame split across reads has to be remembered
 * between them.
 */
export class FrameReader {
    #buffer: Buffer = Buffer.alloc(0);

    /**
     * Feed bytes in, get whole frames out.
     *
     * @throws if a peer announces a frame larger than the limit. The
     *   connection cannot continue after that — the stream is either hostile
     *   or desynchronised, and there is no way to find the next boundary.
     */
    push(chunk: Buffer): Buffer[] {
        this.#buffer = this.#buffer.length === 0 ? chunk : Buffer.concat([this.#buffer, chunk]);

        const frames: Buffer[] = [];
        for (;;) {
            if (this.#buffer.length < LENGTH_PREFIX_BYTES) break;

            const length = this.#buffer.readUInt32BE(0);
            if (length > MAX_FRAME_BYTES) {
                throw new Error(`peer announced a ${length}-byte frame, over the ${MAX_FRAME_BYTES} limit`);
            }

            const total = LENGTH_PREFIX_BYTES + length;
            if (this.#buffer.length < total) break;   // still incomplete

            frames.push(this.#buffer.subarray(LENGTH_PREFIX_BYTES, total));
            this.#buffer = this.#buffer.subarray(total);
        }
        return frames;
    }

    /** Bytes held for an incomplete frame. Useful for idle/timeout checks. */
    get pending(): number {
        return this.#buffer.length;
    }

    reset(): void {
        this.#buffer = Buffer.alloc(0);
    }
}
