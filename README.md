<div align="center">

# ircnode

**A private IRC node with a cryptographic door.**

Runs on your machine, talks to nobody by default, and admits only peers whose
Ed25519 public key you have explicitly added. Everything after the handshake is
encrypted end to end.

[![release](https://github.com/Ashutosh0x/ircnode/actions/workflows/release.yml/badge.svg)](https://github.com/Ashutosh0x/ircnode/actions/workflows/release.yml)
[![Node.js](https://img.shields.io/badge/Node.js-22%2B-5FA04E?logo=node.js&logoColor=white)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-native%20type%20stripping-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Runtime dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](#zero-dependencies-on-purpose)
[![Tests](https://img.shields.io/badge/tests-148%20passing-brightgreen)](#verified-not-asserted)
[![Tor](https://img.shields.io/badge/transport-Tor%20%2F%20SOCKS5-7D4698?logo=torbrowser&logoColor=white)](#reaching-a-peer-on-another-network)
[![Ed25519](https://img.shields.io/badge/identity-Ed25519-6E4AFF)](#how-a-connection-is-established)
[![X25519](https://img.shields.io/badge/forward%20secrecy-X25519-6E4AFF)](#how-a-connection-is-established)
[![ChaCha20-Poly1305](https://img.shields.io/badge/AEAD-ChaCha20--Poly1305-6E4AFF)](#after-the-handshake)
[![SIGMA](https://img.shields.io/badge/handshake-SIGMA-1F6FEB)](#the-signature-covers-the-transcript-not-a-nonce)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

</div>



<img width="1483" height="762" alt="Two ircnode peers connected over an authenticated, encrypted link" src="https://github.com/user-attachments/assets/5525f04b-a0ba-4435-95bf-b3dfdf461de4" />

*Two nodes on one machine, mutually authenticated. Not a mockup.*

---

## Install

**From source** — no runtime dependencies, nothing to compile, and the code you
read is the code that runs:

```bash
git clone https://github.com/Ashutosh0x/ircnode
cd ircnode && npm install && npm test
node src/cli.ts keygen
```

**Prebuilt binaries** are attached to each
[release](https://github.com/Ashutosh0x/ircnode/releases) for Windows, Linux and
macOS (Intel and Apple Silicon). They are **unsigned** — macOS Gatekeeper and
Windows SmartScreen will object, and that warning is accurate. Verify the
checksum, and check the binary reports the commit you expect:

```bash
sha256sum -c SHA256SUMS     # shasum -a 256 -c on macOS
./ircnode version           # prints the exact commit it was built from
```

If you would rather not run an unsigned binary, don't — run it from source. The
binary is a convenience, not the recommended path.

## Quick start

```bash
node src/cli.ts keygen                        # create this node's identity
node src/cli.ts id                            # print your public key — send it to your peer
node src/cli.ts peers add <their-pubkey> bob  # authorise them
node src/cli.ts serve --port 6697             # run it
```

Inside: `/connect host:port` · `/add` · `/revoke` · `/peers` · `/join #channel` · `/help`

Both sides must add each other. Trust is not transitive here, and being trusted
does not mean trusting back.

---

## Reaching a peer on another network

You at home, your friend in London. Neither of you can accept an inbound
connection, because both sit behind a home router — and increasingly behind
carrier-grade NAT, where port forwarding is not available at all.

Three ways, in the order I would actually try them.

### 1. A WireGuard mesh — works today, no code involved

[Tailscale](https://tailscale.com/blog/how-nat-traversal-works) and similar
handle NAT traversal for you and fall back to relaying when a direct path
cannot be found. Both machines get a stable private address, and `ircnode`
just dials it like any other host.

```bash
# both machines, once
tailscale up
tailscale ip -4          # e.g. 100.101.102.103

# you
./ircnode serve --host 100.101.102.103 --port 39840

# your friend
./ircnode serve --connect 100.101.102.103:39840
```

Bind to the **mesh address, not `0.0.0.0`** — that keeps the listener off your
local network and off the public internet.

### 2. Tor onion service — no port forwarding, no third-party mesh

The best fit for this design. The Tor daemon makes only outbound connections,
so it traverses NAT and CGNAT without any router configuration, and an onion
address **is derived from a public key** — the same identity-is-the-key
property `ircnode` already has one layer up.

```bash
# you: add to torrc, then restart tor
HiddenServiceDir /var/lib/tor/ircnode/
HiddenServicePort 39840 127.0.0.1:39840

cat /var/lib/tor/ircnode/hostname     # <56-chars>.onion
./ircnode serve --port 39840          # stays on loopback; tor reaches it

# your friend
./ircnode serve --tor --connect <56-chars>.onion:39840
```

`--tor` is shorthand for `--proxy 127.0.0.1:9050`; `--proxy` takes any SOCKS5
address. A `.onion` **cannot** be dialled without one — it has no DNS entry, so
a direct connection fails with `ENOTFOUND`. The hostname is sent to the proxy
as a name, never resolved locally, so it is not leaked to your resolver.

You can narrow it further with Tor's own
[client authorization](https://community.torproject.org/onion-services/advanced/client-auth/),
which makes the service unreachable without a credential — your allowlist
enforced a layer lower, so unauthorised peers cannot even find the door.

### 3. Port forwarding — simplest, if you control the router

Forward a port to your machine, run with `--host 0.0.0.0`, and have your friend
dial your public address. Add dynamic DNS if it changes. This is the only
option that exposes a port to the internet; the allowlist still means an
unauthorised peer gets nothing, but it is the least private of the three.

---

## What it is not

Not an IRC client. It will not connect to Libera or OFTC. It is a closed
network of machines you control: two people who have exchanged public keys can
talk, nobody else can open a session, and nobody in between can read one.

---

## Where this came from

Bitcoin 0.1–0.6 bootstrapped its peer-to-peer network over IRC. A node joined a
channel between `#bitcoin00` and `#bitcoin99`, issued a `WHO`, and read other
nodes' IP addresses out of their nicknames — each base58-encoded into the nick.
It was disabled by default in 0.6 and **removed outright in 0.8.2**, after the
IRC network it relied on (LFnet) shut down and took peer discovery with it.

Four things were wrong with it. Each is a design constraint here:

| | Bitcoin over IRC | ircnode |
|---|---|---|
| **Identity** | base58 of your IP, in a nickname | Ed25519 keypair; the nick commits to it |
| **Proof** | none — set any nick, claim any address | signature over the session transcript |
| **Privacy** | addresses broadcast in cleartext | ChaCha20-Poly1305; nothing readable on the wire |
| **Access** | anyone who joins | closed allowlist; no key, no session |
| **Failure** | one network; LFnet died, discovery died | every node listens *and* dials; no centre to lose |

---

## How a connection is established

[SIGMA](https://hajji.org/en/crypto/key-exchange-protocols/the-sigma-protocols) —
"SIGn-and-MAc", the construction behind IKEv2 and the ancestor of Noise's
authenticated patterns.

```
1. I → R   ephemeral_i, nonce_i, version
2. R → I   ephemeral_r, nonce_r
             both derive K = X25519(e, E), then HKDF → directional keys
3. R → I   static_r, Sign_r(H(transcript)), MAC(km_r, static_r)
4. I → R   static_i, Sign_i(H(transcript)), MAC(km_i, static_i)
5. R → I   sealed "accepted"
```

### The signature covers the transcript, not a nonce

This is the part that is easy to get wrong, and getting it wrong is not a small
mistake.

The design people usually reach for is: *server sends a random nonce, client
signs `nonce ‖ server_id ‖ timestamp`*. It looks sound. It has a named flaw —
**identity misbinding**, the weakness that sank Station-to-Station and that
SIGMA exists to fix.

The signature proves someone signed a nonce, but nothing ties it to the key
exchange the session will actually use. So a party who is themselves authorised
can relay a signature from one exchange into another and end up sitting between
two peers who each believe they are talking to the other. What the client signed
was true — it just never said *which conversation* it belonged to.

Signing `H(protocol ‖ version ‖ both ephemerals ‖ both nonces)` makes a
signature valid for exactly one exchange. The MAC over the signer's identity,
keyed from the shared secret, proves they actually derived that key rather than
replaying someone else's signature into the flow.

Two further details that matter:

- **The responder authenticates first.** An unauthorised caller learns nothing
  about who is listening beyond the fact that something is, and is dropped
  before it ever names itself.
- **Message 5 exists** because without it the initiator finishes the moment it
  *sends* its auth — before the responder has checked the allowlist. An
  unauthorised peer would briefly report itself connected, then be torn down.
  The sealed accept frame means "connected" means connected.

Forward secrecy comes from the ephemeral X25519 keys. They die with the
connection, so compromising a long-term key later does not decrypt traffic
recorded earlier.

## After the handshake

ChaCha20-Poly1305, separate keys per direction, nonce = a 64-bit counter.

Counters rather than random nonces on purpose: at 96 bits, random nonces carry a
real birthday-collision risk over a long-lived connection and nothing detects
one. A counter cannot repeat as long as it never wraps, so it is checked against
its ceiling before every use and the session retires rather than rolls over.
Reusing a `(key, nonce)` pair with any stream cipher hands over the XOR of the
plaintexts — not a degradation, a total break.

The sequence number is authenticated as associated data and the receiver
requires exactly the next one, so dropping, reordering or replaying a frame is
detected rather than silently changing what a conversation said.

---

## Zero dependencies, on purpose

Node 22 ships Ed25519, X25519, ChaCha20-Poly1305, HKDF and `timingSafeEqual`,
and runs TypeScript natively — so **the code you audit is byte-for-byte the code
that executes.** There is no build step and no transpiled artifact.

Nothing that touches a private key was written by a third party. For a tool
whose whole premise is a closed trust boundary, the supply chain is the attack
surface worth removing — a key-handling process with 100 transitive packages has
100 authors.

This is also why the interface is `readline` + ANSI rather than Ink: React in
the terminal would bring roughly a hundred packages, and JSX would reintroduce a
build step.

---

## Verified, not asserted

```console
$ npm test
PASS  crypto.test.ts       93 checks
PASS  socks5.test.ts       21 checks
PASS  e2e.test.ts          34 checks

3 suites, 148 checks, 0 failed
```

Most are **negative**. A handshake that works between two honest parties proves
very little; what matters is that it *fails* correctly:

- an auth message from a different exchange is refused — *identity misbinding*
- a valid signature with no allowlist entry is refused
- one-way trust is not enough; both sides must authorise
- revoking a peer drops the **live session**, not just the next handshake
- a low-order X25519 key is refused
- a replayed or reordered frame is refused
- CRLF in any IRC parameter is refused — *message injection*
- a hostile length prefix is refused before anything is allocated
- a proxy demanding authentication with no credentials configured is refused
- a proxy that accepts the connection and then says nothing times out, promptly,
  rather than hanging the dial
- the `.onion` is handed to the proxy as a **name**, never resolved locally —
  *DNS leak*

The wire was checked directly, by tapping every byte handed to the kernel:

```
captured 617 bytes in 8 writes
  plaintext canary visible?   no
  "PRIVMSG" visible?          no
  "#private-p2p" visible?     no
  node id visible?            no
```

---

## Honest limits

- **Binds `127.0.0.1` by default.** Zero-trust makes a wider bind survivable,
  but a default that exposes a port to your network will surprise someone.
  `--host` is deliberate.
- **The key file is written `0600`, which Windows does not enforce.** On NTFS
  that is a request, not a guarantee. The CLI says so at keygen rather than
  letting you assume otherwise.
- **No peer exchange and no automatic hole punching.** Reachability is solved
  by Tor or a WireGuard mesh (see above), not by NAT traversal built in here.
- **Metadata is not hidden.** An observer cannot read your traffic but can see
  two addresses exchanging encrypted frames, and roughly how much.
- **Not independently audited.** The construction is standard and the failure
  modes are tested, but that is not review by someone who did not write it.

---

## Layout

| Path | What lives there |
|---|---|
| `src/crypto/identity.ts` | Ed25519 keys, node ids, domain-separated signing |
| `src/crypto/handshake.ts` | SIGMA mutual auth over X25519 |
| `src/crypto/session.ts` | ChaCha20-Poly1305 with counter nonces |
| `src/acl/peers.ts` | the allowlist, and this node's key on disk |
| `src/protocol/framing.ts` | length-prefixed frames over a TCP stream |
| `src/protocol/message.ts` | IRC grammar with IRCv3 tags, injection-safe |
| `src/net/link.ts` | one authenticated connection |
| `src/net/node.ts` | listener, dialler, channels |
| `src/net/socks5.ts` | outbound dialling through Tor or any SOCKS5 proxy |
| `src/ui/tui.ts` | the terminal interface |
| `src/cli.ts` | entry point |

```bash
npm test          # 148 checks, no network required for the crypto suite
npm run typecheck # tsc --noEmit; nothing is emitted, ever
```

---

<div align="center">
<sub>MIT · built with Node's own crypto and nothing else</sub>
</div>
