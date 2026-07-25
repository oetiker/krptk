# krptk — self-hosted encrypted storage for PWAs

*Design draft, 2026-07-25*

## Problem

You build many PWAs. Each one needs a place to keep user data that survives
the browser (cleared site data, new device, lost phone) — without signing up
for Firebase/AWS/Google, and without writing a bespoke backend per app.

The store must be:

- **Self-hosted**: one small service you run yourself, shared by all your apps.
- **Permanent**: a user's data stays until *they* delete it.
- **Abuse-resistant**: an internet-facing free storage endpoint is a magnet
  for bots and freeloaders; it must not become anyone's free file host.

## Core idea

One generic blob-sync server, many apps. The server never understands the
data: every record is **encrypted client-side** before upload, and the server
stores opaque ciphertext keyed by `(user, app, record-key)`.

This one decision does a lot of work:

- The server codebase stays tiny — it's a versioned key-value store with
  quotas and auth, nothing app-specific. New PWA = new `appId`, zero server
  changes.
- Self-hosting liability drops: the operator *cannot* read user data, so
  there's little worth stealing on the box and no temptation to build
  app-specific server logic.
- The biggest abuse vector disappears structurally: there are **no public,
  unauthenticated reads**. Data can only be fetched by the identity that
  wrote it, so the service is useless as a malware CDN, piracy host, or
  image-sharing dump. What's left (quota exhaustion, bot signups) is handled
  by policy — see [Abuse protection](#abuse-protection).

```
 ┌────────── browser ──────────┐          ┌───────── your server ─────────┐
 │  PWA A ─┐                   │          │                               │
 │  PWA B ─┼─ krptk client SDK │◄──HTTPS─►│  krptk (single binary)        │
 │  PWA C ─┘  keys, crypto,    │   +SSE   │  auth · quotas · versioned KV │
 │            offline queue    │          │  SQLite + blob dir            │
 └─────────────────────────────┘          └───────────────────────────────┘
```

## Identity and keys

No emails, no passwords, no server-side password database.

- A user's identity **is** an Ed25519 keypair, generated in the browser on
  first use and kept in IndexedDB.
- Everything derives from one root secret, presented to the user as a
  **12-word recovery phrase** (BIP39 wordlist). Deterministic derivation:

  ```
  seed        = bip39(phrase)
  identityKey = HKDF(seed, "krptk/v1/identity")          # Ed25519, one per user
  appKey(app) = HKDF(seed, "krptk/v1/app/" + appId)      # symmetric, one per app
  ```

- Blobs are encrypted with `appKey(appId)` using XChaCha20-Poly1305 (random
  24-byte nonce per blob). All crypto lives in the shared Rust core and runs
  in the browser as WASM — see
  [Implementation](#implementation-pure-rust-one-workspace).
- The server only ever sees the **public** identity key. It identifies a user
  as `userId = base58(sha256(pubkey))`.

**New device / recovery**: type the 12 words → same keys → same data. That's
the whole story, and it's why "permanent" is honest: the operator can't reset
a password, but also can't lose one. Optionally add QR device-linking later
(transfer the seed over an ephemeral encrypted channel) so users don't have
to type words.

**Per-app isolation for free**: because each app gets its own derived key,
one compromised/malicious PWA can only ever decrypt its own namespace, even
though all apps share one identity and one server account.

**The honest downside**: lose the phrase and the browser profile → data is
gone forever. Apps must nag users to save the phrase at onboarding
(the SDK should ship a ready-made "save your recovery phrase" flow).

## Auth flow

Signed-challenge login, then a cheap bearer token for the hot path:

1. `POST /v1/auth/challenge` → server returns a random nonce.
2. Client signs `nonce || serverOrigin` with the identity key,
   `POST /v1/auth/token` → short-lived (≈1 h) opaque bearer token.
3. All data requests carry `Authorization: Bearer …`. The SDK refreshes
   transparently.

Binding the server origin into the signature prevents a hostile server from
replaying a login against another krptk instance.

## Data model and sync

The primitive is a **versioned KV store with compare-and-swap and a change
feed** — deliberately *not* a full sync engine, so the server stays generic:

- Namespace: `user / app / key` (keys are client-chosen strings, typically
  encrypted or hashed names so the server learns nothing from them).
- Every record has a monotonically increasing per-`(user,app)` **revision**.
- Writes are CAS: `PUT … If-Version: N` fails with `409` if someone else
  (another device) wrote in between. The client then reads, merges, retries.
- `GET /kv?since=<cursor>` returns everything changed after a cursor —
  the pull half of sync. An SSE endpoint pushes "something changed" pokes so
  open tabs sync live without polling.
- Deletes write tombstones (kept ~30 days) so offline devices converge.

Merging is the app's problem, by design — and it's a solved one: for
structured data, store a **Yjs or Automerge CRDT document per record**, and
"merge" on CAS conflict is just merging two CRDT states, conflict-free. For
simple cases, last-write-wins per key is fine. The SDK offers both patterns;
the server knows about neither.

Blob size is capped (default 4 MB). Anything bigger is chunked client-side
by the SDK. This keeps memory bounded and quotas honest.

## API sketch

```
POST   /v1/register                      {pubkey, inviteCode?, pow?}
POST   /v1/auth/challenge                → {nonce}
POST   /v1/auth/token                    {pubkey, signature} → {token, ttl}

GET    /v1/apps/{app}/kv/{key}           → blob, ETag: <version>
PUT    /v1/apps/{app}/kv/{key}           If-Version: N   (CAS; 409 on conflict)
DELETE /v1/apps/{app}/kv/{key}           If-Version: N
GET    /v1/apps/{app}/kv?since=<cursor>  → change list (keys, versions, sizes)
GET    /v1/apps/{app}/events             SSE change notifications

GET    /v1/account                       → usage, quota, app list
DELETE /v1/account                       (signed; full erasure)
```

Admin endpoints live on a separate listener and back the
[management UI](#management-ui): list accounts by usage, adjust quotas, mint
invite codes, freeze/delete accounts. The admin sees sizes and timestamps,
never plaintext.

## Abuse protection

Layered, cheapest defense first:

1. **No public reads** (structural). Nothing on the server can be linked to
   or served anonymously, so the classic "free file host" abuse is impossible
   rather than merely forbidden.

2. **Gated registration** (default: invite codes). The operator mints codes
   (single- or multi-use, optionally with a quota attached); apps can embed a
   registration link or the user pastes a code. For friends-and-family or
   per-community hosting this alone kills bot signups.
   *Optional open mode* for public apps: registration requires a proof-of-work
   stamp (a few seconds of client CPU) + per-IP rate limit + a small starter
   quota. PoW doesn't stop a determined abuser, but combined with quotas it
   makes abuse cost more than it yields.

3. **Hard quotas per identity**: bytes stored (default e.g. 100 MB), record
   count, and requests/day (token bucket). Ciphertext size is trivially
   accountable. `413`/`429` with clear errors the SDK surfaces to the app.

4. **Per-app registry**: the server carries an allowlist of known `appId`s
   with their CORS origins and per-app default quotas. Unknown app or wrong
   origin → rejected. (An origin check is not a security boundary against
   non-browser clients, but it stops drive-by use of your server by strangers'
   apps.)

5. **Blob/size/rate caps**: max blob size, max keys per app, bounded request
   body handling, global connection limits — standard hygiene.

6. **Operator tools, not surveillance**: usage dashboards, top-accounts view,
   freeze/purge — all metadata-only.

Explicitly **off by default**: inactivity expiry. "Permanent" means permanent;
an operator who wants an expiry policy (e.g. purge accounts untouched for
3 years after email-less best-effort warning via the app) can opt in, but the
promise to users should be the strong one.

## Implementation: pure Rust, one workspace

Everything — server, client core, admin UI — is Rust. The trick that makes
this pay off is a shared core crate: the crypto and sync logic is written
once and used natively on the server (for tests and the CLI) and compiled to
WASM for the browser SDK.

```
krptk/                        # cargo workspace
  crates/
    krptk-core/    # key derivation, encryption, chunking, sync/CAS types,
                   #   wire formats — pure logic, wasm32-compatible, no I/O
    krptk-server/  # axum service: API + embedded admin UI + subcommands
    krptk-wasm/    # wasm-bindgen bindings over krptk-core
  sdk/             # thin TS wrapper published as @krptk/client
```

### Server (`krptk-server`)

- **axum + tokio + tower**; rate limiting and body limits as tower layers
  (`tower_governor` for token buckets per identity and per IP).
- **SQLite via sqlx** (compile-time checked queries) in WAL mode for all
  metadata: accounts, quotas, versions, cursors, invite codes, audit log.
  Blobs ≤ ~64 KB inline in SQLite; larger ones as files in a
  content-addressed directory (BLAKE3 names double as checksums).
- **Crypto (RustCrypto/dalek ecosystem)**: `ed25519-dalek` for identity,
  `chacha20poly1305` (XChaCha) for content, `hkdf` + `sha2` for derivation,
  `bip39` for recovery phrases, `blake3` for content addressing. The same
  crates run in WASM — one implementation, no JS crypto to keep in lockstep.
- **One binary, subcommands**: `krptk serve`, `krptk admin …` (over a Unix
  socket), `krptk backup` / `restore` (SQLite online-backup API + blob dir),
  `krptk scrub` (verify checksums). TOML config, `tracing` structured logs,
  Prometheus via `metrics-exporter-prometheus`.
- Static musl build → a single self-contained artifact; Docker image is
  `FROM scratch` + binary. Runs behind Caddy/nginx/Traefik for TLS.
- **Durability** ("permanent" is a durability claim, not just a policy one):
  WAL + fsync on write, checksums verified on read and by the scrub job,
  documented offsite backup recipe (built-in snapshot + rclone/restic; the
  SQLite file also remains Litestream-compatible if the operator prefers).

## Management UI

Operator-facing, and planned in from the start rather than bolted on. It is
**served by the same binary** (templates and assets embedded via
`rust-embed`) so deployment stays "one binary, one config file".

**Scope** (all metadata-only — the operator never sees plaintext):

- **Dashboard**: total storage, account count, requests/day, top accounts by
  usage, quota pressure, backup and scrub status.
- **Accounts**: search by user id, per-app usage breakdown (sizes and
  timestamps only), quota overrides, freeze / unfreeze, delete with
  confirmation.
- **Invites**: mint single- or multi-use codes with quota presets, see
  redemption status, revoke unused codes.
- **App registry**: add/edit `appId`s, CORS origins, per-app default quotas,
  per-app usage stats.
- **Settings**: registration mode (invite-only / open+PoW), PoW difficulty,
  size and rate limits — the knobs from [Abuse protection](#abuse-protection).
- **Audit log**: every admin action, who/when/what, append-only.

**Tech**: server-side rendered with **askama** templates plus small amounts
of vanilla JS for interactivity — an admin UI is tables and forms, and SSR
keeps it dependency-light, fast, and testable with plain HTTP tests. If it
ever outgrows that, `krptk-core` types are already shared, so promoting it
to a Leptos/Dioxus WASM app later is an incremental change, not a rewrite.

**Admin auth, deliberately separate from user auth**: operator accounts with
argon2id-hashed passwords (created via `krptk admin add-operator`), optional
TOTP second factor, session cookies (SameSite=Strict). By default the admin
UI binds to a **separate listener** (e.g. localhost or an internal port) so
operators can keep it off the public internet entirely or put it behind
reverse-proxy auth (mTLS, OIDC) without touching krptk itself. All admin
actions land in the audit log.

## Client SDK

The browser SDK is `krptk-core` compiled to WASM, wrapped in a thin
TypeScript layer (`@krptk/client`). Division of labor:

- **WASM (Rust)**: key derivation, encryption/decryption, recovery-phrase
  handling, chunking, CAS/merge bookkeeping — everything with correctness or
  security weight. Expect ~150–250 KB gzipped; acceptable for PWAs that
  cache aggressively anyway.
- **TypeScript**: the browser-flavored I/O — `fetch`, IndexedDB (offline
  queue and key storage), `EventSource` for SSE, and the UI building blocks
  (recovery-phrase onboarding, device linking). Keeping I/O out of WASM
  avoids async-plumbing pain and keeps the WASM small and portable.

A welcome side effect of the shared core: native Rust clients (a CLI, Tauri
apps, tests that hammer the server) come almost for free.

App-facing API surface (unchanged by the WASM internals):

```ts
const store = await krptk.open({
  server: "https://store.example.org",
  appId: "myapp",
});                                   // handles keygen/registration/auth

await store.put("notes/2026-07", data);   // encrypts, queues, syncs
const v = await store.get("notes/2026-07");
store.onChange(keys => rerender());       // fed by SSE + local writes

store.recoveryPhrase();                   // for the onboarding "save this" UI
```

The SDK owns: key management, encryption, the offline write queue in
IndexedDB (PWAs must work offline; the queue drains on reconnect using CAS +
merge callbacks), chunking, token refresh, and the recovery/device-link UI
building blocks.

## Prior art, and why not just use it

| Project | Why it doesn't quite fit |
|---|---|
| remoteStorage protocol | Right spirit (user-chosen storage, per-app scopes) but no E2E encryption in the protocol, aging ecosystem. Worth stealing its `appId`-scoping ideas. |
| PouchDB/CouchDB | Great sync, but a per-user-DB Couch is heavy to operate, and E2E must be bolted on. |
| Etebase | Closest in crypto design (E2E, self-hosted) — validate our design against it; its development has been quiet. |
| PocketBase / Supabase / Appwrite | Self-hostable app backends, but server-side data models per app and no E2E; you'd run one *per app* or share schemas — the opposite of "one dumb server for all my PWAs". |
| Solid pods | Interesting, but a much larger spec surface than needed. |

The niche krptk fills: **one tiny zero-knowledge server + one SDK, shared by
any number of otherwise-serverless PWAs.**

## Roadmap sketch

- **v0**: workspace scaffold; `krptk-core` (derivation, encryption, wire
  types) with wasm build; server with register/auth/KV/CAS/quotas/invite
  codes; `krptk admin` CLI (no UI yet); SDK with keys, crypto, put/get,
  offline queue; Docker image. Enough to ship one real PWA on it.
- **v1**: change feed + SSE, chunking, recovery-phrase UI kit,
  **management UI** (dashboard, accounts, invites, app registry, settings,
  audit log), backup/scrub commands and docs.
- **v2 (only if needed)**: sharing between users (wrap a record key to
  another identity's public key), device-linking via QR, per-app server-side
  webhooks, S3-compatible blob backend for bigger installs, TOTP for
  operators, Leptos/Dioxus admin SPA if the SSR UI outgrows itself.

## Open questions

1. **Registration UX vs. abuse**: are invite codes acceptable for your apps'
   audiences, or do some apps need open signup (→ PoW + starter quota mode)?
2. **Key custody UX**: is a mandatory recovery phrase acceptable, or do some
   apps need an easier (weaker) mode, e.g. passphrase-encrypted seed stored
   server-side? That reintroduces password UX and weakens zero-knowledge —
   my recommendation is to keep the phrase and invest in the save-the-phrase
   flow, but it's a real product decision.
3. **CRDT in the box?** Should the SDK bundle Yjs helpers, or stay
   merge-agnostic and document the pattern?
4. **Multi-tenancy**: one krptk instance for all your apps and all their
   users, or per-community instances? The design supports both; quotas and
   invite policy are where they differ.
5. **Admin UI exposure**: is a localhost-only listener plus SSH tunnel enough
   for your deployments, or does the UI need to be publicly reachable with
   its own login (→ TOTP earlier in the roadmap)?
6. **WASM bundle size**: is ~200 KB gzipped fine for all your apps, or does
   some very small PWA need a JS-only crypto path? (I'd rather not maintain
   two implementations — the shared core is the main reason the Rust stack
   pays off.)
