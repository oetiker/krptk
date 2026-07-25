# krptk — self-hosted encrypted cloud sync for PWA browser storage

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

**A background replicator for browser storage, backed by one dumb server.**
Apps keep using `localStorage`/IndexedDB as they do today; krptk mirrors that
storage — encrypted client-side — to a server that never understands the data
and only stores opaque ciphertext keyed by `(user, app, record-key)`. See
[Client SDK](#client-sdk-an-automatic-syncer-for-browser-storage) for what
that means in practice; it is the part that decides whether this is pleasant
to adopt.

Keeping the server ignorant does a lot of work:

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
 ┌──────────────── browser ────────────────┐      ┌──── your k8s cluster ────┐
 │ PWA code                                │      │                          │
 │   ↕ (unchanged reads/writes)            │      │  krptk (single binary)   │
 │ localStorage · IndexedDB · Dexie        │      │  auth · quotas           │
 │   ↕ adapters observe + apply            │      │  versioned KV + CAS      │
 │ krptk SDK — WebCrypto, outbox           │◄────►│  admin UI                │
 │ service worker: background sync ────────┼HTTPS─┤  SQLite + blob dir (PVC) │
 └─────────────────────────────────────────┘ +SSE └──────────────────────────┘
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

- Blobs are encrypted with **AES-256-GCM** under a per-record subkey:

  ```
  recordKey = HKDF(appKey, "krptk/v1/rec/" + key)   # one subkey per record
  ciphertext = AES-256-GCM(recordKey, nonce = 0, plaintext, aad = key‖version)
  ```

  Deriving a fresh subkey per record means the nonce never has to be unique
  across records — it can be a constant — which removes the classic
  nonce-reuse footgun entirely. The record key and version go in the AAD, so
  ciphertext can't be replayed under a different key or rolled back to an
  older version undetected.
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

### Crypto: WebCrypto in the browser, Rust natively

The browser data path uses **WebCrypto (`SubtleCrypto`)** rather than crypto
compiled to WASM. Three reasons, in order of importance:

1. **Non-extractable keys.** A derived `CryptoKey` marked non-extractable can
   be used but never read — and `CryptoKey` objects are structured-cloneable,
   so they can be *stored in IndexedDB directly*. Key material never exists
   as JS-reachable bytes, so an XSS bug in a PWA cannot exfiltrate the user's
   keys. With WASM crypto the key sits in linear memory, which is a
   `Uint8Array` away from any script on the page. For a zero-knowledge store,
   this is the strongest argument.
2. **Speed.** AES-GCM goes through native, AES-NI-accelerated code —
   roughly an order of magnitude faster than a WASM stream cipher on
   megabyte-sized blobs, and it runs off the JS heap.
3. **Bundle size.** Zero bytes shipped for the primitives.

Everything the design needs is available: `HKDF` for derivation, `PBKDF2`
with SHA-512 for the BIP39 seed step (2048 iterations, exactly as BIP39
specifies), `AES-GCM` for content, and `Ed25519` for identity signatures
(shipped in all major browsers by 2025; a small WASM fallback covers older
ones). Only the BIP39 *wordlist* mapping is plain non-secret code.

The chain is designed so raw key bytes never need to persist: the seed is
imported as non-extractable HKDF key material, and app and record keys are
derived from it as non-extractable AES keys.

**The honest tradeoffs:**

- **XChaCha20-Poly1305 is out** — WebCrypto doesn't offer it. AES-GCM with
  per-record subkeys is an equally sound choice, and the derivation trick
  above neutralizes AES-GCM's short-nonce weakness.
- **The recovery phrase becomes show-once.** If the seed is never persisted
  in extractable form, the app cannot re-display the phrase later. That's a
  real UX cost, and the mitigation is either accepting it (show it at
  onboarding, verify the user wrote it down) or storing the seed encrypted
  under a user-chosen PIN for later re-display. I'd default to show-once with
  a solid onboarding flow, and offer PIN-protected re-display as an SDK
  option.
- **Per-call overhead.** WebCrypto calls are async with a small fixed cost,
  so syncing thousands of tiny records is dominated by overhead rather than
  cipher speed. The fix is batching — pack many small records into one
  encrypted batch blob — which the SDK does anyway to keep request counts
  (and quota) sane.

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

## Implementation: Rust workspace

The server, the CLI, the admin UI and the native client are Rust. Note what
the WebCrypto decision above implies: **the server performs no content
crypto at all** — it verifies Ed25519 login signatures and otherwise moves
opaque bytes. So the crypto format is a *spec*, not a shared implementation,
with two implementations (WebCrypto in the browser, RustCrypto natively) held
together by cross-implementation test vectors checked in CI. That's a
deliberate, contained duplication: a few hundred lines of well-tested
primitives against a written format.

```
krptk/                        # cargo workspace
  crates/
    krptk-format/  # the wire + crypto format: derivation labels, header
                   #   layout, chunking rules, CAS/sync types, test vectors
    krptk-crypto/  # native impl of the format (aes-gcm, hkdf, ed25519-dalek)
    krptk-server/  # axum service: API + embedded admin UI + subcommands
    krptk-client/  # native client (CLI, tests, Tauri) over format + crypto
  sdk/             # @krptk/client — TS, WebCrypto, IndexedDB, sync engine
```

WASM is now optional rather than load-bearing: a small module for the Ed25519
fallback on older browsers, and nothing else. That drops the SDK from
~200 KB to a few tens of KB.

### Server (`krptk-server`)

- **axum + tokio + tower**; rate limiting and body limits as tower layers
  (`tower_governor` for token buckets per identity and per IP).
- **SQLite via sqlx** (compile-time checked queries) in WAL mode for all
  metadata: accounts, quotas, versions, cursors, invite codes, audit log.
  Blobs ≤ ~64 KB inline in SQLite; larger ones as files in a
  content-addressed directory (BLAKE3 names double as checksums). Database and
  blob directory **must share one volume** so volume snapshots are atomic
  across both.
- **Crypto on the server is minimal**: `ed25519-dalek` to verify login
  signatures, `argon2` for operator passwords, `blake3` for content
  addressing. Content ciphers live only in `krptk-crypto`, for native clients
  and for format conformance tests — the server never needs them.
- **One binary, subcommands**: `krptk serve`, `krptk admin …`,
  `krptk backup` / `restore` (SQLite online-backup API + blob dir),
  `krptk scrub` (verify checksums). TOML config, `tracing` structured logs,
  Prometheus via `metrics-exporter-prometheus`.
- **Maintenance runs in-process**, on an internal schedule, not as separate
  jobs — see [Kubernetes](#deployment-on-kubernetes) for why that constraint
  exists. The CLI subcommands stay available for manual/offline use and talk
  to a running server over its admin API.
- Static musl build → a single self-contained artifact; Docker image is
  `FROM scratch` + binary, distroless-equivalent and scannable to nothing.
- **Durability** ("permanent" is a durability claim, not just a policy one):
  WAL with `synchronous=FULL`, checksums verified on read and by the scheduled
  scrub, a `quiesce` command so the volume can be snapshotted cleanly, and
  `krptk backup`/`restore` for portable logical archives. Backups themselves
  are the cluster's job — see
  [Backup via Ceph RBD snapshots](#backup-and-restore-via-ceph-rbd-snapshots).

## Deployment on Kubernetes

Target deployment is k8s, shipped as a **Helm chart** in-repo. The
uncomfortable truth to design around: krptk is a *single-writer, stateful*
service. SQLite has one writer and the blob directory is a local filesystem,
so this is a **StatefulSet with `replicas: 1`**, scaled vertically. That's not
a limitation to hide — it's a fit-for-purpose choice, and one pod on modest
resources serves thousands of PWA users doing sync-shaped traffic.

Consequences worth planning for rather than discovering:

- **Volume must be block-backed RWO** — **Ceph RBD is the reference target**
  (also EBS/PD, Longhorn, local-path). **Never NFS or CephFS**: SQLite's
  locking is unsafe on most network filesystems, and this is the single most
  likely way to corrupt a krptk install. The chart should refuse (or loudly
  warn about) an RWX storage class. A *single* PVC holds both the database and
  the blobs — see [backup](#backup-and-restore-via-ceph-rbd-snapshots) for why
  that is a correctness requirement rather than a convenience.
- **`updateStrategy` must not run two pods at once.** With RWO the new pod
  can't attach while the old one holds the volume, so a naive rolling update
  deadlocks until timeout. Use `OnDelete`/recreate semantics and accept a few
  seconds of downtime per upgrade. This is where the client design pays off:
  the SDK's offline queue means a brief restart is invisible to PWAs — writes
  queue locally and drain on reconnect. Availability lives in the client, not
  in replica count.
- **Maintenance can't be a `CronJob` that mounts the disk.** A separate pod
  running `scrub` would need the same RWO volume the server pod holds. So
  scheduled maintenance is **built into the server**; a CronJob that *calls
  the admin API* is fine, it just can't mount the volume. Backup is a
  different story now — see
  [Backup via Ceph RBD snapshots](#backup-and-restore-via-ceph-rbd-snapshots).
- **Two Services, two exposure levels.** The public API Service goes behind
  the Ingress; the admin listener gets a `ClusterIP`-only Service that is
  deliberately *not* in any Ingress by default — reachable via
  `kubectl port-forward`, or optionally via a second Ingress with its own
  auth. A `NetworkPolicy` restricts who can reach the admin port at all.
  This is the k8s-native expression of the separate-listener design.
- **SSE needs Ingress care.** Change notifications are long-lived streams, so
  the chart sets `nginx.ingress.kubernetes.io/proxy-buffering: "off"` and
  generous read timeouts (and the equivalents for Traefik). Getting this
  wrong shows up as sync that only works on page reload.
- **Probes**: `/healthz` (liveness, cheap) and `/readyz` (readiness — SQLite
  reachable, blob dir writable, migrations done), plus a `startupProbe` so
  slow migrations on a large database don't trip liveness restarts.
- **Pod hardening** comes almost free with a scratch image: `runAsNonRoot`,
  `readOnlyRootFilesystem: true` (the only writable path is the data volume),
  `allowPrivilegeEscalation: false`, all capabilities dropped, seccomp
  `RuntimeDefault`.
- **Config and secrets**: TOML config from a ConfigMap with a checksum
  annotation so config changes roll the pod; session signing key, operator
  bootstrap credentials and S3 backup credentials from a Secret (External
  Secrets-friendly).
- **Observability**: optional `ServiceMonitor` for Prometheus Operator, and
  the shipped dashboard/alerts should cover the things that actually bite —
  volume nearing full, backup age exceeding threshold, scrub errors, quota
  rejection rate.
- **Resources**: `requests` set with a real `memory` floor (SQLite page cache
  plus blob buffers) and no CPU limit by default, since throttling a
  single-replica sync server is worse than letting it burst.
- **Scaling escape hatch, deliberately deferred**: because everything goes
  through `sqlx`, a Postgres backend plus S3 blob storage would allow
  `replicas: N` behind a normal Deployment. That's a v2 item to design toward
  but not build now — the single-pod story is honest and sufficient, and
  premature HA would cost the simplicity that makes self-hosting pleasant.

### Backup and restore via Ceph RBD snapshots

Since the cluster already does **RBD volume snapshots**, that becomes krptk's
primary backup mechanism and the server gets *simpler*: no scheduled S3
upload, no Litestream sidecar, no backup credentials in a Secret. The design
just has to earn the right to be snapshotted safely.

**Why this is sound**: an RBD snapshot is crash-consistent at the block layer,
and SQLite in WAL mode is explicitly crash-safe — restoring a snapshot looks
exactly like recovering from a power cut, which SQLite handles by replaying or
discarding the WAL. Nothing extra is needed for *integrity*.

Three requirements to make it actually correct:

1. **One PVC for everything.** The SQLite database and the blob directory must
   live on the **same volume**, so the snapshot is atomic across both. Split
   them onto two PVCs and a snapshot can catch metadata referencing a blob
   that isn't there yet (or vice versa) — a silent, latent inconsistency.
   This is now a hard design constraint, not a deployment preference.
2. **`synchronous=FULL`** in WAL mode. With `NORMAL`, recent committed
   transactions can be lost on power loss — and therefore be missing from a
   snapshot — even though the database stays uncorrupted. `FULL` means
   anything krptk has acknowledged to a client is in the snapshot. Given
   sync-shaped write volumes, the fsync cost is worth the honesty; it's
   configurable for operators who disagree.
3. **A quiesce hook** for clean snapshots. `krptk admin quiesce --hold=30s`
   briefly pauses new writes, runs `PRAGMA wal_checkpoint(TRUNCATE)`, fsyncs
   the blob directory, and holds until released or the timeout expires. Wire
   it as a pre-snapshot hook (Velero `pre.hook.backup.velero.io/command`, a
   Kanister blueprint, or a `kubectl exec` in whatever schedules the
   snapshots). Crash-consistent snapshots are *fine*; quiesced ones restore
   with an empty WAL and no replay, which is nicer to reason about during an
   incident.

**Scheduling**: any CSI snapshot scheduler works — Velero schedules, or
snapscheduler if you want something small that just does PVC snapshots. The
chart ships a `VolumeSnapshotClass` reference and optional schedule manifests
but doesn't reimplement any of it.

**The gap snapshots don't close**, and it matters for a store whose promise is
*permanent*:

- **RBD snapshots live in the same Ceph cluster.** They protect against
  accidental deletion, a bad upgrade, or operator error — not against loss of
  the cluster. At least one copy must leave it: either Ceph **snapshot-based
  RBD mirroring** to a second cluster, or Velero with CSI data movement
  exporting to object storage. Pick one; "we have snapshots" is not offsite.
- **Snapshots faithfully preserve corruption.** If a bug or bit-rot damages a
  blob, every subsequent snapshot contains the damage, and a bad restore point
  can go unnoticed for months. That's what `krptk scrub` is for — it verifies
  every blob against its BLAKE3 name and the metadata against the blob set,
  and its results are surfaced in the admin UI and as a Prometheus metric.
  **Snapshot age and last-clean-scrub time are the two alerts that matter.**
- **Logical export stays worthwhile**, in `krptk backup` form: a
  self-describing archive (SQLite dump + blobs) that is portable across
  krptk versions and Ceph clusters, and can be verified independently of the
  block layer. Weekly, offsite, verified — a cheap second failure domain.
  Snapshots are for fast recovery; the logical export is for the bad day.

**Restore drill** (documented and rehearsed, because an untested backup isn't
a backup): scale the StatefulSet to 0 → create a PVC from the
`VolumeSnapshot` → point the StatefulSet at it → scale to 1 → run
`krptk scrub` before letting clients back in. The chart includes this as a
runbook.

**Bonus from RBD**: cloning a snapshot into a throwaway volume is cheap, so
schema migrations and version upgrades can be **rehearsed against a clone of
real production data** before touching the live volume. Worth building into
the upgrade runbook, since single-replica upgrades have no rollback other
than restore.

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
ever outgrows that, the `krptk-format` types are already shared, so promoting
it to a Leptos/Dioxus WASM app later is an incremental change, not a rewrite.

**Admin auth, deliberately separate from user auth**: operator accounts with
argon2id-hashed passwords (created via `krptk admin add-operator`), optional
TOTP second factor, session cookies (SameSite=Strict). By default the admin
UI binds to a **separate listener** (e.g. localhost or an internal port) so
operators can keep it off the public internet entirely or put it behind
reverse-proxy auth (mTLS, OIDC) without touching krptk itself. All admin
actions land in the audit log.

## Client SDK: an automatic syncer for browser storage

**This is the positioning.** krptk is not "another storage API to port your
app to" — it is a *background replicator for the storage your PWA already
uses*. Each adapter exposes **the same API as the store it replaces**, so the
app keeps reading and writing exactly as it does now — it just points at the
adapter object instead of the global. krptk mirrors that storage, encrypted,
to your server and pulls other devices' changes back in. The pitch is roughly
"iCloud-style sync for whatever your PWA already keeps in the browser",
self-hosted.

This framing is strictly better than a bespoke API for three reasons:
retrofitting an existing app is a few lines rather than a rewrite; the app
stays **local-first** by construction, since reads and writes never wait on
the network; and the app keeps working unchanged if krptk is absent or the
user hasn't signed up — sync becomes an *optional feature*, not a dependency.

```ts
import { krptk } from "@krptk/client";

const sync = await krptk.attach({
  server: "https://store.example.org",
  appId:  "myapp",
  stores: [
    krptk.localStorage({ prefix: "myapp:" }),       // mirror these keys
    krptk.idbKeyval({ store: "notes" }),            // ...and this idb store
    krptk.dexie(db, { tables: ["notes", "tags"] }), // ...and these tables
  ],
});

sync.on("status", s => badge.render(s));  // synced | pending | offline | …
sync.on("remote", keys => rerender());    // another device changed things
```

### Adapters

Each adapter's job is to observe local writes, map records to krptk keys, and
apply incoming remote changes back into the local store:

| Local storage | Mapping | Notes |
|---|---|---|
| `localStorage` / `sessionStorage` | one record per key | Facade wraps `Storage`; `storage` events catch other tabs |
| `idb-keyval` | one record per entry | The common "just save my objects" case |
| Dexie tables | one record per row (keyed by primary key) | Dexie addon hooks `creating/updating/deleting` |
| Raw IndexedDB object stores | one record per entry | Via a wrapping `IDBObjectStore` proxy |
| OPFS / Cache API files | chunked blobs | v2 — reuses the chunking already in the format |
| `krptk.cached()` | working set local, full dataset on server | For corpora larger than browser quota — see below |

**No change-detection machinery needed.** Because each adapter exposes the
*same API as the store it wraps* — `sync.local` is `Storage`-shaped,
`sync.notes` is idb-keyval-shaped, the Dexie addon hooks Dexie's own write
events — every write goes through the adapter by construction. There is no
need to diff or poll local storage: swap the object the app writes to and
observation is automatic. Two small pieces cover the edges:

- **One-time initial import.** Data written before krptk was attached is
  reconciled once at first attach (local index vs. server key list), not
  continuously. Cheap, and it makes retrofitting an app with existing local
  data a genuine drop-in.
- **Optional global patching** for a truly scattered legacy app that writes
  `window.localStorage` in fifty places: the SDK can patch
  `Storage.prototype` so those writes are observed without touching the app.
  Reliable for `localStorage` specifically (unlike IndexedDB), and opt-in —
  patching globals in a library is otherwise rude.

If an app *does* bypass the adapter and write the underlying store directly,
those writes simply aren't synced. That's a documented constraint, not a
failure mode to engineer around.

### Cache adapter: datasets bigger than the browser

The adapters above replicate *everything* locally, which is right for notes,
settings and small collections. For a large corpus — media, long histories,
document archives — the useful inversion is **the server holds the full
dataset and the browser keeps a hot working set**. `krptk.cached()` is that
adapter, and it turns krptk into a store that isn't bounded by browser quota
at all:

```ts
const docs = krptk.cached({
  namespace: "docs",
  tiers: { sync: "2mb", local: "200mb" },   // localStorage tier, IndexedDB tier
  pin: ["settings", "recent/*"],            // always kept offline-available
});

const d = await docs.get("docs/1998-42");   // cache hit, or fetch+decrypt+cache
docs.peek("settings");                      // synchronous, L1 only — first paint
```

**Tiers**, coldest last:

| Tier | Holds | Why it exists |
|---|---|---|
| L0 memory | current page session | free, instant |
| L1 `localStorage` | a small hot set (~1–2 MB), JSON-ish | the **only synchronous** tier — readable during first paint with no `await`, which IndexedDB fundamentally cannot offer |
| L2 IndexedDB | the working set, byte-budgeted LRU | bulk capacity, blobs, structured values |
| L3 server | everything | the actual source of truth |

That L1 note is the real argument for using `localStorage` as a cache tier at
all: it's small and string-only, so it's a poor bulk cache, but it is the only
store the app can read *synchronously* at startup. Put the handful of records
the first screen needs there and the app paints instantly; everything else
lives in L2.

**How it behaves:**

- **Local index, not local data.** The `?since=` change feed already returns
  keys, versions and sizes without values — so the client maintains a complete
  local *index* of what exists while holding only a fraction of the bytes.
  Listing, searching by key, and showing a file browser all work offline over
  a dataset far larger than the device.
- **Write-through, never write-back.** Writes go to cache *and* outbox
  together; user data is never only in a volatile tier.
- **Eviction only evicts clean records.** A record with a pending write is
  never a candidate, so no local eviction can lose data. Otherwise LRU against
  the byte budget, sized against `navigator.storage.estimate()`.
- **Pinning and prefetch.** Apps pin what must be offline-available and can
  prefetch by prefix; the change feed's ordering also makes "what did my other
  device just touch" a useful prefetch signal.
- **Remote changes invalidate rather than download.** A `remote` event for an
  uncached key just updates the index — no traffic for data nobody asked for.
- **Range reads for big records.** Large values are already chunked by the
  format, so a cached read can fetch only the chunks it needs instead of the
  whole blob.

**The tradeoff, stated plainly**: cache misses fail while offline. The API is
async-only (a synchronous `Storage` facade can't await a fetch, so `peek()` is
L1-only by design), the status model gains `partial`, and reads raise a typed
`MissingWhileOffline` error the app must handle. That's the honest price of
holding a dataset larger than the browser — and it's opt-in per namespace, so
small stores keep the simple fully-replicated behavior.

### Sync engine

- **Outbox**: local writes mark records dirty in krptk's own IndexedDB store.
  The engine drains the outbox with CAS writes, retrying with backoff; nothing
  is ever lost to a failed request or a closed tab.
- **Inbox**: SSE (tab open) or a `?since=` cursor poll delivers remote
  changes; they're decrypted, written into the local store, and surfaced via
  the `remote` event so the UI re-renders.
- **Conflicts**: last-write-wins per record by default; a per-store `merge`
  hook for app-specific resolution; drop in a Yjs/Automerge document as the
  record value when you want conflict-free merging.
- **Batching**: many small records coalesce into one encrypted batch blob —
  keeps request counts, per-record overhead and quota consumption sane.
- **Status model** exposed for UI: `synced | pending | offline | conflict |
  quota-exceeded | partial | not-linked`. Ships with a tiny sync-status indicator and
  the recovery-phrase onboarding flow, since every app needs both.
- **Explicit allowlist, never "sync everything"**: apps name the prefixes,
  stores and tables to replicate, so caches and derived data don't burn user
  quota.

### Running in the service worker

Sync belongs in the **service worker**, so it happens without a focused tab:

- `sync` (Background Sync) retries a non-empty outbox once connectivity
  returns — the user can close the tab mid-write and it still lands.
- `periodicsync`, where available, opportunistically pulls remote changes so
  the app is already current when opened.
- A tab-side channel keeps open pages in step with what the SW did.

This is where non-extractable `CryptoKey`s shine: the worker reads the key
*handles* from IndexedDB and encrypts with them, while the raw seed is
available to nothing at all.

The SDK also calls `navigator.storage.persist()` — the local half of a
local-first store shouldn't be evicted by the browser under pressure.

A native Rust client (`krptk-client`) gives the same semantics outside the
browser: CLI tooling, server-side tests that hammer the sync protocol, and
Tauri desktop builds of the same apps.

## Prior art, and why not just use it

| Project | Why it doesn't quite fit |
|---|---|
| remoteStorage protocol | Right spirit (user-chosen storage, per-app scopes) but no E2E encryption in the protocol, aging ecosystem. Worth stealing its `appId`-scoping ideas. |
| PouchDB/CouchDB | Great sync, but a per-user-DB Couch is heavy to operate, and E2E must be bolted on. |
| Etebase | Closest in crypto design (E2E, self-hosted) — validate our design against it; its development has been quiet. |
| PocketBase / Supabase / Appwrite | Self-hostable app backends, but server-side data models per app and no E2E; you'd run one *per app* or share schemas — the opposite of "one dumb server for all my PWAs". |
| Solid pods | Interesting, but a much larger spec surface than needed. |
| Dexie Cloud | Closest to the syncer positioning, but it's a hosted commercial service without E2E encryption; self-hosting isn't the model. |

The niche krptk fills: **one tiny zero-knowledge server that transparently
backs up and syncs the browser storage any number of otherwise-serverless
PWAs already use.**

## Roadmap sketch

- **v0**: workspace scaffold; `krptk-format` + `krptk-crypto` with test
  vectors; server with register/auth/KV/CAS/quotas/invite codes; `krptk admin`
  CLI (no UI yet); SDK with WebCrypto key handling, outbox, and the
  `localStorage` + `idb-keyval` adapters; Helm chart and scratch image.
  Enough to ship one real PWA on it.
- **v1**: change feed + SSE, batching and chunking, service-worker sync with
  Background Sync, Dexie adapter, recovery-phrase and sync-status UI kit,
  **management UI** (dashboard, accounts, invites, app registry, settings,
  audit log), `quiesce` + scheduled scrub, snapshot/restore runbook, and
  `krptk backup`/`restore` logical archives.
- **v2 (only if needed)**: cache adapter (tiered working set + local index)
  for datasets bigger than browser quota, sharing between users (wrap a record key to another identity's public key),
  device-linking via QR, OPFS/Cache file sync, TOTP for operators,
  Postgres + S3 backend for multi-replica installs, Leptos/Dioxus admin SPA
  if the SSR UI outgrows itself.

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
5. **Admin UI exposure in k8s**: is `port-forward` to a ClusterIP Service
   enough, or does the UI need its own Ingress with a public login
   (→ TOTP earlier in the roadmap)?
6. **Show-once recovery phrase**: acceptable (the price of never persisting
   extractable key material), or do apps need PIN-protected re-display?
7. **Which adapters first?** Ordering `localStorage`, `idb-keyval`, Dexie and
   raw IndexedDB depends on what your existing PWAs actually use — worth
   listing them before v0.
8. **Cache adapter timing**: does one of your apps need the
   bigger-than-the-browser mode soon enough to pull it into v1, or is
   full replication enough for now?
9. **Storage class**: which block-backed RWO class does your cluster have?
   The chart's defaults and its refuse-RWX guard should match reality.
