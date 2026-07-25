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
- **Never holding readable content**: as the operator you must not end up in
  possession of user text or viewable images — a legal exposure question as
  much as a privacy one. This is a hard requirement, and the server enforces
  it rather than trusting clients; see
  [Never storing cleartext](#never-storing-cleartext--the-operators-position).

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
  image-sharing dump. What's left (quota exhaustion, bot signups by anonymous
  users) is handled by policy — see
  [Trust model](#trust-model-vetted-apps-anonymous-users) and
  [Abuse protection](#abuse-protection).

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

- Blobs are encrypted with **AES-256-GCM under a random per-write content
  key**, which is then wrapped by the app key:

  ```
  contentKey = random 256 bits                   # fresh on every write
  wrapped    = AES-KW(HKDF(appKey, "krptk/v1/wrap"), contentKey)
  ciphertext = AES-256-GCM(contentKey, nonce = 0, plaintext, aad = header)
  record     = header ‖ wrapped ‖ ciphertext
  ```

  A fresh key per write means the nonce never repeats under a given key, so
  it can be a constant — the classic AES-GCM nonce-reuse footgun disappears.
  The header (format version, algorithm ids, key name, record version, chunk
  info) is authenticated as AAD, so ciphertext can't be replayed under a
  different key or silently rolled back to an older version.

  **Why wrapping rather than deriving the key from the key name** — this is
  the one decision that must be right on day one. Deriving
  `HKDF(appKey, name)` is simpler, but it welds every record to the app key
  forever: sharing a single record with another user would mean handing over
  the app key, and rotating the app key would mean re-encrypting every byte
  the user owns. With a wrapped content key, sharing is *rewrapping one small
  key* to a recipient's public key, and rotation rewraps headers without
  touching content. Same cost today, and it's the difference between v2
  features being additive or being a migration.
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
specifies), `AES-GCM` for content, `AES-KW` for key wrapping, `X25519` for
rewrapping a content key to another user (the sharing path), and `Ed25519`
for identity signatures — the last two shipped in all major browsers by 2025,
with a small WASM fallback for older ones. Only the BIP39 *wordlist* mapping
is plain non-secret code.

The chain is designed so raw key bytes never need to persist: the seed is
imported as non-extractable HKDF key material, app keys are derived from it as
non-extractable, and `unwrapKey` turns a stored wrapped key into a
non-extractable content key — so no key in the chain is ever readable by
script.

**The honest tradeoffs:**

- **XChaCha20-Poly1305 is out** — WebCrypto doesn't offer it. AES-GCM with a
  fresh per-write content key is an equally sound choice, and it neutralizes
  AES-GCM's short-nonce weakness.
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

- Namespace: `user / app / key`, where key names are **required to be opaque
  fixed-length hashes** (hashed per path segment, so prefix queries still
  work) — see
  [Never storing cleartext](#never-storing-cleartext--the-operators-position).
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
POST   /v1/register                      {pubkey, appId, pow, devSig?}
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
app pools, freeze/delete accounts and apps. The admin sees sizes and
timestamps, never plaintext.

## Never storing cleartext — the operator's position

The goal here is not cryptographic: it's that **you, running this box, are
never in possession of readable user content** — no readable text, and in
particular no viewable image. That is a much easier property to guarantee than
"prove this blob is properly encrypted", and the server can enforce it
essentially completely.

*(Design guidance, not legal advice — the specifics of hosting liability are
jurisdiction-dependent and worth one conversation with a lawyer. What the
design can do is give you the levers any regime expects: no cleartext, no
ability to read, and a working takedown path.)*

### Rejecting cleartext is decidable in practice

The reason this works is that **cleartext isn't random** — and every format
that could get you in trouble is trivially recognizable:

- **Positive validation first.** A record is accepted only if it *is* a krptk
  record: magic bytes, format version, algorithm ids, wrapped-key length,
  chunk table consistency, body length matching AEAD tag overhead. This is an
  allowlist, not a blocklist — a JPEG, a PNG, an HEIC, a PDF, an MP4 or a
  plain UTF-8 string fails at the first byte. Nothing needs to be *detected*;
  everything that isn't a krptk record is rejected by default.
- **Entropy check on the body.** Ciphertext is incompressible and near-uniform.
  Sampling a few KB and rejecting anything that compresses well or fails
  chi-square costs microseconds, and catches the one remaining accident:
  someone fabricating a valid header around real content. Encrypted data
  passes this always; JPEG/PNG/text data fails it always.
- **Known-format sniffing as a tripwire**, not a gate. Cheap magic-byte
  matching against common media and document formats, purely so that a
  rejection can be *logged as "an app tried to upload a JPEG"* rather than
  "malformed record". That's the signal you actually want in the admin UI.
- **Every chunk carries its own header.** Large values are chunked, and chunk
  #7 of a photo must be a valid krptk chunk in its own right — otherwise the
  invariant would hold for records but not for the bytes actually on disk.
- **Opaque key names, enforced.** Values being encrypted isn't enough:
  `photos/2019-ibiza/nude-01.jpg` as a key name puts readable content on your
  disk. So the server requires fixed-length hashed names — hashed **per path
  segment**, so `recent/*` prefix queries, pinning and prefetch still work
  while the names carry nothing. What remains visible is shape: record counts,
  sizes, hierarchy depth, change times. Irreducible for any sync server, and
  stated here rather than glossed over.

Enforcement is a per-app flag (`require_encrypted: true`, **on by default**),
returning a hard `422`. The management UI surfaces rejection counts and the
tripwire categories, so a spike tells you immediately that some client shipped
broken.

### The server must never render what it stores

A liability-shaped detail that has nothing to do with crypto: even under the
invariant, the server should be structurally incapable of *serving* content as
media. So every blob response is `Content-Type: application/octet-stream`
regardless of anything the client claimed, plus
`Content-Disposition: attachment`, `X-Content-Type-Options: nosniff` and a
restrictive CSP. The server never stores or echoes a client-supplied content
type, and does **no image processing whatsoever** — no thumbnailing, no
dimension probing, no format conversion, because all of those require
plaintext. Combined with there being no unauthenticated read path, the service
cannot function as an image host even if something slipped past validation.

App-side, the matching rule: **thumbnails and previews are content too.** A
photo app that encrypts originals but caches plaintext thumbnails has defeated
the whole exercise. The SDK's adapters treat derived media exactly like source
media.

### A continuously verified claim, not a promise

"We never store cleartext" is worth much more if it's *checked*, so the scrub
job does double duty: alongside verifying BLAKE3 checksums, it re-validates
that **every stored record still parses as a krptk record and passes the
entropy check**. Results go to a Prometheus metric and the admin UI. That
turns the invariant from a statement about intent into a continuously audited
property of the running system — which is exactly the kind of thing that is
useful to be able to demonstrate after the fact.

Worth writing down in the repo as a short transparency note (what is stored,
what is verified, what the operator can and cannot see), since that document
is what you'd hand to anyone asking.

### What remains, and what actually protects you

- **A determined user can still store illegal material — encrypted.** They'd
  have to encrypt it, at which point you hold ciphertext, which is precisely
  the position of every E2E service. The invariant means you cannot be found
  holding a viewable file; it does not mean the underlying bytes are innocent.
- **You cannot inspect, and that is the point.** Holding no keys means you
  cannot proactively moderate — but it also means you cannot be expected to.
  What matters is that you can still *act*: freeze or delete an account or a
  record on notice, without reading anything.
- **So the takedown path is a design feature, not paperwork.** An abuse
  contact, an admin flow to freeze/purge an account, and an append-only audit
  log of those actions. The ability to respond to notice is generally what
  keeps a host in the "conduit, not publisher" position; being unable to read
  content doesn't undermine that, but being unable to *act* would.
- **Your users are the public, not your friends.** The apps are vetted; the
  people storing data in them are anonymous strangers — see
  [Trust model](#trust-model-vetted-apps-anonymous-users). So none of the
  comfort of "private store for known people" applies, and the design leans
  instead on controls that work without knowing anyone: the cleartext
  invariant, no public read path, per-app accountability with a named
  developer behind each app, and a takedown flow that works on notice.
- **Sharing changes the analysis — flag it now.** The moment user-to-user
  sharing lands, the service starts to *distribute* rather than merely store,
  which is a different legal question. So sharing stays off by default and
  enabled per app, and that milestone deserves its own review rather than
  being treated as a feature toggle.
- **Log as little as possible, deliberately.** Metadata sufficient to answer a
  lawful request (account creation time, quota usage, action audit) with short
  retention. Extensive IP logging is itself a privacy liability; the default
  should be minimal and documented.

## Trust model: vetted apps, anonymous users

Getting this boundary right changes several earlier assumptions, so it's worth
stating plainly:

- **Apps are vetted.** Their developers are people you know. Registering an
  `appId` is a deliberate act by you, the operator.
- **Users are the public.** Anyone who opens a friend's PWA can create an
  account. They're anonymous by design — no email, no password, just a
  keypair. You will never know who they are, and cannot.

So **invite codes gate apps, not users**, and the earlier "invite chain makes
users identifiable" argument does not survive: from the users' side this is a
public service, and it should be designed as one.

The awkward part is that **a PWA holds no secrets**. Anything embedded in a
client-side app — including a registration credential — is public the moment
it ships. There is therefore no way for an app to authenticate its users to
the server that a stranger could not replay. That's not a flaw to fix; it's a
constraint to design around.

The design's answer is to make the **app the unit of accountability** rather
than the user:

- Each registered app has a **pool**: total bytes, total accounts, and an
  account-creation rate. Users draw from their app's pool. If an app is
  abused or goes unexpectedly viral, the blast radius is that pool, and the
  operator has one conversation with one person they actually know.
- Every account records **which app registered it, and when** — so an abuse
  report resolves to an app, and an app resolves to a developer with a
  contact address in the registry.
- Each app has a **kill switch**: freeze registrations, freeze writes, or
  freeze the whole namespace, independently of other apps.
- An **app operator agreement** (short, plain) with each developer friend:
  they present terms to their users, they name an abuse contact, they respond
  when you forward something. This is the human half of the technical
  controls, and with anonymous end users it's the part that actually
  distributes responsibility.

**The alternative worth weighing**: if hosting anonymous members of the public
turns out to be more exposure than you want, the other model is to hand each
friend the Helm chart and let them run their own instance — you keep the
software, they keep the users. The design supports both; this is a decision
about appetite, not architecture, and it's easier to make now than after the
first app has a thousand users.

## Abuse protection

Layered, cheapest defense first:

1. **No public reads** (structural). Nothing on the server can be linked to
   or served anonymously, so the classic "free file host" abuse is impossible
   rather than merely forbidden.

2. **App gating** (invite codes, but for developers). The operator mints codes
   or simply registers `appId`s directly; unknown app or wrong origin →
   rejected. An origin check isn't a security boundary against non-browser
   clients, but it stops drive-by use of your server by strangers' apps.

3. **User registration is open but expensive.** Since apps can't authenticate
   their users, registration cost is the control:
   - **Proof of work** — a few seconds of client CPU, invisible during a
     normal onboarding, unpleasant at scale.
   - **Per-IP and per-app creation rate limits**, with the app's pool as the
     hard ceiling.
   - **Earned quota**: accounts start small (a few MB) and grow with age and
     genuine use. An abuser gets a fleet of near-useless accounts; a real
     user never notices. This is the single most effective knob, because it
     makes Sybil accounts worthless rather than merely costly.
   - **Optional developer-signed registration** for apps that *do* have a
     backend or their own invite system: the registry entry carries the
     developer's public key, and registrations must be signed by it. Not
     available to purely serverless PWAs, hence optional.

4. **Hard quotas per identity** *and* per app: bytes stored, record count,
   requests/day (token bucket). Ciphertext size is trivially accountable.
   `413`/`429` with clear errors the SDK surfaces to the app.

5. **Blob/size/rate caps**: max blob size, max keys per app, bounded request
   body handling, global connection limits — standard hygiene.

6. **Global guardrails**: a cluster-wide storage ceiling with alerting well
   before the PVC fills, since with anonymous signup total exposure is
   accounts × quota rather than a number you chose directly.

7. **Cleartext refused at the door**: not an abuse control as such, but it is
   what keeps the operator out of possession of readable content — see
   [Never storing cleartext](#never-storing-cleartext--the-operators-position).

8. **Operator tools, not surveillance**: usage dashboards, top accounts and
   top apps, freeze/purge, abuse contact and takedown flow — all
   metadata-only, all audit-logged.

**Expiry, revisited for anonymous users.** "Permanent" stays the promise for
accounts holding real data — with no email there is no way to warn anyone, so
deleting their data is not something to do casually. But anonymous public
signup produces a *lot* of junk: accounts created by a curious visitor who
never stored anything, or who cleared their browser the same day. So the
policy splits:

- **Empty accounts** (registered, never stored a record) expire after ~30
  days. No data is lost by definition, and this absorbs most of the noise.
- **Accounts with data are permanent**, unless the operator opts into a
  long-horizon policy knowingly.

That keeps the strong promise where it means something without accumulating
unbounded debris from anonymous registration.

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
  metadata: accounts, app registry and pools, quotas, versions, cursors,
  audit log.
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
  scrub (which also re-validates the cleartext invariant), a `quiesce` command so the volume can be snapshotted cleanly, and
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
  confirmation. With anonymous users there is nothing else to search *by* —
  no names, no emails, by design.
- **Apps**: register `appId`s, their developer contact, CORS origins, and
  **pools** (total bytes, account count, creation rate) with live consumption
  against each — plus the per-app kill switch (freeze registrations, freeze
  writes, freeze everything).
- **Accounts by provenance**: which app registered an account and when, so an
  abuse report resolves to an app and then to a person you can call.
- **Settings**: PoW difficulty, earned-quota curve, per-IP and per-app
  creation limits, size and rate limits, global storage ceiling — the knobs
  from [Abuse protection](#abuse-protection).
- **Abuse handling**: notice intake, per-account and per-record freeze and
  purge, and the resulting audit entries — the operator-facing half of
  [never storing cleartext](#never-storing-cleartext--the-operators-position).
- **Invariant health**: cleartext-rejection counts by category, last clean
  scrub, snapshot age — the numbers that back the transparency note.
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

## What must be designed now vs. built now

"Why not just build the whole thing?" is the right question to ask of any
phased plan, and the answer isn't the same for every part. The distinction
that matters is **format vs. code**:

- Anything that touches the **wire format, crypto format, key names, or the
  server's data model is designed and specified in full now**, even where it
  isn't implemented. Retrofitting these means migrating users' encrypted data
  — the one migration a zero-knowledge store handles badly, because the
  server can't rewrite anything on the users' behalf. Every client would have
  to re-upload everything it owns, from a device that still has the keys.
- Anything **additive in code** — another adapter, another admin screen —
  can wait, because adding it later costs the same as adding it now.

Concretely, these must be right in the v1 format, and are:

| Decision | Why it can't be retrofitted |
|---|---|
| Wrapped random content keys | Sharing and key rotation are impossible if keys are derived from the app key — see [Identity and keys](#identity-and-keys) |
| Record header: format version + algorithm ids | Without a version byte there is no way to *ever* change anything else |
| Opaque hashed key names, hashed per segment | Key names are chosen at write time; changing the scheme renames every record |
| Chunking layout for large values | Determines whether range reads and the cache adapter are possible at all |
| Change feed returning key + version + size | The cache adapter's local index is built from this; adding fields later is fine, changing semantics is not |
| Tombstones and cursor semantics | Convergence rules can't change under live clients |
| One PVC holding database + blobs | A snapshot-atomicity requirement, not a preference |

Note what that table implies: the cache adapter and user-to-user sharing are
*late implementation items but early format items*. They're in the format
from day one precisely so they can be added later without a migration.

The reason not to implement everything before shipping is not caution about
scope — it's that a design like this is validated by one real PWA running on
it. Adapters built before any app needs them are guesses; the change feed's
ergonomics only become clear once a second device is syncing. So:

- **Milestone 1 — format frozen, thin vertical slice.** `krptk-format` and
  `krptk-crypto` complete with test vectors; server with
  register/auth/KV/CAS, per-app pools and earned quota, PoW registration, the
  cleartext-refusal invariant
  (positive validation, entropy check, opaque key names, no-render response
  headers); `krptk admin` CLI; SDK with WebCrypto key handling, outbox, and the
  `localStorage` + `idb-keyval` adapters; Helm chart and scratch image.
  One of your PWAs runs on it for real.
- **Milestone 2 — make it operable and pleasant.** Change feed + SSE,
  batching and chunking, service-worker background sync, Dexie adapter,
  recovery-phrase and sync-status UI kit, management UI, `quiesce` +
  scheduled scrub (checksums *and* cleartext-invariant re-validation),
  snapshot/restore runbook, logical `backup`/`restore`, transparency note.
- **Milestone 3 — the capabilities the format already anticipates.** Cache
  adapter with local index, user-to-user sharing by rewrapping content keys
  (off by default, per-app, and deserving its own liability review since it
  turns storage into distribution),
  QR device linking, OPFS/Cache file sync, TOTP for operators, and — only if
  a real install demands it — the Postgres + S3 multi-replica backend.

If a milestone-3 item turns out to be needed sooner, pulling it forward is
just work, not redesign. That's the whole point of freezing the format first.

## Open questions

1. **Hosting the public, or not**: are you comfortable being the operator of
   record for anonymous users of your friends' apps, or would you rather ship
   each friend their own instance? This is the biggest open question in the
   document and everything about exposure follows from it — see
   [Trust model](#trust-model-vetted-apps-anonymous-users).
2. **Key custody UX**: is a mandatory recovery phrase acceptable, or do some
   apps need an easier (weaker) mode, e.g. passphrase-encrypted seed stored
   server-side? That reintroduces password UX and weakens zero-knowledge —
   my recommendation is to keep the phrase and invest in the save-the-phrase
   flow, but it's a real product decision.
3. **CRDT in the box?** Should the SDK bundle Yjs helpers, or stay
   merge-agnostic and document the pattern?
4. **Earned-quota curve**: what do accounts start with and how fast does it
   grow? Too tight annoys real users on day one; too loose makes Sybil
   accounts worth creating. Needs a number, not a principle.
5. **Admin UI exposure in k8s**: is `port-forward` to a ClusterIP Service
   enough, or does the UI need its own Ingress with a public login
   (→ TOTP earlier in the roadmap)?
6. **Show-once recovery phrase**: acceptable (the price of never persisting
   extractable key material), or do apps need PIN-protected re-display?
7. **Which adapters first?** Ordering `localStorage`, `idb-keyval`, Dexie and
   raw IndexedDB depends on what your existing PWAs actually use — worth
   listing them before milestone 1.
8. **Cache adapter timing**: it's in the format from day one either way —
   does one of your apps need the bigger-than-the-browser mode implemented
   early, or is full replication enough to start?
9. **Storage class**: which block-backed RWO class does your cluster have?
   The chart's defaults and its refuse-RWX guard should match reality.
10. **Sharing between users**: the format supports it (rewrap a content key to
    a recipient's X25519 key), but the *UX* — how one user names another
    without the server holding an address book — is unsolved, and it's worth
    deciding before it gets built rather than after.
11. **Legal review, once** — and now clearly needed, since the users are the
    general public rather than people you know: the cleartext invariant, the
    takedown flow, the app operator agreement and the transparency note are
    the design's answer to operator exposure, but the specifics (Swiss
    hosting-provider duties, expected retention, what an abuse contact must
    look like, whether the developer or you is the data controller) want a
    lawyer's read before the service holds strangers' data. Worth doing
    before milestone 1 ships publicly, not after.
12. **Management UI also needs an abuse workflow**, not just quotas: notice
    intake, freeze, purge, and the audit trail as first-class screens. Should
    that be in milestone 2 with the rest of the UI, or earlier?
