# krptk — encrypted per-user storage for PWAs

*Design draft, 2026-07-26*

krptk gives a PWA a place to keep per-user data that survives the browser —
cleared site data, a new device, a lost phone — without the app growing a
backend. One small server, shared by any number of apps, storing only
ciphertext it cannot read.

Three objectives drive every decision in this document. Where they conflict,
they are ranked in this order:

1. **Encrypted per-user storage that a PWA can adopt in a few lines.**
   The data is unreadable to the server; adoption cost is near zero.
2. **Low liability for the operator, and lawful data handling.**
   The operator is never in possession of readable user content, holds no
   personal data in the data plane, and can act on notice.
3. **A path to charging** — app owners for their pool, end users for their
   own space — without redesigning anything.

Objective 3 is new to this draft and it is not merely additive: it forces
usage metering and entitlement-based quota into v1, and it settles the
question of whether the operator hosts the public at all. See
[Objective 3](#objective-3-a-path-to-charging).

Supporting documents, split out to keep this one readable:

- [SDK.md](SDK.md) — adapters, the cache adapter, sync engine internals.
- [DEPLOYMENT.md](DEPLOYMENT.md) — Kubernetes, storage, backup and restore,
  management UI, operator runbooks.

---

# Objective 1: encrypted storage a PWA can adopt in a few lines

## Core idea

**A background replicator for browser storage, backed by one dumb server.**
Apps keep using `localStorage`/IndexedDB as they do today; krptk mirrors that
storage — encrypted client-side — to a server that only stores opaque
ciphertext keyed by `(user, app, record-key)`.

```
 ┌──────────────── browser ────────────────┐      ┌──── your k8s cluster ────┐
 │ PWA code                                │      │                          │
 │   ↕ (unchanged reads/writes)            │      │  krptk (single binary)   │
 │ localStorage · IndexedDB · Dexie        │      │  auth · quotas · metering│
 │   ↕ adapters observe + apply            │      │  versioned KV + CAS      │
 │ krptk SDK — WebCrypto, outbox           │◄────►│  admin UI                │
 │ service worker: background sync ────────┼HTTPS─┤  SQLite + blob dir (PVC) │
 └─────────────────────────────────────────┘ +SSE └──────────────────────────┘
```

Keeping the server ignorant does three jobs at once:

- The server codebase stays tiny — a versioned key-value store with quotas,
  auth and usage accounting, nothing app-specific. New PWA = new `appId`,
  zero server changes.
- Operator liability drops: the operator *cannot* read user data, so there is
  little worth stealing on the box (objective 2).
- The largest abuse vector disappears structurally: there are **no public,
  unauthenticated reads**. Data is fetchable only by the identity that wrote
  it, so the service is useless as a malware CDN, piracy host or image dump.

## The positioning: not another storage API

krptk is not "an API to port your app to" — it is a replicator for the
storage the PWA already uses. Each adapter exposes **the same API as the store
it replaces**, so the app points at the adapter object instead of the global
and keeps reading and writing exactly as before:

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

Three consequences, and they are the reason for this framing: retrofitting an
existing app is a few lines rather than a rewrite; the app is **local-first**
by construction, since reads and writes never wait on the network; and the app
keeps working unchanged if krptk is absent or the user never signs up — sync
is an optional feature, not a dependency.

Adapters cover `localStorage`, `idb-keyval`, Dexie tables, raw IndexedDB, and
(later) OPFS files, plus a cache adapter for datasets larger than the browser
allows. Details in [SDK.md](SDK.md).

## Identity and keys

No emails, no passwords, no server-side password database.

- A user's identity **is** an Ed25519 keypair, generated in the browser on
  first use and kept in IndexedDB.
- Everything derives from one root secret, presented as a **12-word recovery
  phrase** (BIP39 wordlist):

  ```
  seed        = bip39(phrase)
  identityKey = HKDF(seed, "krptk/v1/identity")          # Ed25519, one per user
  appKey(app) = HKDF(seed, "krptk/v1/app/" + appId)      # symmetric, one per app
  ```

- Blobs are encrypted with **AES-256-GCM under a random per-write content
  key**, wrapped by the app key:

  ```
  contentKey = random 256 bits                   # fresh on every write
  wrapped    = AES-KW(HKDF(appKey, "krptk/v1/wrap"), contentKey)
  ciphertext = AES-256-GCM(contentKey, nonce = 0, plaintext, aad = header)
  record     = header ‖ wrapped ‖ ciphertext
  ```

  A fresh key per write means the nonce never repeats under a given key, so it
  can be a constant — the AES-GCM nonce-reuse footgun disappears. The header
  (format version, algorithm ids, key name, record version, chunk info) is
  authenticated as AAD, so ciphertext cannot be replayed under a different key
  or rolled back to an older version.

- The server only ever sees the **public** identity key, and identifies a user
  as `userId = base58(sha256(pubkey))`.

**Why wrapping rather than deriving the key from the key name** — the one
decision that must be right on day one. Deriving `HKDF(appKey, name)` is
simpler but welds every record to the app key forever: sharing one record
would mean handing over the app key, and rotating the app key would mean
re-encrypting every byte the user owns. With a wrapped content key, sharing is
rewrapping one small key to a recipient's public key, and rotation rewraps
headers without touching content. Same cost today; the difference between v2
features being additive and being a migration.

**Per-app isolation for free**: each app gets its own derived key, so one
compromised PWA can only decrypt its own namespace even though all apps share
one identity and one server account.

**New device / recovery**: type the 12 words → same keys → same data. That is
the whole story, and it is why "permanent" is honest — the operator cannot
reset a phrase, but also cannot lose one. QR device-linking (seed transferred
over an ephemeral encrypted channel) can come later.

**The downside**: lose the phrase and the browser profile → the data is gone.
The SDK ships a "save your recovery phrase" onboarding flow because every app
needs one.

## Crypto: WebCrypto in the browser, Rust natively

The browser data path uses **WebCrypto (`SubtleCrypto`)**, not crypto compiled
to WASM, for one dominant reason and two supporting ones:

1. **Non-extractable keys.** A derived `CryptoKey` marked non-extractable can
   be used but never read — and `CryptoKey` objects are structured-cloneable,
   so they can be stored in IndexedDB directly. Key material never exists as
   JS-reachable bytes, so an XSS bug in a PWA cannot exfiltrate the user's
   keys. With WASM the key sits in linear memory, a `Uint8Array` away from any
   script on the page.
2. **Speed** — AES-GCM through native AES-NI code, roughly an order of
   magnitude faster than a WASM stream cipher on large blobs, off the JS heap.
3. **Bundle size** — zero bytes for the primitives.

Everything needed is available: `HKDF`, `PBKDF2`+SHA-512 for the BIP39 seed
step, `AES-GCM`, `AES-KW`, `X25519` for rewrapping to another user, `Ed25519`
for identity signatures. The chain is designed so raw key bytes never persist:
the seed imports as non-extractable HKDF material, app keys derive
non-extractable, and `unwrapKey` yields a non-extractable content key.

Two accepted costs:

- **XChaCha20-Poly1305 is out** — WebCrypto doesn't offer it. AES-GCM with a
  fresh per-write key is equally sound and neutralizes the short-nonce
  weakness.
- **The recovery phrase becomes show-once.** A seed never persisted in
  extractable form cannot be re-displayed. Default to show-once with a solid
  onboarding flow; offer PIN-protected re-display as an SDK option.

Per-call WebCrypto overhead makes thousands of tiny records overhead-bound
rather than cipher-bound; the SDK batches small records into one encrypted
blob, which it wants to do for request counts and quota anyway.

## Auth flow

Signed challenge, then a cheap bearer token for the hot path:

1. `POST /v1/auth/challenge` → random nonce.
2. Client signs `nonce ‖ serverOrigin` with the identity key,
   `POST /v1/auth/token` → short-lived (≈1 h) opaque bearer token.
3. Data requests carry `Authorization: Bearer …`; the SDK refreshes
   transparently.

Binding the server origin into the signature stops a hostile server replaying
a login against another krptk instance.

## Data model and sync

The primitive is a **versioned KV store with compare-and-swap and a change
feed** — deliberately *not* a sync engine, so the server stays generic:

- Namespace `user / app / key`, where key names are **required to be opaque
  fixed-length hashes**, hashed per path segment so prefix queries still work
  (see [the cleartext invariant](#the-invariant-no-cleartext-ever)).
- Every record has a monotonically increasing per-`(user,app)` **revision**.
- Writes are CAS: `PUT … If-Version: N` returns `409` if another device wrote
  in between. The client reads, merges, retries.
- `GET /kv?since=<cursor>` returns everything changed after a cursor — the
  pull half of sync — and returns key, version and size without values, which
  is what lets a client hold a full index of a dataset it hasn't downloaded.
  An SSE endpoint pushes "something changed" pokes.
- Deletes write tombstones (kept ~30 days) so offline devices converge.

Merging is the app's problem by design, and a solved one: store a **Yjs or
Automerge document per record** and merging on CAS conflict is conflict-free;
last-write-wins per key is fine for simple cases. The SDK offers both; the
server knows about neither.

Blob size is capped (default 4 MB); larger values are chunked client-side.

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

GET    /v1/account                       → usage, quota, entitlements, notices
POST   /v1/account/billing-session       (signed) → PSP portal/checkout URL
DELETE /v1/account                       (signed; full erasure)
```

Admin endpoints live on a separate listener and back the management UI: list
accounts by usage, adjust quotas, mint app pools, freeze or delete accounts
and apps. The admin sees sizes and timestamps, never plaintext. See
[DEPLOYMENT.md](DEPLOYMENT.md).

---

# Objective 2: low operator liability, lawful data handling

The operator hosts anonymous members of the public who use other people's
apps. Everything in this section follows from that, and none of the comfort of
"a private store for people I know" applies.

*(Design guidance, not legal advice. What the design can do is provide the
levers any regime expects: no cleartext, no ability to read, no personal data
at rest, and a working takedown path. One legal review is still required —
see [Open questions](#open-questions).)*

## The invariant: no cleartext, ever

The goal is not cryptographic. It is that **the operator is never in
possession of readable user content** — no readable text and in particular no
viewable image. That is far easier to guarantee than "prove this blob is
properly encrypted", and the server enforces it rather than trusting clients.

It is decidable in practice because cleartext isn't random:

- **Positive validation.** A record is accepted only if it *is* a krptk
  record: magic bytes, format version, algorithm ids, wrapped-key length,
  chunk-table consistency, body length matching AEAD tag overhead. An
  allowlist, not a blocklist — a JPEG, PNG, HEIC, PDF, MP4 or UTF-8 string
  fails at the first byte. Nothing must be *detected*; everything that isn't a
  krptk record is rejected by default.
- **Entropy check on the body.** Ciphertext is incompressible and
  near-uniform. Sampling a few KB and rejecting anything that compresses well
  or fails chi-square costs microseconds and catches the one remaining case:
  a valid header fabricated around real content.
- **Every chunk carries its own header**, so chunk #7 of a photo must be a
  valid krptk chunk in its own right — otherwise the invariant holds for
  records but not for the bytes on disk.
- **Opaque key names, enforced.** `photos/2019-ibiza/nude-01.jpg` as a key
  name puts readable content on disk even if values are encrypted. Names are
  fixed-length hashes, hashed per path segment so `recent/*` queries, pinning
  and prefetch still work. What remains visible is shape: record counts,
  sizes, hierarchy depth, change times — irreducible for any sync server.
- **Format sniffing as a tripwire, not a gate.** Cheap magic-byte matching
  purely so a rejection logs as "an app tried to upload a JPEG" rather than
  "malformed record". That is the signal the admin UI needs.

Enforcement is a per-app flag (`require_encrypted`, **on by default**)
returning `422`.

**The server must also never render what it stores.** Every blob response is
`Content-Type: application/octet-stream` regardless of what any client
claimed, plus `Content-Disposition: attachment`, `X-Content-Type-Options:
nosniff` and a restrictive CSP. The server never stores or echoes a
client-supplied content type and does **no image processing whatsoever** — no
thumbnailing, no dimension probing, no conversion, all of which require
plaintext. With no unauthenticated read path, the service cannot function as
an image host even if something slipped past validation. App-side, the
matching rule: **thumbnails and previews are content too**, and the SDK's
adapters treat derived media exactly like source media.

**Continuously verified, not promised.** The scrub job re-validates that every
stored record still parses as a krptk record and passes the entropy check,
alongside verifying BLAKE3 checksums. Results go to a Prometheus metric and
the admin UI, which turns the invariant from a statement of intent into an
audited property of the running system — the useful thing to be able to
demonstrate after the fact. A short transparency note in the repo (what is
stored, what is verified, what the operator can and cannot see) is what you
hand to anyone who asks.

## No personal data in the data plane

By decision, the storage service holds **no name, no email address, no
contactable identifier of any kind**. An account is a public key, a byte
count, and timestamps. This is what keeps volume snapshots and offsite copies
boring, keeps erasure a row delete, and keeps the transparency note short.

Two consequences to design around rather than discover:

- **There is no channel to users.** Operator-to-user messages ride the API:
  `/v1/account` carries a `notices` list (quota nearly full, app frozen,
  entitlement lapsed, planned maintenance, "you still haven't confirmed you
  saved your recovery phrase"), the SDK exposes it, the app shows it on next
  open. Unsuitable for anything urgent or for reaching someone who never
  returns — but those are the cases where holding an address wouldn't have
  helped much either.
- **Payment is the one place identity appears**, and it is held by the payment
  provider, never by krptk. See
  [entitlements, not customers](#entitlements-not-customers).

**Log as little as possible, deliberately.** Metadata sufficient to answer a
lawful request (account creation time, usage history, action audit) with short
retention. Extensive IP logging is itself a privacy liability.

Earlier drafts included optional email enrollment — an address verified once,
discarded, and reduced to a peppered per-app HMAC handle — to buy Sybil
resistance as a quota tier. **That is now recommended for deletion**: it buys
uniqueness, a paid tier buys uniqueness better (see
[what payment replaces](#what-payment-replaces)), and it costs SMTP, a pepper
outside the volume, lazy pepper rotation, pseudonymous-personal-data scope
under data-protection law, and an onboarding step. The construction is
recorded in [DEPLOYMENT.md](DEPLOYMENT.md#appendix-email-enrollment-not-recommended)
in case a specific app ever needs it.

## Who is responsible for what

Charging changes this, which is why it belongs here rather than in a legal
appendix. Two arrangements, and they are not the same paperwork:

- **App owner pays** (the primary model). The app developer is the data
  **controller**; krptk is their **processor**. This needs one processing
  agreement per app owner, a sub-processor disclosure (hosting, payment
  provider), and data subject requests arriving through the developer, who is
  the one with a user relationship. Liability is contractual and bounded, and
  the number of controller relationships equals the number of developers you
  have contracts with.
- **End user pays krptk directly** (per-app opt-in). krptk becomes a
  controller for that billing and account relationship, even while remaining a
  blind store for the content. That means an information notice to the user, a
  direct data subject request path, and consumer contract terms.

Recommendation: **make app-owner billing primary and end-user billing an
app-level opt-in.** It keeps controller relationships at "people I have
contracts with" rather than "the anonymous public", which is the single
largest lever on objective 2 that objective 3 touches.

The **app operator agreement** (short, plain) is the human half of the
technical controls: developers present terms to their users, name an abuse
contact, and respond when something is forwarded. With anonymous end users,
this is what actually distributes responsibility.

## Trust model: vetted apps, anonymous users

- **Apps are vetted.** Their developers are people you know; registering an
  `appId` is a deliberate act by the operator.
- **Users are the public.** Anyone who opens a friend's PWA can create an
  account, anonymously by design. You will never know who they are.

So **invite codes gate apps, not users**. The awkward part is that **a PWA
holds no secrets**: anything embedded in a client-side app is public the moment
it ships, so no app can authenticate its users to the server in a way a
stranger couldn't replay. That is a constraint to design around, not a flaw to
fix, and the answer is to make the **app the unit of accountability**:

- Each app has a **pool** — total bytes, total accounts, account-creation
  rate. Users draw from their app's pool, so an abused or unexpectedly viral
  app has a blast radius of one pool and the operator has one conversation
  with one person they know.
- Every account records **which app registered it, and when**, so an abuse
  report resolves to an app and an app resolves to a named developer.
- Each app has a **kill switch**: freeze registrations, freeze writes, or
  freeze the whole namespace, independently of other apps.

The alternative — hand each friend the Helm chart and let them run their own
instance — is no longer open if the operator intends to charge for storage.
You cannot bill for bytes you don't hold. Objective 3 settles this: **the
operator hosts.**

## What remains

- **A determined user can still store illegal material — encrypted.** Then the
  operator holds ciphertext, which is the position of every E2E service. The
  invariant means you cannot be found holding a viewable file; it does not mean
  the bytes are innocent.
- **You cannot inspect, and that is the point.** Holding no keys means you
  cannot proactively moderate — and cannot be expected to. What matters is
  that you can still *act*: freeze or purge an account or a record on notice,
  without reading anything.
- **The takedown path is therefore a design feature**, not paperwork: an abuse
  contact, an admin flow to freeze and purge, and an append-only audit log of
  those actions. Being unable to read content generally doesn't undermine the
  conduit position; being unable to *act* would.
- **Sharing changes the analysis.** The moment user-to-user sharing lands the
  service begins to *distribute* rather than merely store, which is a
  different legal question. Sharing stays off by default, enabled per app, and
  that milestone gets its own review.

---

# Objective 3: a path to charging

Nothing here needs to be built for v1. Two things need to be *true* in v1, or
introducing a paid tier later means guessing at history and migrating policy
scattered through the codebase.

## Two customers

- **App owners** buy a pool: bytes and accounts for their app's users. A small
  number of billing relationships with people you know, no consumer checkout,
  and the party who actually benefits from their users having space. This is
  the natural first revenue and the preferred posture (see
  [who is responsible for what](#who-is-responsible-for-what)).
- **End users** buy their own quota. Many small relationships, consumer
  checkout inside a PWA that holds no secrets, and a heavier
  data-protection posture. Enabled per app, not globally.

Both are the same mechanism underneath.

## Entitlements, not customers

The server stores entitlements. It does not store customers.

```
entitlement: (subject, bytes, records, expires_at, source_ref)
  subject     = userId | appId
  source_ref  = opaque payment-provider reference — no name, no email, no address
```

All identity, invoicing, VAT, dunning, receipts, SCA and chargebacks live at
the payment provider, which already solves them and is already a processor for
that data. krptk never sees a card, a name or an address. Its only job is: on
a provider webhook, set or extend an entitlement; when one lapses, fall back
to the free tier. A user reaches the provider's hosted portal through
`POST /v1/account/billing-session`, authorized by a signature from their
identity key — so even the "manage my subscription" path needs no stored
identifier.

The boring-snapshot property therefore survives paid accounts: a leaked
database yields opaque user ids and byte counts, not customers.

**Be honest about what this does and doesn't hide.** A payment is a link
between a person and a `userId`. It exists — at the provider, not in krptk.
The transparency note must say that plainly rather than claiming the operator
knows nothing about anyone once money changes hands.

**Payment is never authentication and never key recovery.** This is the same
rule that governed email enrollment, generalized. A paying customer who loses
their recovery phrase has lost their data and must cancel at the provider;
there is no path from a payment relationship to a decryption key. Any such
path would be an authentication backdoor with a receipt attached.

## What must be true in v1

**Usage metering, because it cannot be reconstructed.** Billing on storage
means billing on bytes over time, and today's row cannot tell you last month's
peak. So v1 samples usage per `(user, app)` and per app pool on a schedule and
keeps a rolled-up history — daily peak and mean bytes, record counts, request
counts — retained around 13 months. Metadata-only, cheap, and the difference
between introducing a paid tier and guessing at one. The billing unit should
be **GB-month per subject**, because that is what the meter records.

**Quota as a computed entitlement, never a constant.**

```
effective_quota(user, app) = free_tier
                           + Σ active entitlements(user)
                           + Σ allocation from app pool
                           + operator override
```

If v1 hardcodes tier numbers, every later tier is a migration of policy
through the codebase. This is a data-model decision, so it is in the
[freeze table](#what-must-be-right-now).

**A stated lapse behavior, because there is no way to warn anyone.**
"Permanent until the user deletes it" cannot silently mean "permanent while
someone keeps paying". On lapse the account goes **read-only, not deleted**:
writes are refused, reads and export keep working indefinitely, and an in-app
notice explains it. Deleting the paid-for data of someone you cannot contact
is precisely the thing to avoid; storage is cheap and the reputational cost is
not. If cost ever forces deletion, it needs a long, announced, in-app-notified
path — and that policy belongs in the terms from day one rather than being
invented under pressure.

**Nothing in the crypto format changes.** Checkout links and webhooks touch no
record header, no key name, no chunk layout. That is exactly why billing can
be deferred safely — as long as metering and entitlements exist.

## What payment replaces

A paid tier is stronger Sybil resistance than proof of work, an earned-quota
curve and email verification put together: an abuser who must pay for space is
a customer. So the free tier stays deliberately small, and the abuse controls
below become tuning rather than load-bearing defense. This is what justifies
demoting email enrollment out of the design entirely.

## Abuse protection, in the meantime

Layered, cheapest first, and mostly structural:

1. **No public reads.** Nothing can be linked to or served anonymously, so
   "free file host" abuse is impossible rather than forbidden.
2. **App gating.** The operator registers `appId`s; unknown app or wrong
   origin is rejected. An origin check is not a boundary against non-browser
   clients, but it stops drive-by use by strangers' apps.
3. **Registration is open but expensive** — proof of work (a few seconds of
   client CPU, invisible in onboarding, unpleasant at scale), per-IP and
   per-app creation rate limits with the app's pool as the hard ceiling, and a
   **small free tier** that grows modestly with age and genuine use. Optional
   developer-signed registration for apps that do have a backend.
4. **Hard quotas per identity and per app**: bytes, record count, requests/day
   (token bucket). Ciphertext size is trivially accountable. `413`/`429` with
   clear errors the SDK surfaces.
5. **Size and rate caps**: max blob size, max keys per app, bounded request
   bodies, global connection limits.
6. **A global storage ceiling** with alerting well before the volume fills,
   since with anonymous signup total exposure is accounts × quota.
7. **Operator tools, not surveillance**: usage dashboards, top accounts and
   apps, freeze and purge, abuse contact and takedown flow — metadata-only,
   audit-logged.

**Expiry.** Anonymous signup produces junk: accounts created by a curious
visitor who never stored anything. So **empty accounts** (registered, never
stored a record) expire after ~30 days — no data is lost by definition, and
this absorbs most of the noise. **Accounts with data are permanent**: with no
address on file there is no way to warn anyone, and a policy you cannot
announce is not a policy you should have. Paid accounts that lapse go
read-only, as above.

---

# Implementation

The server, CLI, admin UI and native client are Rust. Note what the WebCrypto
decision implies: **the server performs no content crypto at all**. It
verifies Ed25519 login signatures and otherwise moves opaque bytes. So the
crypto format is a *spec*, not a shared implementation, with two
implementations — WebCrypto in the browser, RustCrypto natively — held
together by cross-implementation test vectors in CI. A deliberate, contained
duplication: a few hundred lines of well-tested primitives against a written
format.

```
krptk/                        # cargo workspace
  crates/
    krptk-format/  # wire + crypto format: derivation labels, header layout,
                   #   chunking rules, CAS/sync types, test vectors
    krptk-crypto/  # native impl of the format (aes-gcm, hkdf, ed25519-dalek)
    krptk-server/  # axum service: API + embedded admin UI + subcommands
    krptk-client/  # native client (CLI, tests, Tauri) over format + crypto
  sdk/             # @krptk/client — TS, WebCrypto, IndexedDB, sync engine
```

WASM is optional rather than load-bearing (a small Ed25519 fallback for older
browsers), which keeps the SDK to a few tens of KB.

**Server shape**: axum + tokio + tower, with rate limits and body limits as
tower layers. SQLite via sqlx in WAL mode for all metadata — accounts, app
registry and pools, entitlements, usage history, versions, cursors, audit log.
Blobs ≤ ~64 KB inline; larger ones as files in a content-addressed directory
(BLAKE3 names double as checksums). Database and blob directory **must share
one volume** so snapshots are atomic across both. One binary with subcommands
(`serve`, `admin …`, `backup`/`restore`, `scrub`, `quiesce`), static musl
build, `FROM scratch` image. Deployment, durability and backup detail in
[DEPLOYMENT.md](DEPLOYMENT.md).

## What must be right now

The distinction that matters is **format versus code**. Anything touching the
wire format, crypto format, key names, or the server's data model is specified
in full now, even where it isn't implemented — retrofitting these means
migrating users' encrypted data, the one migration a zero-knowledge store
handles badly, because the server cannot rewrite anything on the users'
behalf. Every client would have to re-upload everything it owns from a device
that still has the keys. Anything additive in code — another adapter, another
admin screen — can wait, because adding it later costs the same.

| Decision | Why it can't be retrofitted |
|---|---|
| Wrapped random content keys | Sharing and key rotation are impossible if keys derive from the app key |
| Record header: format version + algorithm ids | Without a version byte, nothing else can ever change |
| Opaque hashed key names, hashed per segment | Names are chosen at write time; changing the scheme renames every record |
| Chunking layout for large values | Determines whether range reads and the cache adapter are possible at all |
| Change feed returning key + version + size | The cache adapter's index is built from this; adding fields is fine, changing semantics is not |
| Tombstones and cursor semantics | Convergence rules can't change under live clients |
| **Usage metering and its retention** | Byte-hours cannot be reconstructed after the fact; a paid tier needs history that starts before the tier does |
| **Quota as a computed entitlement** | Hardcoded tiers scatter policy through the code and make every later tier a migration |
| One volume holding database + blobs | A snapshot-atomicity requirement, not a preference |

The cache adapter and user-to-user sharing are *late implementation items but
early format items* — in the format from day one precisely so they can be
added later without a migration. Billing is the same shape: late code, early
data model.

The reason not to implement everything before shipping is not caution about
scope — a design like this is validated by one real PWA running on it.
Adapters built before an app needs them are guesses, and the change feed's
ergonomics only become clear once a second device syncs.

- **Milestone 1 — format frozen, thin vertical slice.** `krptk-format` and
  `krptk-crypto` complete with test vectors; server with register / auth /
  KV / CAS, per-app pools, entitlement-computed quota, usage metering, PoW
  registration, and the cleartext invariant (positive validation, entropy
  check, opaque key names, no-render response headers); `krptk admin` CLI; SDK
  with WebCrypto key handling, outbox, and the `localStorage` + `idb-keyval`
  adapters; Helm chart and scratch image. One of your PWAs runs on it for
  real.
- **Milestone 2 — operable and pleasant.** Change feed + SSE, batching and
  chunking, service-worker background sync, Dexie adapter, recovery-phrase and
  sync-status UI kit, management UI including the abuse workflow (notice
  intake, freeze, purge, audit) and usage/entitlement screens, `quiesce` and
  scheduled scrub, snapshot/restore runbook, logical backup/restore,
  transparency note.
- **Milestone 3 — billing, and what the format anticipates.** Payment provider
  integration (checkout, webhooks, entitlements, billing portal sessions,
  lapse-to-read-only), app operator agreements; cache adapter with local
  index; user-to-user sharing by rewrapping content keys (off by default, per
  app, with its own liability review since it turns storage into
  distribution); QR device linking; OPFS file sync; TOTP for operators; and
  only if a real install demands it, the Postgres + S3 multi-replica backend.

Pulling a milestone-3 item forward is work, not redesign. That is the point of
freezing the format first.

## Prior art

| Project | Why it doesn't quite fit |
|---|---|
| remoteStorage protocol | Right spirit (user-chosen storage, per-app scopes) but no E2E encryption in the protocol, aging ecosystem. Worth stealing its `appId`-scoping ideas. |
| PouchDB/CouchDB | Great sync, but a per-user-DB Couch is heavy to operate and E2E must be bolted on. |
| Etebase | Closest in crypto design (E2E, self-hosted) — validate against it; development has been quiet. |
| PocketBase / Supabase / Appwrite | Self-hostable app backends, but server-side data models per app and no E2E; you'd run one *per app*. |
| Solid pods | Interesting, but a much larger spec surface than needed. |
| Dexie Cloud | Closest to the syncer positioning, but hosted, commercial, and without E2E; self-hosting isn't the model. |

The niche: **one tiny zero-knowledge server that transparently backs up and
syncs the browser storage any number of otherwise-serverless PWAs already
use** — and can bill for it.

---

## Open questions

Ordered by how much they block. The earlier "host the public or ship each
friend an instance?" question is closed by objective 3: the operator hosts.

1. **Legal review, once, before strangers' data lands.** The users are the
   general public, and the operator intends to take money. The cleartext
   invariant, the takedown flow, the app operator agreement and the
   transparency note are the design's answer to exposure, but the specifics
   want a lawyer: Swiss hosting-provider duties, expected retention, what an
   abuse contact must look like, and above all **whether the developer or the
   operator is the controller** in each billing arrangement (see
   [who is responsible for what](#who-is-responsible-for-what)). Blocks
   milestone 1 shipping publicly, not milestone 1.
2. **Free-tier and entitlement numbers.** What does a free account get, how
   much does a paid GB-month cost, and what does an app pool cost? Too tight
   annoys real users on day one; too loose makes Sybil accounts worth
   creating. Needs numbers, not principles — but only the *free* number blocks
   milestone 1.
3. **Is app-owner billing enough?** If yes, end-user checkout, consumer terms
   and the second controller relationship never need to exist. This is a
   product decision that removes real complexity if it goes the easy way.
4. **Key custody UX.** Is a mandatory recovery phrase acceptable, or do some
   apps need an easier, weaker mode (passphrase-encrypted seed stored
   server-side)? That reintroduces password UX and weakens zero-knowledge; the
   recommendation is to keep the phrase and invest in the save-the-phrase
   flow. Related: is show-once acceptable, or is PIN-protected re-display
   needed?
5. **Which adapters first**, and does any app need the cache adapter early?
   Depends on what your existing PWAs actually use — worth listing them before
   milestone 1. The format supports the cache adapter either way.
6. **Sharing UX.** The format supports rewrapping a content key to a
   recipient's X25519 key, but how one user names another without the server
   holding an address book is unsolved. Worth deciding before it is built.
7. **CRDT in the box?** Should the SDK bundle Yjs helpers or stay
   merge-agnostic and document the pattern?
8. **Storage class and admin exposure.** Which block-backed RWO class does the
   cluster have, and is `port-forward` to a ClusterIP Service enough for the
   admin UI or does it need its own Ingress with a login (→ TOTP earlier)?
   See [DEPLOYMENT.md](DEPLOYMENT.md).
