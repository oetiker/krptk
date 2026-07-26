# krptk client SDK

Supporting document to [DESIGN.md](DESIGN.md). The design document covers the
SDK's *positioning* — a background replicator for the storage a PWA already
uses, adopted in a few lines. This document covers how that is built.

## Adapters

Each adapter observes local writes, maps records to krptk keys, and applies
incoming remote changes back into the local store.

| Local storage | Mapping | Notes |
|---|---|---|
| `localStorage` / `sessionStorage` | one record per key | Facade wraps `Storage`; `storage` events catch other tabs |
| `idb-keyval` | one record per entry | The common "just save my objects" case |
| Dexie tables | one record per row (keyed by primary key) | Dexie addon hooks `creating/updating/deleting` |
| Raw IndexedDB object stores | one record per entry | Via a wrapping `IDBObjectStore` proxy |
| OPFS / Cache API files | chunked blobs | v2 — reuses the chunking already in the format |
| `krptk.cached()` | working set local, full dataset on server | For corpora larger than browser quota — see below |

**No change-detection machinery needed.** Because each adapter exposes the same
API as the store it wraps — `sync.local` is `Storage`-shaped, `sync.notes` is
idb-keyval-shaped, the Dexie addon hooks Dexie's own write events — every write
goes through the adapter by construction. There is nothing to diff or poll:
swap the object the app writes to and observation is automatic.

Two small pieces cover the edges:

- **One-time initial import.** Data written before krptk was attached is
  reconciled once at first attach (local index vs. server key list), not
  continuously. Cheap, and it makes retrofitting an app with existing local
  data a genuine drop-in.
- **Optional global patching** for a scattered legacy app that writes
  `window.localStorage` in fifty places: the SDK can patch `Storage.prototype`
  so those writes are observed without touching the app. Reliable for
  `localStorage` specifically (unlike IndexedDB), and opt-in — patching globals
  in a library is otherwise rude.

If an app bypasses the adapter and writes the underlying store directly, those
writes simply aren't synced. A documented constraint, not a failure mode to
engineer around.

## Cache adapter: datasets bigger than the browser

The adapters above replicate everything locally, which is right for notes,
settings and small collections. For a large corpus — media, long histories,
document archives — the useful inversion is **the server holds the full dataset
and the browser keeps a hot working set**. `krptk.cached()` is that adapter, and
it makes krptk a store that isn't bounded by browser quota at all.

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

That L1 note is the whole argument for using `localStorage` as a cache tier:
it is small and string-only, so a poor bulk cache, but it is the only store the
app can read *synchronously* at startup. Put the handful of records the first
screen needs there and the app paints instantly; everything else lives in L2.

**Behavior:**

- **Local index, not local data.** The `?since=` change feed returns keys,
  versions and sizes without values, so the client maintains a complete local
  *index* of what exists while holding a fraction of the bytes. Listing,
  searching by key, and showing a file browser all work offline over a dataset
  far larger than the device.
- **Write-through, never write-back.** Writes go to cache *and* outbox
  together; user data is never only in a volatile tier.
- **Eviction only evicts clean records.** A record with a pending write is
  never a candidate, so no local eviction can lose data. Otherwise LRU against
  the byte budget, sized against `navigator.storage.estimate()`.
- **Pinning and prefetch.** Apps pin what must be offline-available and can
  prefetch by prefix; the change feed's ordering makes "what did my other
  device just touch" a useful prefetch signal.
- **Remote changes invalidate rather than download.** A `remote` event for an
  uncached key just updates the index — no traffic for data nobody asked for.
- **Range reads for big records.** Large values are already chunked by the
  format, so a cached read fetches only the chunks it needs.

**The tradeoff**: cache misses fail while offline. The API is async-only (a
synchronous `Storage` facade cannot await a fetch, so `peek()` is L1-only by
design), the status model gains `partial`, and reads raise a typed
`MissingWhileOffline` error the app must handle. That is the honest price of
holding a dataset larger than the browser — and it is opt-in per namespace, so
small stores keep the simple fully-replicated behavior.

## Sync engine

- **Outbox**: local writes mark records dirty in krptk's own IndexedDB store.
  The engine drains the outbox with CAS writes, retrying with backoff; nothing
  is lost to a failed request or a closed tab.
- **Inbox**: SSE (tab open) or a `?since=` cursor poll delivers remote changes;
  they are decrypted, written into the local store, and surfaced via the
  `remote` event so the UI re-renders.
- **Conflicts**: last-write-wins per record by default; a per-store `merge`
  hook for app-specific resolution; drop in a Yjs/Automerge document as the
  record value for conflict-free merging.
- **Batching**: many small records coalesce into one encrypted batch blob,
  which keeps request counts, per-record overhead and quota consumption sane —
  and matters more than it looks, since per-call WebCrypto overhead dominates
  for tiny records.
- **Status model** exposed for UI: `synced | pending | offline | conflict |
  quota-exceeded | read-only | partial | not-linked`, plus any operator
  `notices` from `/v1/account` — the only channel to users, since the server
  stores no addresses. `read-only` covers a lapsed paid entitlement. Ships with
  a small sync-status indicator and the recovery-phrase onboarding flow, since
  every app needs both.
- **Explicit allowlist, never "sync everything"**: apps name the prefixes,
  stores and tables to replicate, so caches and derived data don't burn user
  quota.

## Running in the service worker

Sync belongs in the service worker, so it happens without a focused tab:

- `sync` (Background Sync) retries a non-empty outbox once connectivity
  returns — the user can close the tab mid-write and it still lands.
- `periodicsync`, where available, opportunistically pulls remote changes so
  the app is current when opened.
- A tab-side channel keeps open pages in step with what the worker did.

This is where non-extractable `CryptoKey`s pay off: the worker reads key
*handles* from IndexedDB and encrypts with them, while the raw seed is
available to nothing at all.

The SDK also calls `navigator.storage.persist()` — the local half of a
local-first store shouldn't be evicted under browser storage pressure.

A native Rust client (`krptk-client`) gives the same semantics outside the
browser: CLI tooling, server-side tests that hammer the sync protocol, and
Tauri desktop builds of the same apps.
