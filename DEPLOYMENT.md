# krptk deployment and operations

Supporting document to [DESIGN.md](DESIGN.md). Nothing here constrains the wire
or crypto format, with one exception that is called out in the design document's
freeze table: **the database and blob directory must share one volume**, because
snapshot atomicity depends on it.

## Kubernetes

Target deployment is k8s, shipped as a **Helm chart** in-repo. The uncomfortable
truth to design around: krptk is a *single-writer, stateful* service. SQLite has
one writer and the blob directory is a local filesystem, so this is a
**StatefulSet with `replicas: 1`**, scaled vertically. That is a fit-for-purpose
choice rather than a limitation to hide — one pod on modest resources serves
thousands of PWA users doing sync-shaped traffic.

Consequences worth planning for rather than discovering:

- **Volume must be block-backed RWO.** **Ceph RBD is the reference target**
  (also EBS/PD, Longhorn, local-path). **Never NFS or CephFS**: SQLite's
  locking is unsafe on most network filesystems, and this is the single most
  likely way to corrupt a krptk install. The chart should refuse, or loudly
  warn about, an RWX storage class. A *single* PVC holds both database and
  blobs — see [backup](#backup-and-restore-via-volume-snapshots).
- **`updateStrategy` must not run two pods at once.** With RWO the new pod
  cannot attach while the old one holds the volume, so a naive rolling update
  deadlocks until timeout. Use `OnDelete`/recreate semantics and accept a few
  seconds of downtime per upgrade. This is where the client design pays off:
  the SDK's offline queue makes a brief restart invisible to PWAs — writes
  queue locally and drain on reconnect. Availability lives in the client, not
  in replica count.
- **Maintenance can't be a `CronJob` that mounts the disk.** A separate pod
  running `scrub` would need the same RWO volume the server holds. So scheduled
  maintenance is **built into the server**, on an internal schedule. A CronJob
  that *calls the admin API* is fine; it just cannot mount the volume. The CLI
  subcommands stay available for manual and offline use.
- **Two Services, two exposure levels.** The public API Service goes behind the
  Ingress; the admin listener gets a `ClusterIP`-only Service deliberately
  *not* in any Ingress by default — reachable via `kubectl port-forward`, or
  optionally a second Ingress with its own auth. A `NetworkPolicy` restricts
  who can reach the admin port at all.
- **SSE needs Ingress care.** Change notifications are long-lived streams, so
  the chart sets `nginx.ingress.kubernetes.io/proxy-buffering: "off"` and
  generous read timeouts (and the Traefik equivalents). Getting this wrong
  shows up as sync that only works on page reload.
- **Probes**: `/healthz` (liveness, cheap) and `/readyz` (readiness — SQLite
  reachable, blob dir writable, migrations done), plus a `startupProbe` so slow
  migrations on a large database don't trip liveness restarts.
- **Pod hardening** comes almost free with a scratch image: `runAsNonRoot`,
  `readOnlyRootFilesystem: true` (the only writable path is the data volume),
  `allowPrivilegeEscalation: false`, all capabilities dropped, seccomp
  `RuntimeDefault`.
- **Config and secrets**: TOML config from a ConfigMap with a checksum
  annotation so config changes roll the pod; session signing key, operator
  bootstrap credentials and payment-provider webhook secret from a Secret
  (External Secrets-friendly).
- **Observability**: optional `ServiceMonitor` for Prometheus Operator. The
  shipped dashboard and alerts should cover what actually bites — volume
  nearing full, backup age exceeding threshold, scrub errors, quota rejection
  rate, cleartext-rejection spikes.
- **Resources**: `requests` with a real `memory` floor (SQLite page cache plus
  blob buffers) and no CPU limit by default, since throttling a single-replica
  sync server is worse than letting it burst.
- **Scaling escape hatch, deliberately deferred**: because everything goes
  through `sqlx`, a Postgres backend plus S3 blob storage would allow
  `replicas: N` behind a normal Deployment. A v2 item to design toward but not
  build — the single-pod story is honest and sufficient, and premature HA would
  cost the simplicity that makes self-hosting pleasant.

## Durability

"Permanent" is a durability claim, not just a policy one:

- WAL mode with `synchronous=FULL`.
- BLAKE3 checksums verified on read and by the scheduled scrub, which also
  re-validates the [cleartext invariant](DESIGN.md#the-invariant-no-cleartext-ever).
- A `quiesce` command so the volume can be snapshotted cleanly.
- `krptk backup` / `restore` for portable logical archives.

## Backup and restore via volume snapshots

Since the cluster already does **RBD volume snapshots**, that is krptk's
primary backup mechanism and the server gets *simpler*: no scheduled S3 upload,
no Litestream sidecar, no backup credentials in a Secret. The design only has to
earn the right to be snapshotted safely.

**Why this is sound**: an RBD snapshot is crash-consistent at the block layer,
and SQLite in WAL mode is explicitly crash-safe — restoring a snapshot looks
exactly like recovering from a power cut, which SQLite handles by replaying or
discarding the WAL. Nothing extra is needed for *integrity*.

Three requirements make it correct:

1. **One PVC for everything.** The database and the blob directory must live on
   the **same volume** so the snapshot is atomic across both. Split them and a
   snapshot can catch metadata referencing a blob that isn't there yet, or vice
   versa — a silent, latent inconsistency. This is a hard design constraint,
   not a deployment preference.
2. **`synchronous=FULL`** in WAL mode. With `NORMAL`, recent committed
   transactions can be lost on power loss and therefore be missing from a
   snapshot, even though the database stays uncorrupted. `FULL` means anything
   krptk has acknowledged to a client is in the snapshot. At sync-shaped write
   volumes the fsync cost is worth the honesty; configurable for operators who
   disagree.
3. **A quiesce hook.** `krptk admin quiesce --hold=30s` briefly pauses new
   writes, runs `PRAGMA wal_checkpoint(TRUNCATE)`, fsyncs the blob directory,
   and holds until released or the timeout expires. Wire it as a pre-snapshot
   hook (Velero `pre.hook.backup.velero.io/command`, a Kanister blueprint, or a
   `kubectl exec` from whatever schedules snapshots). Crash-consistent
   snapshots are fine; quiesced ones restore with an empty WAL and no replay,
   which is nicer to reason about during an incident.

**Scheduling**: any CSI snapshot scheduler works — Velero schedules, or
snapscheduler for something small that just does PVC snapshots. The chart ships
a `VolumeSnapshotClass` reference and optional schedule manifests but
reimplements none of it.

**The gaps snapshots don't close**, and they matter for a store whose promise is
*permanent*:

- **RBD snapshots live in the same Ceph cluster.** They protect against
  accidental deletion, a bad upgrade or operator error — not against loss of
  the cluster. At least one copy must leave it: either Ceph snapshot-based RBD
  mirroring to a second cluster, or Velero with CSI data movement to object
  storage. Pick one; "we have snapshots" is not offsite.
- **Snapshots faithfully preserve corruption.** If a bug or bit-rot damages a
  blob, every subsequent snapshot contains the damage and a bad restore point
  can go unnoticed for months. That is what `krptk scrub` is for: it verifies
  every blob against its BLAKE3 name and the metadata against the blob set,
  surfacing results in the admin UI and as a Prometheus metric. **Snapshot age
  and last-clean-scrub time are the two alerts that matter.**
- **Logical export stays worthwhile**, in `krptk backup` form: a
  self-describing archive (SQLite dump plus blobs), portable across krptk
  versions and Ceph clusters, verifiable independently of the block layer.
  Weekly, offsite, verified — a cheap second failure domain. Snapshots are for
  fast recovery; the logical export is for the bad day.

**Restore drill**, documented and rehearsed, because an untested backup isn't a
backup: scale the StatefulSet to 0 → create a PVC from the `VolumeSnapshot` →
point the StatefulSet at it → scale to 1 → run `krptk scrub` before letting
clients back in. The chart includes this as a runbook.

**Bonus from RBD**: cloning a snapshot into a throwaway volume is cheap, so
schema migrations and version upgrades can be **rehearsed against a clone of
real production data** before touching the live volume. Worth building into the
upgrade runbook, since single-replica upgrades have no rollback other than
restore.

## Management UI

Operator-facing, planned in from the start rather than bolted on, and **served
by the same binary** (templates and assets embedded via `rust-embed`) so
deployment stays "one binary, one config file".

**Scope** — all metadata-only; the operator never sees plaintext:

- **Dashboard**: total storage, account count, requests/day, top accounts by
  usage, quota pressure, backup and scrub status.
- **Accounts**: search by user id, per-app usage breakdown (sizes and
  timestamps only), quota overrides, freeze / unfreeze, delete with
  confirmation. With anonymous users there is nothing else to search by — no
  names, no emails, by design.
- **Apps**: register `appId`s, their developer contact, CORS origins, and
  **pools** (total bytes, account count, creation rate) with live consumption
  against each — plus the per-app kill switch (freeze registrations, freeze
  writes, freeze everything).
- **Accounts by provenance**: which app registered an account and when, so an
  abuse report resolves to an app and then to a person you can call.
- **Usage and entitlements**: the metered history per account and per app pool,
  active entitlements and their expiry, lapsed-to-read-only accounts. This is
  the operator half of [objective 3](DESIGN.md#objective-3-a-path-to-charging),
  and the screen that tells you whether pricing is sane.
- **Settings**: PoW difficulty, free-tier size and growth curve, per-IP and
  per-app creation limits, size and rate limits, global storage ceiling.
- **User notices**: compose the in-app messages an account sees on next open —
  the only channel to users, since no addresses are stored.
- **Abuse handling**: notice intake, per-account and per-record freeze and
  purge, and the resulting audit entries. First-class screens, not an
  afterthought — this is the operator-facing half of the liability story.
- **Invariant health**: cleartext-rejection counts by category, last clean
  scrub, snapshot age — the numbers backing the transparency note.
- **Audit log**: every admin action, who/when/what, append-only.

**Tech**: server-side rendered with **askama** templates plus small amounts of
vanilla JS. An admin UI is tables and forms; SSR keeps it dependency-light,
fast, and testable with plain HTTP tests. If it outgrows that, the
`krptk-format` types are already shared, so promoting it to a Leptos/Dioxus WASM
app later is incremental rather than a rewrite.

**Admin auth, deliberately separate from user auth**: operator accounts with
argon2id-hashed passwords (created via `krptk admin add-operator`), optional
TOTP second factor, session cookies (`SameSite=Strict`). By default the admin UI
binds to a **separate listener** so operators can keep it off the public
internet entirely or put it behind reverse-proxy auth (mTLS, OIDC) without
touching krptk. All admin actions land in the audit log.

## Appendix: email enrollment (not recommended)

Earlier drafts offered optional email enrollment as a quota tier: verify an
address once, discard it, keep only a peppered per-app handle. The design
document now [recommends against it](DESIGN.md#no-personal-data-in-the-data-plane)
— a paid tier buys the same Sybil resistance without SMTP, without a pepper
that must live outside the volume and be backed up separately, without lazy
pepper rotation, and without pulling pseudonymous personal data into scope. The
construction is recorded here in case a specific app ever needs it.

```
handle = HMAC-SHA256(serverPepper, normalize(email) ‖ appId)
```

- **A server-side pepper**, kept in a Secret *outside* the database and its
  backups. Without it, a leaked database can be brute-forced in minutes: the
  address space is small and enumerable, hashed email dumps get reversed
  routinely, and data-protection law treats a hashed identifier as
  *pseudonymous personal data*, still in scope. "We only store a hash" removes
  no obligation.
- **Scoped per app.** Including `appId` means the same person enrolling in three
  apps produces three unlinkable handles, preserving the per-app isolation the
  key hierarchy already gives and making Sybil resistance per-app — the right
  granularity, since pools are per-app.
- **Normalize before hashing** (lowercase, trim, optionally strip
  plus-addressing and Gmail dots — a policy choice that tightens dedup).
- **The plaintext address is transient**: held only for the verification
  round-trip in a short-TTL row, then discarded. A hash can be compared but not
  contacted, so email buys exactly one thing — uniqueness.
- **Pepper rotation is lazy**: you cannot re-hash addresses you no longer have,
  so a rotation carries old and new handle columns and upgrades each account the
  next time its owner verifies.

Two rules would be non-negotiable if it were ever built, and they generalize to
payment: **email is never authentication** (access comes from the keypair,
always — an email login would let the server impersonate users) and **email is
never key recovery** (the recovery phrase is the only path; users will assume
otherwise the moment they see an email field, so the UI must say so plainly or
enrollment actively worsens data loss by making people feel safe).

The endpoints, if needed:

```
POST /v1/enroll/start    {appId, email}  → sends code, short-TTL row
POST /v1/enroll/verify   {pubkey, code}  → tier upgrade
```

Disposable-address domains make dedup a treadmill rather than a solution.
Privacy Pass / Private Access Tokens are the emerging way to get anonymous rate
limiting with no identifier at all — worth watching rather than building on
today.
