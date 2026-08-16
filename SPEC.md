# mailpack — an open format for personal mail archives

**Version: 0.1** · Status: DRAFT — nothing here is frozen. The pack layout (§5–§7)
freezes at v1.0; the logical-identity algorithm (§13) is versioned independently and is
never frozen (see §13.1).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as
described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 1. Goals

Mail accumulates for decades across schools, jobs, domains, and providers, and every
migration is a chance to lose attachments, botch a merge, or silently drop years of
history. A mailpack archive is a folder of files built to end that: one place where a
lifetime of mail from every source is consolidated, merged without double-counting,
and still readable in thirty years with no mailpack software at all.

Concretely, the format:

1. stores raw RFC 5322 messages content-addressed and deduplicated, without ever
   rewriting a message — every payload is a `.eml` file inside a standard ZIP archive;
2. distinguishes *byte identity* (storage) from *message identity* (what the user
   thinks of as "one email"), so the same message captured from Takeout, IMAP, Graph,
   and PST merges instead of multiplying;
3. records provenance (which account, which folder, which capture run) in append-only
   manifests;
4. is evidence-grade as a property of the format: manifests form a hash chain
   committed to by per-run Merkle roots, signed by the owner and independently
   timestamped, so the archive's history can be verified by a stranger — within the
   limits stated honestly in §2.

Evidence is a property the archive has, not a reason to install it. The reason to
install it is consolidation, merge, and longevity in an open format.

Non-goals: encryption at rest (use full-disk encryption; the archive is plaintext for
recoverability), multi-writer concurrency, compliance retention (17a-4/FINRA/MiFID).

## 2. Threat model

What the evidence machinery proves, and what it does not. Verify tooling MUST NOT use
output language that overstates any of this.

**Signatures are owner attestation.** An Ed25519 signature (§10) proves the holder of
the signing key attested to a run's records. It detects tampering by anyone who does
not hold the key. It proves nothing about whether the attested claims are true.

**Timestamps are existence-at-date.** RFC 3161 and OpenTimestamps tokens (§11) prove
the sealed run existed at a point in time. They do not prove who made it or that its
contents are true.

**Neither is authenticity.** Attestation is not authenticity: a maliciously ingested
message is fully attested — signed, chained, timestamped — because attestation records
that the owner archived these bytes at this time, not that the bytes are a genuine
message from their purported sender. The `unattested` verification status (§18)
detects crash orphans and out-of-band file placement only; it is not an authenticity
signal in either direction.

**The cascade property.** Every run commits to the exact bytes of its predecessor's
manifest (§8.1), and every run's records are bound by a Merkle root sealed by
signature and timestamp (§9). Silently rewriting an interior manifest therefore breaks
the `prev_sha256` of every later run; silently deleting an interior manifest breaks
the chain outright. The owner holds the signing key, so re-signing rewritten history
is free — but re-anchoring is not: the original timestamps cannot be reproduced, so
rewritten history's only anchors postdate the edit. An archive whose every anchor is
younger than the events it claims is exactly what tampered history looks like.

**The honest limit: tail truncation.** Anchoring is transitive backwards only; there
are no forward pointers. Deleting the newest runs deletes their anchors with them and
leaves a shorter archive that verifies cleanly. Truncation is undetectable unless the
verifier knows the expected chain head out of band. No mitigation is claimed beyond
out-of-band head knowledge (e.g. the owner publishing or depositing the latest run
ULID + manifest hash elsewhere).

**DKIM evidence is a recorded claim.** A `dkim` record (§8.4) stores the DNS TXT key
record the owner's software says it retrieved at time T. Anchoring makes that claim
tamper-evident afterwards; it does not make it true. Its value is corroboration: keys
recorded independently by other archives or observers can agree with it.

## 3. Terminology

- **Object** — the raw bytes of one message as captured, identified by its SHA-256.
- **Pack** — a sealed, immutable ZIP64 archive containing objects.
- **Staging** — loose objects not yet sealed into a pack.
- **Run** — one capture or maintenance operation, identified by a ULID, producing one
  manifest.
- **Manifest** — an append-only JSONL record of what a run observed or did.
- **Chain** — the backward hash links (`prev_run`, `prev_sha256`) connecting each run
  to its predecessor's manifest bytes.
- **End record** — a manifest's final record: counts plus the run's Merkle root. A
  manifest with an end record is *complete*; without one it is *interrupted*.
- **Anchor** — an independent timestamp token (`.tsr`, `.ots`) over a run's seal
  target.
- **Byte identity** — SHA-256 of an object's raw bytes. Governs storage and dedup.
- **Logical identity** — a versioned digest over canonicalised message features.
  Governs message counts, merge, search, and UI. One logical message may have many
  byte variants.
- **Tombstone** — a manifest record documenting deliberate deletion of an object.
- **Recovery run** — a run that re-emits an interrupted manifest's parseable records
  verbatim so they regain a sealed, anchorable home (§12).

## 4. Archive layout

```
<root>/
  mailpack.json                   # archive marker (§4.1)
  .lock                           # writer lock file (§16); contents unspecified
  packs/
    <pack-ulid>.zip               # sealed packs (§6)
    staging/
      <sha256>.eml                # loose objects (§5)
  manifests/
    <run-ulid>.jsonl              # manifest (§8)
    <run-ulid>.sig                # Ed25519 signature over the end record (§10)
    <run-ulid>.tsr                # RFC 3161 timestamp tokens (§11)
    <run-ulid>.ots                # OpenTimestamps proof (§11)
  index/                          # derived, disposable (§14)
  meta/
    keys.json                     # trusted public keys (§10.2)
    sources.json                  # account config, sync cursors (§15)
```

`packs/` and `manifests/` **are** the archive. Everything under `index/` MUST be
rebuildable from them. `meta/` is configuration plus the key registry; §10.2 defines
what of it matters to verification.

All ULIDs are [Crockford-base32 ULIDs](https://github.com/ulid/spec), 26 characters,
uppercase. All SHA-256 values in file names and manifests are lowercase hex, 64
characters.

File names beginning `.tmp-` are reserved for in-flight writes in every directory of
the archive. Readers MUST ignore them; the lock holder MAY delete them (§16).

Readers MUST tolerate the absence of directories that would be empty (`index/`,
`meta/`, `packs/staging/`): an archive copied without empty directories is still the
same archive.

### 4.1 Archive marker

`mailpack.json` identifies a directory as a mailpack archive:

```json
{
  "mailpack": 1,
  "format_version": "0.1",
  "archive_id": "01J8ZQ5X7E9RVN3TCK4WDBGHMA",
  "created": "2026-08-15T00:00:00Z"
}
```

- `mailpack` — always the integer `1`.
- `format_version` — `"MAJOR.MINOR"`, the spec version the archive was created
  against. Readers MUST refuse an archive whose MAJOR exceeds the newest they
  implement, and SHOULD warn on a higher MINOR.
- `archive_id` — a ULID assigned at creation, stable for the archive's life.
- `created` — RFC 3339 UTC timestamp.

Readers MUST refuse to treat a directory as an archive if `mailpack.json` is absent or
`mailpack` ≠ 1. Unknown keys MUST be ignored (here and in every JSON object in this
spec).

## 5. Objects and staging

An object is the raw captured bytes of one message. Objects are immutable: no
implementation may ever alter the bytes of a stored object.

- Object ID = SHA-256 of the raw bytes, lowercase hex.
- A newly ingested object is written either to `packs/staging/<sha256>.eml` or
  directly into a pack under construction (a bulk writer MAY bypass staging; the pack
  is not part of the archive until sealed and renamed into place, §6).
- Writers MUST write staging objects atomically (write to a `.tmp-` name in the same
  directory, sync, then rename) and SHOULD sync the parent directory after the
  rename so the entry itself is durable.
- Writers MUST NOT store an object whose ID already exists in staging or in any sealed
  pack (dedup is by byte identity). Readers MUST tolerate duplicates anyway — a crash
  between sealing and staging cleanup can leave one — and treat any copy as
  equivalent.

The `.eml` extension is cosmetic but REQUIRED: it makes extracted files open in mail
clients, at no cost.

## 6. Packs

A pack is a ZIP archive (ZIP64 extensions permitted and expected) whose entries are
objects. Packs are sealed once and never modified; the only permitted operation on a
sealed pack is replacement during a deletion rewrite (§17).

Requirements:

- File name: `packs/<pack-ulid>.zip`, ULID assigned at seal time.
- Entry name: exactly `<sha256>.eml`. Version-1 writers MUST NOT write any other
  entry. Readers MUST ignore entries whose names do not match
  `^[0-9a-f]{64}\.eml$` — this reserves room for future pack-level metadata entries
  without breaking old readers.
- Entry contents: the object's raw bytes. The entry name's hash MUST equal the SHA-256
  of the uncompressed entry data.
- Compression: writers SHOULD use DEFLATE; STORE is permitted. Readers MUST support
  both. No other methods, no encryption, no split/spanned archives.
- Writers SHOULD order entries by ascending hash when the full entry set is known
  before writing begins (e.g. sealing staged objects), so identical object sets
  produce identical entry order. A streaming bulk writer MAY write entries in arrival
  order.
- Writers SHOULD seal packs in the 256 MiB – 1 GiB range. This is a target, not a
  conformance bound.

Sealing MUST be crash-safe: build the pack at a `.tmp-` name, verify it by reading
back every entry and recomputing its hash, sync it durably, rename it into place,
sync the parent directory, and only then remove any sealed objects from staging.

Rationale for ZIP64 packs (informative): loose small files can be pathologically slow
under synchronous scanning; packs collapse a million paths to a few hundred; the
central directory doubles as a pack index; and recovery without mailpack software
is "double-click the pack".

## 7. Object location

An object's location (staging vs. which pack) is *derived* state, discoverable by
listing `packs/staging/` and reading pack central directories. Manifests never record
pack membership — this keeps every manifest valid across pack sealing and deletion
rewrites.

## 8. Manifests

A manifest is a UTF-8 JSONL file, `manifests/<run-ulid>.jsonl`: one JSON object per
line, each line terminated by LF (`\n`), no BOM.

Lifecycle: a manifest is created at its final name and grows by appends only. Writers
SHOULD sync it progressively and MUST sync it when the run finishes. A manifest is
never renamed, never reopened, and never edited: once its run ends (with an end
record, §8.5) it is immutable because signatures, timestamps, and the next run's
chain link cover its exact bytes — and a manifest whose run died before the end
record (an *interrupted* manifest) is equally immutable, a permanent crash artifact.
Crashed runs are recovered by re-emission into a new run (§12), never by resuming the
old file.

Reader rules:

- Every record has a `type` field. Readers MUST skip records with unknown `type`
  values.
- A final line lacking its terminating LF (a crash mid-append) MUST be tolerated and
  ignored — it is not part of the record sequence.
- Any other unparseable line makes the manifest *manifest-malformed* (§18). Reporting
  tools MUST still process the parseable records around it.

### 8.1 `run` record

The first line of every manifest MUST be a `run` record:

```json
{"type": "run", "run": "01J8ZQ5X7E9RVN3TCK4WDBGHMA", "format_version": "0.1",
 "archive_id": "01J8ZQ5X7E9RVN3TCK4WDBGHMA",
 "prev_run": "01J8ZQ4A2M6PWX8YB0CDEFGHJK",
 "prev_sha256": "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c",
 "started": "2026-08-15T01:02:03Z", "source": "imap:alice@example.com",
 "kind": "ingest"}
```

- `run` — the run ULID; MUST match the file name.
- `archive_id` — the archive's ULID (§4.1); binds the run to its archive.
- `prev_run` / `prev_sha256` — the chain link: the preceding run's ULID and the
  lowercase-hex SHA-256 of that run's manifest file — its exact bytes at link time,
  whether complete or interrupted. Both `null` on the archive's first run.
- `started` — RFC 3339 UTC.
- `source` — an opaque source identifier; `null` for maintenance runs.
- `kind` — `"ingest"`, `"delete"`, `"maintenance"`, or `"recovery"`. A recovery run
  additionally carries `"recovers": "<run-ulid>"`, the interrupted run it re-emits
  (§12).

Runs form a single backward chain: exactly one run has `prev_run: null`, and every
other run's `prev_run` names an existing run. Two manifests naming the same
`prev_run` are a *chain fork* (§18); a writer discovering a fork MUST refuse to
append new runs until it is resolved.

### 8.2 `message` record

One per message observed by the run:

```json
{"type": "message",
 "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
 "size": 4096,
 "logical_id": "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c",
 "identity_v": 1,
 "provider_id": "18c2f3a9b1e4d507",
 "folders": ["INBOX", "Receipts"],
 "date": "2019-03-04T12:00:00Z",
 "ingested": "2026-08-15T01:02:04Z"}
```

- `sha256` — byte identity (§5). REQUIRED.
- `size` — object size in bytes. REQUIRED.
- `logical_id`, `identity_v` — logical identity and the algorithm version that produced
  it (§13). REQUIRED. `identity_v: 0` with `logical_id: null` means "not computed"
  (e.g. the message failed to parse; archival is never blocked by parsing).
- `provider_id` — provider-native message ID (e.g. Gmail `X-GM-MSGID`, IMAP UID
  qualified by UIDVALIDITY, Graph message id), or `null`. Format is source-specific and
  opaque.
- `folders` — folder/label names as reported by the source. MAY be empty.
- `date` — the message's internal date as reported by the source, RFC 3339 UTC, or
  `null`.
- `ingested` — when this run stored/observed the object, RFC 3339 UTC. REQUIRED.

The same object MAY appear in message records of many runs (a re-sync observes it
again; a second source yields the same bytes). Each record is one provenance claim.
Writers MUST record an observation even when the object itself was a duplicate —
re-observation is how attestation self-heals after a crash (§12).

### 8.3 `tombstone` record

Documents deliberate deletion (§17):

```json
{"type": "tombstone",
 "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
 "deleted": "2026-08-15T09:00:00Z",
 "reason": "user"}
```

- `sha256` — the deleted object. REQUIRED.
- `deleted` — RFC 3339 UTC. REQUIRED.
- `reason` — free text; `"user"` is conventional. OPTIONAL.

A tombstone asserts: this object once existed, and its absence is deliberate.
Verifiers use it to distinguish *excised* from *missing* (§18).

### 8.4 `dkim` record

Documents one DKIM verification attempt against an archived message. Written only
when a DNS key record was actually retrieved — the key is the durable artifact, and it
is stored even when verification failed.

```json
{"type": "dkim",
 "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
 "domain": "example.com",
 "selector": "s1",
 "from_domain": "example.com",
 "aligned": "strict",
 "body_length": null,
 "result": "pass",
 "key_record": "v=DKIM1; k=rsa; p=MIIBIjANBgkq…",
 "checked": "2026-08-15T01:02:05Z"}
```

- `sha256` — the verified object. REQUIRED.
- `domain`, `selector` — the signature's `d=` and `s=`. REQUIRED.
- `from_domain` — the domain of the first `From` mailbox at check time. REQUIRED.
- `aligned` — `"strict"`, `"relaxed"`, or `"none"`: the alignment judgment between
  `domain` and `from_domain`, computed at ingest time. The raw `from_domain` is
  stored alongside the judgment because relaxed alignment depends on the public
  suffix list, which drifts; a bare stored boolean would rot. REQUIRED.
- `body_length` — the signature's raw `l=` value, or `null` when absent. REQUIRED.
- `result` — `"pass"` or `"fail"`. REQUIRED.
- `key_record` — the DNS TXT record retrieved for `<selector>._domainkey.<domain>`.
  REQUIRED.
- `checked` — RFC 3339 UTC. REQUIRED.

Resolution rule: `dkim` records are observations, not state. They accumulate; nothing
supersedes an earlier record, and a later `fail` never erases an earlier anchored
`pass` — key rotation and transport mangling make later failures expected for honest
messages.

Display requirements (normative for tools rendering these records): a pass whose
`aligned` is `"none"` MUST NOT be rendered as verification of the sender; a pass with
a non-null `body_length` MUST NOT be rendered as verification of the full message
content. See §2: none of this is authenticity, and output language must not imply it.

### 8.5 `end` record

The last line of a complete manifest:

```json
{"type": "end", "finished": "2026-08-15T01:07:00Z",
 "messages": 2412, "tombstones": 0,
 "root": "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9"}
```

- `finished` — RFC 3339 UTC. REQUIRED.
- `messages`, `tombstones` — counts of those record types in this manifest. REQUIRED.
- `root` — the run's Merkle root (§9). REQUIRED.

A manifest whose last parseable record is an `end` record is *complete*; any other
manifest is *interrupted*. Nothing may follow the end record.

## 9. Merkle commitment and the seal target

Every complete run commits to its records with a Merkle tree in the
[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962#section-2.1) shape:

- leaf hash = `SHA-256(0x00 ‖ leaf)`; interior node = `SHA-256(0x01 ‖ left ‖ right)`.
- For n > 1 leaves the tree splits after the largest power of two smaller than n; the
  root of zero leaves is `SHA-256("")`.
- The leaves are every line of the manifest **except the end record**, in file order,
  each without its trailing LF.

**The seal target is the end-record line.** Let E = the exact bytes of the end record
line, without its trailing LF:

- `manifests/<run-ulid>.sig` contains an Ed25519 signature over E (§10).
- `manifests/<run-ulid>.tsr` / `.ots` tokens cover `SHA-256(E)` (§11).

The end record is not a leaf of its own tree — it cannot contain its own hash. It is
covered directly: the signature and timestamps are over E itself, and E contains the
root, so every leaf — including the run record with its chain link — is transitively
signed and timestamped, and the counts and finish time are directly signed and
timestamped. One line is the single canonical target for signing, timestamping, and
disclosure.

### 9.1 Disclosure bundle

A single record can be disclosed and verified without revealing the rest of the run.
A disclosure bundle consists of:

1. the record line (leaf bytes),
2. its leaf index and the tree size (leaf count),
3. the Merkle audit path (RFC 6962 §2.1.1),
4. the end-record line E,
5. the run ULID,
6. the signature envelope (§10.1),
7. any timestamp tokens (§11).

The recipient verifies: leaf + audit path → root; root equals the `root` in E; the
signature over E verifies against the disclosed key (whose fingerprint the recipient
checks out of band); the timestamp tokens cover `SHA-256(E)`. This proves the record
was part of a run the owner sealed at or before the anchored time — subject to §2.

## 10. Signatures

### 10.1 Signature file

`manifests/<run-ulid>.sig` is a JSON envelope:

```json
{"alg": "ed25519",
 "key": "4f2d8a7c1b9e6350a2c4e8d1f7b3a5c9e0d2f4a6b8c1d3e5f7a9b0c2d4e6f801",
 "sig": "<base64, 64-byte Ed25519 signature>"}
```

- `alg` — MUST be `"ed25519"` in this version.
- `key` — the signing key's fingerprint: lowercase hex SHA-256 of the 32-byte public
  key.
- `sig` — standard (RFC 8032) Ed25519 signature over the seal target E (§9), base64
  (RFC 4648, with padding).

Interrupted manifests have no end record and therefore no signature; their records
regain a signable home through recovery (§12).

The signature detects corruption and tampering. It does **not** prove time — that is
the anchors' job (§11) — and neither proves authenticity (§2). Docs built on this
spec should say so plainly.

### 10.2 Key registry and lifecycle

`meta/keys.json`:

```json
{"keys": [
  {"public": "<base64 32-byte Ed25519 public key>",
   "fingerprint": "4f2d…",
   "created": "2026-08-15T00:00:00Z",
   "retired": null,
   "comment": "laptop"}
]}
```

Keys are a lifecycle, not a constant: over decades users lose keys and change machines.

- Multiple keys MAY be trusted concurrently.
- Rotation: add the new key, mark the old one `retired` (RFC 3339). Retired keys still
  verify old manifests; they SHOULD NOT sign new ones.
- A lost key is not corruption. Verification reports runs signed by unknown keys as
  *provenance-unverifiable*, distinct from *corrupt* (§18).
- Verifiers MAY be given a key set out-of-band instead of trusting `meta/keys.json`
  (the registry travels with the archive, so a tamperer can rewrite it; out-of-band
  fingerprint comparison is the stronger check and MUST be supported by verify
  tooling).

## 11. Timestamps and anchoring

Two anchor mechanisms, because they fail in opposite directions:

- `manifests/<run-ulid>.tsr` — one or more RFC 3161 `TimeStampResp` structures, DER,
  concatenated. Each MUST cover `SHA-256(E)` (§9). Writers SHOULD obtain tokens from
  ≥ 2 independent TSAs — no single authority may be the point of trust.
- `manifests/<run-ulid>.ots` — an OpenTimestamps proof over the same hash.
  Bitcoin-anchored; needs no surviving authority. Proofs start incomplete and MUST be
  upgraded once attestations confirm; tooling runs the upgrade pass in the background.

**Anchoring is asynchronous.** Finishing a run MUST NOT block on any external
service: the run completes, is signed, and becomes readable immediately; an anchor
queue obtains `.tsr`/`.ots` tokens afterwards, retrying until they exist. Sidecar
token files MAY be added — and OTS proofs upgraded — at any later time without
violating manifest immutability: sidecars are evidence *about* the run, not archive
content, and are not covered by any hash.

A run that missed its anchor window is still indirectly anchored: any later run's
token covers, through the chain (§8.1), every earlier manifest's bytes. Indirect
anchoring is real but disclosure-expensive — proving it requires revealing every
intervening manifest — which is exactly why per-run tokens remain the goal and the
queue retries until they exist.

Timestamps are optional per-run; their absence downgrades verification results (§18),
it does not invalidate the archive.

## 12. Recovery

An interrupted manifest (§8.5) is never resumed or edited. Its parseable records are
instead *re-emitted* by a recovery run:

- `kind: "recovery"`, with `recovers` naming the interrupted run (§8.1).
- The recovery run appends every parseable `message` and `tombstone` line of the
  interrupted manifest **verbatim** — byte-identical lines, original `ingested`
  timestamps included — then finishes normally, gaining its own end record, root,
  signature, and anchors.
- A trailing LF-less partial line in the interrupted manifest is not a record and is
  not re-emitted. A mid-file unparseable line is damage, not interruption: the
  manifest is *manifest-malformed* (§18) and recovery does not apply to it.

Writers MUST perform recovery for all uncovered interrupted manifests after acquiring
the writer lock and before beginning any other run, so the exposure window is one
crashed session, not open-ended.

An interrupted run is *covered* when every parseable `message`/`tombstone` line in it
appears byte-identically in some later complete run (vacuously true when it has no
such records). Verification reports a covered interrupted run as *recovered* (§18):
transient in effect, while the crash artifact stays honestly visible forever.

Loss bounds (informative): a staging writer makes object bytes durable before
appending the record, so a crash costs at most one manifest line — the object
survives as `unattested` and the next observation re-records it (§8.2). A bulk writer
appends records only after its pack seals, so a crash mid-pack loses only the
in-flight temp pack — never archived, re-readable from the local source via an import
cursor (§15) — and a crash between seal and record-append leaves sealed objects
`unattested` until resume re-records them. No durably-stored message ever loses
bytes; attestation loss is bounded and self-heals.

## 13. Logical identity

Byte identity double-counts real mailboxes: Takeout injects `X-Gmail-Labels` and munges
`From ` lines; Microsoft Graph synthesises MIME on request; PST conversion always
produces synthesised bytes. The same message captured two ways never matches
byte-for-byte. Logical identity is the versioned, reproducible answer to "are these the
same email?"

### 13.1 Versioning

The algorithm is identified by an integer `identity_v`, carried on every message record.
Implementations MUST reproduce published versions bit-exactly against the test vectors
in [`vectors/`](vectors/). Fixes and improvements ship as a new version — never as a
silent change to an existing one. Old manifests keep their old `identity_v`; nothing is
rewritten.

### 13.2 Algorithm v1 [DRAFT — test vectors pending; do not implement as final]

Inputs: the raw object bytes, parsed as RFC 5322.

1. **message-id**: the `Message-ID` header value with surrounding whitespace and one
   pair of enclosing angle brackets removed. Absent or unparseable → empty string.
2. **date**: the `Date` header parsed per RFC 5322, converted to Unix seconds (UTC),
   rendered as a decimal integer. Absent or unparseable → empty string.
3. **from**: the addr-spec of the first mailbox in `From`, lowercased. Absent or
   unparseable → empty string.
4. **body-hash**: lowercase hex SHA-256 of the canonicalised body: decode the
   transfer encoding of the first `text/*` leaf part (or the raw body if unstructured),
   normalise line endings to LF, strip trailing whitespace from each line, strip
   trailing empty lines. [DRAFT: charset handling, multipart selection, and
   HTML-vs-plain preference are unresolved — this is exactly the empirical work the
   version number exists for.]

Then each input is framed by its length — an unambiguous encoding regardless of field
contents:

```
frame(x)   = len(x) as 8-byte big-endian ‖ x
logical_id = sha256(frame("mailpack-identity-v1") ‖ frame(message-id) ‖
                    frame(date) ‖ frame(from) ‖ frame(body-hash))
```

rendered as lowercase hex.

Correctness of a version is defined against the labeled ground-truth corpus in
[`corpus/`](corpus/), not against intuition.

## 14. Index

`index/` holds derived acceleration state (e.g. a SQLite database mapping hash →
location, full-text search). Its format is implementation-defined, explicitly out of
scope for this spec, and MUST be rebuildable from packs + manifests alone. A verifier
MUST NOT need it.

## 15. Sources

`meta/sources.json` holds capture configuration: accounts, folder include/exclude,
sync and import cursors (e.g. how far through a local mbox a bulk import has
progressed, so an interrupted import resumes from source). Implementation-defined and
out of scope, with one rule: it MUST NOT contain secrets (credentials belong in the
OS keychain), because archives get copied.

## 16. Concurrency

One writer, any number of readers, no reader locks — a reader is anything that only
reads: search, the GUI, verification, disclosure.

- **Mutation requires the lock.** `<root>/.lock` exists for OS advisory locking
  (flock / `LockFileEx`); its contents are unspecified. Any process that mutates the
  archive MUST hold the exclusive lock, SHOULD hold it for its whole session, and on
  failing to acquire it MUST fail fast ("locked by another writer") rather than
  block or fall back to read-write.
- **Readers take no lock.** Instead, a writer MUST pass only through states a
  lock-free reader can correctly interpret: atomic renames for every publish, the
  `.tmp-` convention (§4) for everything in flight, and the tolerated trailing
  partial manifest line (§8).
- **Rescan on miss.** A reader that misses an object in staging MUST rescan pack
  directories before concluding absence — the object may have just been sealed. The
  same applies to a pack file that vanishes underfoot (deletion rewrite, §17):
  rescan, then retry.
- **Windows delete-retry.** Deleting a file another process has open fails on
  Windows. Deleters MUST retry such deletions; sweepable leftovers (`.tmp-`, an
  already-replaced pack) may also be cleaned by a later lock holder.
- **NFS caveat.** Advisory locking is unreliable on network filesystems. An archive
  on NFS/SMB gets no single-writer guarantee from this spec; keep archives on local
  disks and replicate instead.

## 17. Deletion

Append-only governs how the store works, not what the owner may do. Deletion is a
deliberate, recorded operation:

1. Write a new manifest (run `kind: "delete"`) containing one tombstone record per
   deleted object; finish, sign, and anchor it like any other run. The record
   precedes the removal: bytes are destroyed only after their tombstones are durable.
2. For each pack containing a deleted object: write a replacement pack (new ULID)
   containing every entry except the deleted ones, verify the replacement by reading
   back every entry, rename it into place, then — and only then — delete the old pack
   (with retries per §16). A pack losing its last entry is deleted without
   replacement. Staged objects are simply removed after the manifest is complete.

A deletion MUST NOT edit any existing manifest or pack. Message records referencing the
deleted object remain in their manifests forever; the tombstone is what makes the
absence honest. A crash between tombstone and removal leaves the object present but
condemned — a *zombie* (§18) — and the deletion is simply re-run.

## 18. Verification

A verifier reads packs + manifests (+ keys) and reports. The result vocabulary is part
of the format, because "your archive is fine" and "your archive is fine but run
2019-441 can't be attributed" must be distinguishable. A verifier MUST NOT bail on the
first problem: every run and every object gets a status.

**Record order.** The archive's record sequence is totally ordered: runs in chain
order (§8.1), records in file order within a run. Per object, the latest `message` or
`tombstone` record determines its expected state — a message record expects presence,
a tombstone expects absence, and a later observation reverses an earlier tombstone
(re-ingest after deletion is legitimate).

Per object (union of all records vs. what exists):

| status | meaning |
|---|---|
| `ok` | expected present; bytes present and hash to the recorded ID |
| `corrupt` | expected present; bytes present but do NOT hash to the recorded ID |
| `missing` | expected present; absent — data loss |
| `excised` | expected absent (tombstoned); absent |
| `zombie` | expected absent (tombstoned); still present — deletion incomplete, re-runnable |

Objects present in the store but referenced by no record are `unattested`: a crash
orphan or an out-of-band file placement (§2). Verifiers MUST report the store⇄manifest
diff in both directions.

Per run:

| dimension | statuses |
|---|---|
| completion | `complete` / `interrupted` / `recovered` (interrupted but covered, §12) |
| chain | `chain-ok` / `chain-broken` (prev missing or `prev_sha256` mismatch) / `chain-fork` (a shared `prev_run`) |
| root | `root-ok` / `root-mismatch` (recomputed tree ≠ end record) / not applicable (interrupted) |
| integrity | `manifest-malformed` (any unparseable non-trailing line; reported with line numbers) |
| signature | `sig-ok` / `sig-unknown-key` (provenance unverifiable, not corruption) / `sig-invalid` / `sig-missing` |
| anchors | `ts-ok` / `ts-pending` (OTS awaiting upgrade) / `ts-missing` |

An archive is **intact** iff no object is `corrupt` or `missing` and no run is
`sig-invalid`, `chain-broken`, `chain-fork`, `root-mismatch`, or `manifest-malformed`.
Everything else — `interrupted`, `recovered`, `zombie`, `unattested`,
`sig-unknown-key`, `sig-missing`, `ts-*` — is a reported warning, never conflated
with damage.

## 19. Conformance

- A **reader** MUST locate and return objects given the layout in §4–§7 — including
  objects still in staging, which are as much part of the archive as packed ones —
  tolerating duplicates, absent empty directories, and foreign pack entries (§6), and
  MUST parse manifests per §8, skipping unknown record types and keys and tolerating
  the trailing partial line.
- A **writer** MUST uphold immutability (§5, §6, §8), atomicity and crash-safety
  (§5, §6, §17), dedup-by-hash (§5), the chain (§8.1), recovery-before-new-runs
  (§12), and the locking discipline (§16).
- An **identity implementation** MUST match the published test vectors bit-exactly for
  every `identity_v` it claims.
- A **verifier** MUST implement §18 and MUST NOT require `index/` or network access
  (anchor verification MAY use the network; everything else works offline).

The conformance corpus lives in [`corpus/`](corpus/); identity test vectors in
[`vectors/`](vectors/). Both are versioned with this spec.

## 20. Open questions (tracked toward v1.0)

- Identity v1 body canonicalisation (§13.2) — needs the ground-truth corpus first.
- Maximum manifest size / manifest splitting for very large runs.
- The stdlib-only recovery reader ships with this repo before v1.0 — and MUST surface
  staging objects (§19).
