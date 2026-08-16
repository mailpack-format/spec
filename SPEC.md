# mailpack — an open format for personal mail archives

**Version: 0.1** · Status: DRAFT — nothing here is frozen. The pack layout (§5–§7)
freezes at v1.0; the logical-identity algorithm (§13) is versioned independently and is
never frozen (see §13.1).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD
NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to
be interpreted as described in BCP 14
([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119),
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear
in all capitals.

## 1. Introduction

Personal mail accumulates for decades across providers, employers, schools, and
domains, and outlives every account that carries it. The incumbent storage formats
each solve part of the problem. mbox concatenates messages into a single fragile file,
with dialect-dependent escaping and no integrity protection. Maildir stores one file
per message but has no cross-source identity, no provenance, and no integrity
protection. PST is proprietary. Mail left on a server survives only as long as the
account does. None of them can merge the same mailbox captured two ways without
double-counting it.

A mailpack archive is a directory of files with four properties that no incumbent
format provides together:

1. **Consolidation without double-counting.** Messages are stored as raw RFC 5322
   bytes, content-addressed, deduplicated, and never rewritten. Byte identity
   (storage) is distinguished from logical identity (what the user regards as one
   email), so the same message captured from IMAP, Takeout, Graph, and PST merges
   instead of multiplying (§13).
2. **Provenance.** Which account, which folder, which capture run — recorded in
   append-only manifests (§8).
3. **Tamper evidence.** Manifests form a hash chain committed to by per-run Merkle
   roots, signed by the owner and independently timestamped (§9–§11). The archive's
   history can be verified by a stranger, within the limits stated in §2.
4. **Longevity.** Every payload is a `.eml` file inside a standard ZIP archive. An
   archive remains readable with no mailpack software and no surviving
   implementation: any ZIP tool opens a pack, and any mail client opens an entry.

Tamper evidence is a structural property of the format, not its purpose; the purpose
is consolidation, provenance, and longevity.

### 1.1 Non-goals

The format deliberately does not provide:

- **Encryption at rest.** The archive is plaintext for recoverability. Deployments
  requiring confidentiality encrypt beneath the format (full-disk or volume
  encryption).
- **Multi-writer concurrency.** One writer at a time (§16). §8.1 reserves syntax for
  a future multi-parent chain; this version defines no merge semantics.
- **Sub-message deduplication.** Objects are whole messages: an attachment shared by
  thirty messages is stored thirty times (§6). Deduplicating below the message is a
  job for the storage layer holding the archive, not for the format.
- **Source-state reconstruction.** Manifests record what a run observed, not what a
  source contained. The format carries no completeness claims about any enumeration,
  so "the mailbox as it stood at time T" is not derivable; §2 states why such claims
  are excluded.
- **Synchronization.** An archive is a directory; it replicates with any file-copy
  tool. The format defines no wire protocol and no conflict resolution.
- **Compliance retention** (SEC 17a-4, FINRA, MiFID II) and similar regulatory
  regimes.
- **Live mail storage.** The archive is written by capture and maintenance runs, not
  by a mail client's hot path.

## 2. Threat model

This section states what the evidence machinery proves and what it does not. Verify
tooling MUST NOT use output language that overstates any of it.

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

**Tail truncation.** Anchoring is transitive backwards only; there are no forward
pointers. Deleting the newest runs deletes their anchors with them and leaves a
shorter archive that verifies cleanly. Truncation is therefore undetectable from
archive contents alone; detection requires out-of-band knowledge of the expected
chain head. The format supplies that head in a compact, disclosure-free form — the
32-byte `SHA-256(E)` of the latest end record (§9) — which the owner can publish,
deposit with any independent party, or have counter-signed. A receipt for that value
held outside the archive makes truncation past it detectable by anyone holding the
receipt. Absent such a deposit, truncation is undetectable.

**Witness records are recorded retrievals.** A witness record (§8.4) preserves an
external artifact — a DKIM key record, for example — that the owner's software states
it retrieved at a stated time. Anchoring makes the statement tamper-evident
afterwards; it does not make the retrieval honest. Each record therefore carries its
provenance: `proven` when captured trust-chain material lets a verifier establish,
from the archive alone, that the artifact came from its claimed source; `asserted`
when nothing but the owner's word places it there. Asserted artifacts gain value
through corroboration — the same artifact recorded independently by other archives or
observers — and MUST NOT be presented as proven. In every case the record's stated
result is recomputable from stored bytes (§8.4), so the artifact's provenance is the
only trust surface.

**Claims must be checkable.** Manifest records document what the owner's software did
— runs, observations, deletions — or preserve external perishable artifacts that
cannot be re-fetched later (witness records). The format records no self-assessments:
a claim such as "this folder was enumerated completely" preserves nothing a stranger
can check, and its permanence would add trust surface without adding evidence. Record
types that fail this test are excluded by design.

## 3. Terminology

- **Object** — the raw bytes of one message as captured, identified by its SHA-256.
- **Pack** — a sealed, immutable ZIP archive (ZIP64 extensions as needed, §6)
  containing objects.
- **Staging** — loose objects not yet sealed into a pack.
- **Run** — one capture or maintenance operation, identified by a ULID, producing one
  manifest.
- **Manifest** — an append-only JSONL record of what a run observed or did.
- **Chain** — the backward hash links (`prev_run`, `prev_sha256`) connecting each run
  to its predecessor's manifest bytes.
- **End record** — a manifest's final record: counts plus the run's Merkle root. A
  manifest whose final line is a valid end record is *complete*; any other manifest
  is *interrupted* (§8.5).
- **Anchor** — an independent timestamp token (`.tsr`, `.ots`) over a run's seal
  target.
- **Byte identity** — SHA-256 of an object's raw bytes. Governs storage and dedup.
- **Logical identity** — a versioned digest over canonicalised message features.
  Governs message counts, merge, search, and UI. One logical message may have many
  byte variants.
- **Tombstone** — a manifest record documenting deliberate deletion of an object.
- **Witness record** — a manifest record preserving an external, perishable artifact
  that corroborates something about an archived message, together with a recomputable
  check result (§8.4).
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

An object is the raw captured bytes of one message. Objects are immutable: an
implementation MUST NOT alter the bytes of a stored object.

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

The `.eml` extension carries no semantics but is REQUIRED: extracted files open
directly in mail clients.

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
  of the uncompressed entry data. The ZIP CRC-32 is not a substitute for this
  comparison; implementations MUST NOT rely on it.
- Compression: writers SHOULD use DEFLATE; STORE is permitted. Readers MUST support
  both. No other methods, no encryption, no split/spanned archives.
- Writers SHOULD order entries by ascending hash when the full entry set is known
  before writing begins (e.g. sealing staged objects), so identical object sets
  produce identical entry order. A streaming bulk writer MAY write entries in arrival
  order.
- Writers SHOULD seal packs in the 256 MiB – 1 GiB range. This is a target, not a
  conformance bound, and it assumes an archive on local storage; a continuously
  replicated archive may prefer smaller packs, because a deletion rewrite (§17)
  rewrites — and re-transfers — whole packs.

Sealing MUST be crash-safe: build the pack at a `.tmp-` name, verify it by reading
back every entry and recomputing its hash, sync it durably, rename it into place,
sync the parent directory, and only then remove any sealed objects from staging.

Rationale (informative): loose small files are pathologically slow under synchronous
per-file scanning; packs collapse a million paths to a few hundred; the central
directory doubles as a pack index; and a pack is recoverable with any ZIP tool, no
mailpack software required. The cost of storing whole messages is the absence of
sub-message deduplication: an attachment shared across a reply chain is stored once
per distinct message, and per-entry compression cannot recover redundancy between
entries. This is accepted (§1.1); a storage layer holding packs can recover it below
the format (block-level or content-defined deduplication) without touching the
archive.

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
- Any other unparseable line — an empty line included — makes the manifest
  *manifest-malformed* (§18). Reporting tools MUST still process the parseable
  records around it.

### 8.1 `run` record

The first line of every manifest MUST be a `run` record:

```json
{"type": "run", "run": "01J8ZQ6C3H2K9P4D8W1M5XETRV", "format_version": "0.1",
 "archive_id": "01J8ZQ5X7E9RVN3TCK4WDBGHMA",
 "prev_run": "01J8ZQ4A2M6PWX8YB0CDEFGHJK",
 "prev_sha256": "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c",
 "keys_sha256": "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7",
 "started": "2026-08-15T01:02:03Z", "source": "imap:alice@example.com",
 "kind": "ingest"}
```

- `run` — the run ULID; MUST match the file name.
- `format_version` — the archive's format version (§4.1), `"MAJOR.MINOR"`. REQUIRED.
- `archive_id` — the archive's ULID (§4.1); binds the run to its archive.
- `prev_run` / `prev_sha256` — the chain link: the preceding run's ULID and the
  lowercase-hex SHA-256 of that run's manifest file — its exact bytes at link time,
  whether complete or interrupted. Both `null` on the archive's first run. Both
  fields are scalars in this version: writers MUST emit a single ULID and a single
  hash. A future minor version may define array-valued links (a run with several
  predecessors); a reader encountering an array MUST treat the manifest as written
  by an unsupported future version, not as malformed. Such a manifest's chain
  position is uninterpretable by this version: its chain status is *not applicable*
  (§18), it takes no part in fork detection, and — the chain tip being
  undeterminable — a writer MUST refuse to append, the same refusal required below
  when the chain tip cannot be determined.
- `keys_sha256` — lowercase-hex SHA-256 of the exact bytes of `meta/keys.json` as
  the run began, or `null` if the file did not exist. REQUIRED. Binds the registry
  state into the anchored history (§10.2).
- `started` — RFC 3339 UTC.
- `source` — an opaque source identifier, or `null` for a run that observes no
  source (`maintenance`, `delete`, and `recovery` runs). A run observes at most one
  source: every message record a run emits first-hand is an observation from that
  run's `source`. A record re-emitted by recovery (§12) keeps its original
  attribution: its source is found by following `recovers` links back to the first
  run that is not a recovery run. If that walk fails — some manifest along it has no
  parseable run record — the record's source is *unknown*: it still participates in
  presence/absence resolution (§18) but not in per-source resolution. This
  attribution rule is what makes per-source resolution well defined.
- `kind` — `"ingest"`, `"delete"`, `"maintenance"`, or `"recovery"`. A recovery run
  additionally carries `"recovers": "<run-ulid>"`, the interrupted run it re-emits
  (§12).

Runs form a single backward chain: exactly one run has `prev_run: null`, and every
other run's `prev_run` names an existing run. Two manifests whose run records name
the same `prev_run` — two claiming `null` included — are a *chain fork* (§18); a
writer discovering a fork MUST refuse to append new runs until it is resolved.

Header damage has defined semantics. A parseable first line that is not a `run`
record, a `run` field that does not match the file name, or an `archive_id` that
does not match the archive marker each make the manifest *manifest-malformed*
(§18). A manifest with no parseable line at all is a *headerless crash artifact*:
the §8 lifecycle creates the file at its final name before the run record is
appended, so a crash in that window durably leaves one — it is an interrupted run
with no records, a reported warning, never damage. A manifest lacking a parseable
run record makes no chain claim: it takes no part in fork detection, and its own
chain status is *not applicable*. A writer MUST refuse to append when the chain
tip cannot be determined: on a fork, and on any manifest that has parseable
records but no parseable run record (its chain position is unknowable). A
headerless crash artifact with no records claims no position and blocks nothing.

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
  it (§13; a manifest records the identity computed at write time — see §13.1).
  REQUIRED. `identity_v: 0` with `logical_id: null` means "not computed" (e.g. the
  message failed to parse; archival is never blocked by parsing).
- `provider_id` — provider-native message ID (e.g. Gmail `X-GM-MSGID`, IMAP UID
  qualified by UIDVALIDITY, Graph message id), or `null`. Format is source-specific
  and opaque; the value is meaningful only relative to the record's source (§8.1).
- `folders` — folder/label names as reported by the source. MAY be empty. Resolved
  per source (§18).
- `date` — the message's internal date as reported by the source (e.g. IMAP
  `INTERNALDATE`), RFC 3339 UTC, or `null`. This is the source's storage timestamp,
  not the message's `Date:` header — §13.2 reads the latter from the message bytes.
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

### 8.4 `witness` record

Mail carries corroborating material whose later verification depends on external,
perishable artifacts: DKIM keys rotate out of DNS, certificate chains expire, key
servers disappear. A witness record preserves such an artifact at the moment it can
still be retrieved, together with the result of checking an archived message against
it. The artifact is the evidence; the anchored manifest fixes when it was captured
(§2).

Witness records share a common core; protocol-specific fields are selected by a
`protocol` discriminator. This version registers one protocol: `dkim` (§8.4.1).
Future protocols (§20) are added by registering a new discriminator value and its
fields — the common core is never revised. Readers MUST skip witness records whose
`protocol` they do not implement, and verifiers MUST report them as unrecognized
rather than as damage: the forward-compatibility rule §8 applies to unknown record
types extends to unknown protocols within this one.

Common fields, all REQUIRED:

- `sha256` — the checked object.
- `protocol` — the registered protocol identifier.
- `artifact` — the retrieved artifact in its original retrieved form, base64
  (RFC 4648, with padding). The raw bytes are the durable evidence; any parsed
  rendering of them is a per-protocol convenience.
- `trust_chain` — material chaining the artifact to a trust root independent of the
  owner, in its retrieved form, base64; `null` when none was captured. The chain is
  exactly as perishable as the artifact and cannot be fetched retroactively; writers
  SHOULD capture it whenever the retrieval path offers it.
- `provenance` — `"proven"` or `"asserted"`. `"proven"` REQUIRES a `trust_chain`
  from which a verifier can establish, offline, that the artifact came from its
  claimed source. Anything less is `"asserted"`: the owner's software states that it
  retrieved these bytes, and nothing in the archive can prove it (§2). Provenance is
  a property of each observation, not of a protocol.
- `result` — the protocol-defined check result.
- `checked` — retrieval and check time, RFC 3339 UTC.

Recomputability is the family's defining requirement: every registered protocol MUST
define `result` so that a verifier holding nothing but the archive can recompute it
from the stored artifact and the message bytes — and disagree with the record. The
stated result is never part of the trust surface; the artifact's provenance is the
whole of it.

Witness records are observations, not state. They accumulate; nothing supersedes an
earlier record, and a later failure does not erase an earlier anchored success —
artifact rotation and transport mangling make later failures expected for honest
messages.

#### 8.4.1 Protocol: `dkim`

One record per DKIM verification attempt against an archived message, written only
when a DNS key record was actually retrieved. The key is the perishable artifact; it
is stored even when verification failed.

```json
{"type": "witness", "protocol": "dkim",
 "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
 "artifact": "<base64 of: v=DKIM1; k=rsa; p=MIIBIjANBgkq…>",
 "trust_chain": null,
 "provenance": "asserted",
 "result": "pass",
 "checked": "2026-08-15T01:02:05Z",
 "domain": "example.com",
 "selector": "s1",
 "from_domain": "example.com",
 "aligned": "strict",
 "body_length": null}
```

- `artifact` — the DKIM key record: the RDATA of the TXT record at
  `<selector>._domainkey.<domain>`, with its character-strings concatenated
  (RFC 6376 §3.6.2.2).
- `trust_chain` — DNSSEC validation material sufficient to validate that TXT RRset
  up to the root zone trust anchor, DNS wire format, or `null`. [DRAFT: the exact
  serialization is unresolved (§20).] `provenance: "proven"` REQUIRES such a chain;
  an unvalidated retrieval is `"asserted"`.
- `result` — `"pass"` or `"fail"`: RFC 6376 verification of the message's signature
  against the key in `artifact`. Recomputable per §8.4.
- `domain`, `selector` — the signature's `d=` and `s=`. REQUIRED.
- `from_domain` — the domain of the first `From` mailbox at check time. REQUIRED.
- `aligned` — `"strict"`, `"relaxed"`, or `"none"`: the alignment judgment between
  `domain` and `from_domain`, computed at check time. The raw `from_domain` is
  stored alongside the judgment because relaxed alignment depends on the public
  suffix list, which drifts; a bare stored boolean would rot. REQUIRED.
- `body_length` — the signature's raw `l=` value, or `null` when absent. REQUIRED.

Display requirements (normative for tools rendering these records): a pass whose
`aligned` is `"none"` MUST NOT be rendered as verification of the sender; a pass
with a non-null `body_length` MUST NOT be rendered as verification of the full
message content; an `"asserted"` record MUST NOT be rendered as if the artifact's
origin were proven (§2).

### 8.5 `end` record

The last line of a complete manifest:

```json
{"type": "end", "run": "01J8ZQ6C3H2K9P4D8W1M5XETRV",
 "archive_id": "01J8ZQ5X7E9RVN3TCK4WDBGHMA",
 "finished": "2026-08-15T01:07:00Z",
 "messages": 2412, "tombstones": 0,
 "root": "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9"}
```

- `run`, `archive_id` — MUST equal the run record's values. The end record is
  the seal target (§9) and travels alone in disclosure bundles, so it must
  identify the run and archive it seals by itself; a mismatch is
  *manifest-malformed* (§18). REQUIRED.
- `finished` — RFC 3339 UTC. REQUIRED.
- `messages`, `tombstones` — counts of those record types in this manifest. REQUIRED.
- `root` — the run's Merkle root (§9). REQUIRED.

A manifest is *complete* iff its final line is a valid end record satisfying the
requirements above. Nothing follows an end record: material after one —
parseable or not — makes the manifest *manifest-malformed* (§18) and the manifest
is not complete; an end record seals only a manifest it terminates. Recovery
treats such a manifest like any other malformed interrupted manifest (§12):
parseable records are salvaged by re-emission, wherever they sit relative to the
stray end record, but the manifest never reports
*recovered* — and, being incomplete, none of its lines count as coverage for any
other run.

## 9. Merkle commitment and the seal target

Every complete run commits to its records with a Merkle tree in the
[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962#section-2.1) shape:

- leaf hash = `SHA-256(0x00 ‖ leaf)`; interior node = `SHA-256(0x01 ‖ left ‖ right)`.
- For n > 1 leaves the tree splits after the largest power of two smaller than n. (The
  tree is never empty: the run record is always a leaf.)
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
4. the end-record line E — which itself names the run and archive (§8.5),
5. the signature envelope (§10.1),
6. any timestamp tokens (§11).

The recipient verifies: leaf + audit path → root; root equals the `root` in E; E's
`run` and `archive_id` name the run and archive being claimed; the signature over E
verifies against the disclosed key (whose fingerprint the recipient checks out of
band); the timestamp tokens cover `SHA-256(E)`. This proves the record was part of
that run of that archive, sealed by the owner at or before the anchored time —
subject to §2.

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
the anchors' job (§11) — and neither proves authenticity (§2). Documentation built on
this spec should state both limits plainly.

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

Keys have a lifecycle: over decades, users lose keys and change machines.

- Multiple keys MAY be trusted concurrently.
- Rotation: add the new key, mark the old one `retired` (RFC 3339). Retired keys still
  verify old manifests; they SHOULD NOT sign new ones.
- A lost key is not corruption. Verification reports runs signed by unknown keys as
  *provenance-unverifiable*, distinct from *corrupt* (§18).

The registry is bound to the run chain: every run records `keys_sha256` (§8.1), the
hash of `meta/keys.json` as the run began. Editing the registry therefore leaves a
mark — the file no longer hashes to the newest run's recorded value — and concealing
the edit requires appending a new run, whose anchors postdate it (§2). A transient
mismatch immediately after rotation is expected; rotation tooling SHOULD finish by
recording a maintenance run so the new registry state is promptly anchored. Verify
tooling MUST report a registry whose bytes do not hash to the newest run's
`keys_sha256`.

The binding does not let a verifier reconstruct historical registry contents from
hashes alone, and it does not defeat an attacker who extends the chain with runs
signed by keys they inserted. Out-of-band fingerprint comparison remains the stronger
check: verify tooling MUST support being given a key set out-of-band in place of
`meta/keys.json`.

## 11. Timestamps and anchoring

Two anchor mechanisms, because they fail in opposite directions:

- `manifests/<run-ulid>.tsr` — one or more RFC 3161 `TimeStampResp` structures, DER,
  concatenated. Readers parse the file sequentially: each structure is a DER
  SEQUENCE whose encoded length delimits it, and the next begins at the following
  byte. Each MUST cover `SHA-256(E)` (§9). Writers SHOULD obtain tokens from ≥ 2
  independent TSAs — no single authority may be the point of trust.
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
- The recovery run appends every parseable record line of the interrupted manifest
  whose `type` is neither `run` nor `end` **verbatim** — byte-identical lines,
  original timestamps included, record types the recovering writer does not itself
  understand included (verbatim bytes require no understanding) — then finishes
  normally, gaining its own end record, root, signature, and anchors. `run` and
  `end` lines are excluded because each may appear only at its own manifest's edge
  (§8.1, §8.5); everything between the edges is salvage.
- A trailing LF-less partial line in the interrupted manifest is not a record and is
  not re-emitted. A mid-file unparseable line is damage, not interruption: the
  manifest is *manifest-malformed* (§18), permanently. Recovery still applies to its
  parseable records — salvage costs nothing and asserts nothing about the damaged
  line — but a malformed manifest never reports *recovered*: coverage cannot speak
  for lines nobody can parse.

Writers MUST perform recovery for all uncovered interrupted manifests — malformed
ones included — after acquiring the writer lock and before beginning any other run,
and then proceed normally: nothing about a crash artifact, damaged or not, blocks
new runs. Recovery-before-new-runs is a correctness precondition for §18's
latest-record resolution, not hygiene: re-emitted message records land in a run
later than the crash, so if any other run — a deletion, say — could interpose
between crash and recovery, a re-emitted observation of a deliberately deleted
object would become its latest record and flip *excised* to *missing*. Because
every writer recovers first, under the same lock, no run can ever interpose.

A recovery run is an ordinary run: it can itself be interrupted, and is then
covered or re-emitted under exactly these rules — re-emission of a re-emission is
still byte-identical to the original records, so coverage converges.

An interrupted run is *covered* when every parseable record line in it whose `type`
is neither `run` nor `end` appears byte-identically in some later complete run
(vacuously true when it has no such records). Verification reports a covered interrupted run as *recovered* (§18) —
transient in effect, while the crash artifact stays honestly visible forever —
unless it is also manifest-malformed, in which case it stays *interrupted*.

Loss bounds (informative): a staging writer makes object bytes durable before
appending the record, so a crash costs at most one manifest line — the object
survives as `unattested` and the next observation re-records it (§8.2). A bulk writer
appends records only after its pack seals, so a crash mid-pack loses only the
in-flight temp pack — never archived, re-readable from the local source via an import
cursor (§15) — and a crash between seal and record-append leaves sealed objects
`unattested` until resume re-records them. No durably-stored message ever loses
bytes; attestation loss is bounded and self-heals. Re-emission roughly doubles the
interrupted manifest's record bytes; bulk runs checkpoint per pack roll, capping
that at one checkpoint's records, so the case that amplifies is a single very large
incremental run crashing near its end (see §20 on manifest splitting).

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

A manifest's `logical_id` is therefore a capture-time claim: it records what the
then-current algorithm computed, reproducibly checkable by anyone holding the bytes.
Identity under the *current* version is derived state and lives in the index (§14).
After the algorithm advances, implementations MUST NOT treat older manifests'
`logical_id` values as current-version identity.

### 13.2 Algorithm v1 [DRAFT — test vectors pending; do not implement as final]

Inputs: the raw object bytes, parsed as RFC 5322.

Identity is tiered: a message bearing a Message-ID is identified by it; a message
without one falls back to content features. A single digest over many fields would
require exact agreement on every one, and the capture paths that motivate logical
identity (§13) are precisely those that perturb dates, encodings, and bodies; a
missed merge silently double-counts, which is the failure the format exists to
prevent. The tier is a function of the message bytes alone — implementations
recompute it, and it is not recorded in manifests.

Fields:

1. **message-id**: the `Message-ID` header value with surrounding whitespace and one
   pair of enclosing angle brackets removed. Absent or unparseable → the message has
   no message-id and identity uses tier 2.
2. **from**: the addr-spec of the first mailbox in `From`, lowercased. Absent or
   unparseable → empty string.
3. **date**: the `Date` header parsed per RFC 5322, converted to Unix seconds (UTC),
   rendered as a decimal integer. Absent or unparseable → empty string. (This is the
   message's own header, not the source-reported `date` of §8.2.)
4. **body-hash**: lowercase hex SHA-256 of the canonicalised body: decode the
   transfer encoding of the first `text/*` leaf part (or the raw body if
   unstructured), normalise line endings to LF, strip trailing whitespace from each
   line, strip trailing empty lines. [DRAFT: charset handling, multipart selection,
   and HTML-vs-plain preference are unresolved — this is exactly the empirical work
   the version number exists for.]

Each input is framed by its length — an unambiguous encoding regardless of field
contents:

```
frame(x) = len(x) as 8-byte big-endian ‖ x
```

Tier 1 — message-id present:

```
logical_id = sha256(frame("mailpack-identity-v1-t1") ‖ frame(message-id) ‖ frame(from))
```

Tier 2 — message-id absent:

```
logical_id = sha256(frame("mailpack-identity-v1-t2") ‖ frame(date) ‖ frame(from) ‖
                    frame(body-hash))
```

rendered as lowercase hex. Two messages are the same logical message iff their
`logical_id`s are equal; the distinct context strings keep the tiers disjoint.

[DRAFT: tier 1's exposure is over-merge — Message-IDs duplicated across genuinely
distinct messages by drafts, resends, and defective generators. Over-merge loses no
data: identity never alters stored bytes, and a later identity version can split
what v1 joined. Its real frequency is an empirical question for the corpus.]

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
  already-replaced pack) MAY also be cleaned by a later lock holder.
- **NFS caveat.** Advisory locking is unreliable on network filesystems. An archive
  on NFS/SMB gets no single-writer guarantee from this spec; keep archives on local
  disks and replicate instead.

## 17. Deletion

Append-only governs how the store works, not what the owner may do. Deletion is a
deliberate, recorded operation:

1. Write a new manifest (run `kind: "delete"`) containing one tombstone record per
   deleted object; finish, sign, and anchor it like any other run. The record
   precedes the removal: bytes are destroyed only after their tombstones are durable.
   The gate is exactly the tombstone run's durable completion — its end record
   synced. Signing is local; anchoring is asynchronous per §11; deletion never
   waits on an external service.
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
order — the unique path of `prev_run` links walked forward from the genesis run —
then records in file order within a run. Runs off that path (fork branches,
manifests making no chain claim) follow the chained runs, ordered by run ULID
among themselves: a best effort, since such an archive already reports damage.
Run ULIDs normally coincide with chain order, but chain links, not timestamps,
are authoritative — "later" in this spec (coverage, §12; latest-record
resolution) always means later in this total order. Per object, the latest `message` or
`tombstone` record determines its expected state — a message record expects presence,
a tombstone expects absence, and a later observation reverses an earlier tombstone
(re-ingest after deletion is legitimate). This rule is sound only because recovery
precedes any new run (§12): re-emitted records can never leapfrog a later tombstone.

**Per-source resolution.** Presence and absence resolve across all sources, as
above. Descriptive fields resolve per source. A record's source is determined by
the attribution rule of §8.1: the emitting run's `source`, followed through
`recovers` links for re-emitted records; records whose attribution walk fails have
unknown source and take no part in this rule. Per object and per source, the latest message
record's `folders` and `provider_id` are current for that source; earlier records
are history. Sources are never collapsed: an object simultaneously in `INBOX` at one
source and `Archive` at another has both, and a conformant reader reports them per
source.

Per object (union of all records vs. what exists):

| status | meaning |
|---|---|
| `ok` | expected present; bytes present, matching the recorded size and hashing to the recorded ID |
| `corrupt` | expected present; bytes present but the recorded size or ID does not match |
| `missing` | expected present; absent — data loss |
| `excised` | expected absent (tombstoned); absent |
| `zombie` | expected absent (tombstoned); still present — deletion incomplete, re-runnable |

Objects present in the store but referenced by no record are `unattested`: a crash
orphan or an out-of-band file placement (§2). Verifiers MUST report the store⇄manifest
diff in both directions.

Per run:

| dimension | statuses |
|---|---|
| completion | `complete` / `interrupted` / `recovered` (interrupted but covered, §12; a malformed manifest never reports recovered) |
| chain | `chain-ok` / `chain-broken` (prev missing or `prev_sha256` mismatch) / `chain-fork` (run records sharing a `prev_run`) / not applicable (no parseable run record, or an array-valued chain link from an unsupported future version; §8.1) |
| root | `root-ok` / `root-mismatch` (recomputed tree ≠ end record) / not applicable (interrupted) |
| integrity | `manifest-malformed` (any unparseable non-trailing line; reported with line numbers) |
| signature | `sig-ok` / `sig-unknown-key` (provenance unverifiable, not corruption) / `sig-invalid` / `sig-missing` / not applicable (interrupted — no end record to sign, §10.1) |
| anchors | `ts-ok` / `ts-pending` (OTS awaiting upgrade) / `ts-missing` / `ts-invalid` (a present token fails verification or does not cover `SHA-256(E)`; per token, the run reports the worst) |

Witness records (§8.4) never affect the statuses above. A verifier MAY recompute
their results from stored artifacts and message bytes; if it does, it MUST report
disagreements, alongside each record's `provenance`. Witness records with
unrecognized protocols are reported as unrecognized, never as damage.

An archive is **intact** iff no object is `corrupt` or `missing` and no run is
`sig-invalid`, `ts-invalid`, `chain-broken`, `chain-fork`, `root-mismatch`, or
`manifest-malformed` — wrong evidence is worse than absent evidence, for anchors as
for signatures. Everything else — `interrupted`, `recovered`, `zombie`,
`unattested`, `sig-unknown-key`, `sig-missing`, `ts-pending`, `ts-missing` — is a
reported warning, never conflated with damage.

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
  (anchor verification MAY use the network; everything else works offline). A
  verifier MUST NOT decompress an entry beyond the size its object's records claim:
  output exceeding the recorded `size` already fails the size check (`corrupt`,
  §18), and unbounded decompression would let a hostile pack exhaust the verifier
  through the very read-back path verification requires. Entries referenced by no
  record are identified as `unattested` by entry name alone and need not be
  decompressed at all.

The conformance corpus lives in [`corpus/`](corpus/); identity test vectors in
[`vectors/`](vectors/). Both are versioned with this spec.

## 20. Open questions (tracked toward v1.0)

- Identity v1 body canonicalisation and tier-1 over-merge frequency (§13.2) — both
  need the ground-truth corpus first.
- The `trust_chain` serialization for protocol `dkim` (§8.4.1).
- Witness protocol registrations beyond `dkim` — ARC chains, S/MIME certificate
  validation material, OpenPGP keys — additive under §8.4.
- Maximum manifest size / manifest splitting for very large runs — which would also
  cap recovery's re-emission cost when a huge run is interrupted (§12).
- The stdlib-only recovery reader ships with this repo before v1.0 — and MUST surface
  staging objects (§19).
- Export tooling (Maildir/mbox). Deliberately outside conformance: longevity is a
  structural property of ZIP + `.eml`, and an exporter is a tool, not a format
  obligation.
