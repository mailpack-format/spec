# mailpack — an open format for personal mail archives

**Version: 0.1-draft** · Status: DRAFT — nothing here is frozen. The pack layout (§4–§6)
freezes at v1.0; the logical-identity algorithm (§8) is versioned independently and is
never frozen (see §8.1).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as
described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 1. Goals

A mailpack archive is a folder of files that:

1. stores raw RFC 5322 messages content-addressed and deduplicated, without ever
   rewriting a message;
2. records provenance (which account, which folder, which capture run) in append-only
   manifests;
3. can be verified by a stranger: signatures detect tampering, independent timestamps
   prove existence at a point in time;
4. can be recovered with no mailpack software — every payload is a `.eml` file inside a
   standard ZIP archive;
5. distinguishes *byte identity* (storage) from *message identity* (what the user thinks
   of as "one email"), and says so explicitly.

Non-goals: encryption at rest (use full-disk encryption; the archive is plaintext for
recoverability), multi-writer concurrency, compliance retention (17a-4/FINRA/MiFID).

## 2. Terminology

- **Object** — the raw bytes of one message as captured, identified by its SHA-256.
- **Pack** — a sealed, immutable ZIP64 archive containing objects.
- **Staging** — loose objects not yet sealed into a pack.
- **Run** — one capture or maintenance operation, identified by a ULID, producing one
  manifest.
- **Manifest** — an append-only JSONL record of what a run observed or did.
- **Byte identity** — SHA-256 of an object's raw bytes. Governs storage and dedup.
- **Logical identity** — a versioned digest over canonicalised message features. Governs
  message counts, merge, search, and UI. One logical message may have many byte variants.
- **Tombstone** — a manifest record documenting deliberate deletion of an object.

## 3. Archive layout

```
<root>/
  mailpack.json                   # archive marker (§3.1)
  packs/
    <pack-ulid>.zip               # sealed packs (§5)
    staging/
      <sha256>.eml                # loose objects (§4)
  manifests/
    <run-ulid>.jsonl              # manifest (§7)
    <run-ulid>.sig                # Ed25519 signature over the manifest file (§9)
    <run-ulid>.tsr                # RFC 3161 timestamp tokens (§10) [DRAFT]
    <run-ulid>.ots                # OpenTimestamps proof (§10) [DRAFT]
  index/                          # derived, disposable (§11)
  meta/
    keys.json                     # trusted public keys (§9.2)
    sources.json                  # account config, sync cursors (§12)
```

`packs/` and `manifests/` **are** the archive. Everything under `index/` MUST be
rebuildable from them. `meta/` is configuration plus the key registry; §9.2 defines what
of it matters to verification.

All ULIDs are [Crockford-base32 ULIDs](https://github.com/ulid/spec), 26 characters,
uppercase. All SHA-256 values in file names and manifests are lowercase hex, 64
characters.

### 3.1 Archive marker

`mailpack.json` identifies a directory as a mailpack archive:

```json
{
  "mailpack": 1,
  "format_version": "0.1-draft",
  "archive_id": "01J8ZQ5X7E9RVN3TCK4WDBGHMA",
  "created": "2026-08-15T00:00:00Z"
}
```

- `mailpack` — always the integer `1`.
- `format_version` — the spec version the archive was created against.
- `archive_id` — a ULID assigned at creation, stable for the archive's life.
- `created` — RFC 3339 UTC timestamp.

Readers MUST refuse to treat a directory as an archive if `mailpack.json` is absent or
`mailpack` ≠ 1. Unknown keys MUST be ignored (here and in every JSON object in this
spec).

## 4. Objects and staging

An object is the raw captured bytes of one message. Objects are immutable: no
implementation may ever alter the bytes of a stored object.

- Object ID = SHA-256 of the raw bytes, lowercase hex.
- A newly ingested object is written to `packs/staging/<sha256>.eml`.
- Writers MUST write staging objects atomically (write to a temporary name in the same
  directory, then rename).
- Writers MUST NOT store an object whose ID already exists in staging or in any sealed
  pack (dedup is by byte identity). Readers MUST tolerate duplicates anyway — a crash
  between sealing and staging cleanup can leave one — and treat any copy as equivalent.

The `.eml` extension is cosmetic but REQUIRED: it makes extracted files open in mail
clients, at no cost.

## 5. Packs

A pack is a ZIP archive (ZIP64 extensions permitted and expected) whose entries are
objects. Packs are sealed once and never modified; the only permitted operation on a
sealed pack is replacement during a deletion rewrite (§13).

Requirements:

- File name: `packs/<pack-ulid>.zip`, ULID assigned at seal time.
- Entry name: exactly `<sha256>.eml` — no directories, no other entries.
- Entry contents: the object's raw bytes. The entry name's hash MUST equal the SHA-256
  of the uncompressed entry data.
- Compression: writers SHOULD use DEFLATE; STORE is permitted. Readers MUST support
  both. No other methods, no encryption, no split/spanned archives.
- Writers SHOULD order entries by ascending hash, so identical object sets produce
  identical entry order.
- Writers SHOULD seal packs in the 256 MiB – 1 GiB range. This is a target, not a
  conformance bound.

Sealing MUST be crash-safe: build the pack at a temporary name, verify it by reading
back every entry and recomputing its hash, sync it durably, rename it into place, and
only then remove the sealed objects from staging.

Rationale for ZIP64 packs (informative): loose small files can be pathologically slow 
under synchronous scanning; packs collapse a million paths to a few hundred; the 
central directory doubles as a pack index; and recovery without mailpack software 
is "double-click the pack".

## 6. Object location

An object's location (staging vs. which pack) is *derived* state, discoverable by
listing `packs/staging/` and reading pack central directories. Manifests never record
pack membership — this keeps every manifest valid across pack sealing and deletion
rewrites.

## 7. Manifests

A manifest is a UTF-8 JSONL file, `manifests/<run-ulid>.jsonl`: one JSON object per
line, each line terminated by LF (`\n`), no BOM. Manifests are append-only during their
run and immutable afterward — a sealed manifest file is never edited, because
signatures and timestamps cover its exact bytes.

Every record has a `type` field. Readers MUST skip records with unknown `type` values.

### 7.1 `run` record

The first line of every manifest MUST be a `run` record:

```json
{"type": "run", "run": "01J8ZQ5X7E9RVN3TCK4WDBGHMA", "format_version": "0.1-draft",
 "started": "2026-08-15T01:02:03Z", "source": "imap:alice@example.com",
 "kind": "ingest"}
```

- `run` — the run ULID; MUST match the file name.
- `started` — RFC 3339 UTC.
- `source` — an opaque source identifier; `null` for maintenance runs.
- `kind` — `"ingest"`, `"delete"`, or `"maintenance"`.

### 7.2 `message` record

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

- `sha256` — byte identity (§4). REQUIRED.
- `size` — object size in bytes. REQUIRED.
- `logical_id`, `identity_v` — logical identity and the algorithm version that produced
  it (§8). REQUIRED. `identity_v: 0` with `logical_id: null` means "not computed"
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

### 7.3 `tombstone` record

Documents deliberate deletion (§13):

```json
{"type": "tombstone",
 "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
 "deleted": "2026-08-15T09:00:00Z",
 "reason": "user"}
```

- `sha256` — the deleted object. REQUIRED.
- `deleted` — RFC 3339 UTC. REQUIRED.
- `reason` — free text; `"user"` is conventional. OPTIONAL.

A tombstone asserts: this object once existed, and its absence is deliberate. Verifiers
use it to distinguish *excised* from *missing* (§14).

## 8. Logical identity

Byte identity double-counts real mailboxes: Takeout injects `X-Gmail-Labels` and munges
`From ` lines; Microsoft Graph synthesises MIME on request; PST conversion always
produces synthesised bytes. The same message captured two ways never matches
byte-for-byte. Logical identity is the versioned, reproducible answer to "are these the
same email?"

### 8.1 Versioning

The algorithm is identified by an integer `identity_v`, carried on every message record.
Implementations MUST reproduce published versions bit-exactly against the test vectors
in [`vectors/`](vectors/). Fixes and improvements ship as a new version — never as a
silent change to an existing one. Old manifests keep their old `identity_v`; nothing is
rewritten.

### 8.2 Algorithm v1 [DRAFT — test vectors pending; do not implement as final]

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

Then:

```
logical_id = sha256("mailpack-identity-v1" || 0x00 || message-id || 0x00 ||
                    date || 0x00 || from || 0x00 || body-hash)
```

rendered as lowercase hex.

Correctness of a version is defined against the labeled ground-truth corpus in
[`corpus/`](corpus/), not against intuition.

## 9. Signatures

### 9.1 Signature file

`manifests/<run-ulid>.sig` is a JSON envelope:

```json
{"alg": "ed25519",
 "key": "4f2d8a7c1b9e6350a2c4e8d1f7b3a5c9e0d2f4a6b8c1d3e5f7a9b0c2d4e6f801",
 "sig": "<base64, 64-byte Ed25519 signature>"}
```

- `alg` — MUST be `"ed25519"` in this version.
- `key` — the signing key's fingerprint: lowercase hex SHA-256 of the 32-byte public
  key.
- `sig` — standard (RFC 8032) Ed25519 signature over the exact bytes of the
  corresponding `.jsonl` file, base64 (RFC 4648, with padding).

The signature detects corruption and tampering. It does **not** prove time — that is
the timestamps' job (§10). Docs built on this spec should say so plainly.

### 9.2 Key registry and lifecycle

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
  *provenance-unverifiable*, distinct from *corrupt* (§14).
- Verifiers MAY be given a key set out-of-band instead of trusting `meta/keys.json`
  (the registry travels with the archive, so a tamperer can rewrite it; out-of-band
  fingerprint comparison is the stronger check and MUST be supported by verify
  tooling).

## 10. Timestamps [DRAFT]

Two mechanisms, because they fail in opposite directions:

- `manifests/<run-ulid>.tsr` — one or more RFC 3161 `TimeStampResp` structures, DER,
  concatenated. Each MUST cover the SHA-256 of the manifest file. Writers SHOULD obtain
  tokens from ≥ 2 independent TSAs — no single authority may be the point of trust.
- `manifests/<run-ulid>.ots` — an OpenTimestamps proof over the same SHA-256.
  Bitcoin-anchored; needs no surviving authority. Proofs start incomplete and MUST be
  upgraded once attestations confirm; tooling runs the upgrade pass in the background.

Timestamps are optional per-run; their absence downgrades verification results (§14),
it does not invalidate the archive. [DRAFT: per-run root / root-of-roots aggregation
for O(1) timestamp cost is not yet specified.]

## 11. Index

`index/` holds derived acceleration state (e.g. a SQLite database mapping hash →
location, full-text search). Its format is implementation-defined, explicitly out of
scope for this spec, and MUST be rebuildable from packs + manifests alone. A verifier
MUST NOT need it.

## 12. Sources

`meta/sources.json` holds capture configuration (accounts, sync cursors, folder
include/exclude). Implementation-defined and out of scope, with one rule: it MUST NOT
contain secrets (credentials belong in the OS keychain), because archives get copied.

## 13. Deletion

Append-only governs how the store works, not what the owner may do. Deletion is a
deliberate, recorded operation:

1. Write a new manifest (run `kind: "delete"`) containing one tombstone record per
   deleted object; sign (and timestamp) it like any other.
2. For each pack containing a deleted object: write a replacement pack (new ULID)
   containing every entry except the deleted ones, verify the replacement by reading
   back every entry, then — and only then — delete the old pack. Staged objects are
   simply removed after the manifest is written.

A deletion MUST NOT edit any existing manifest or pack. Message records referencing the
deleted object remain in their manifests forever; the tombstone is what makes the
absence honest.

## 14. Verification

A verifier reads packs + manifests (+ keys) and reports. The result vocabulary is part
of the format, because "your archive is fine" and "your archive is fine but run
2019-441 can't be attributed" must be distinguishable.

Per object (union of all message records vs. what exists):

| status | meaning |
|---|---|
| `ok` | present; bytes hash to the recorded ID |
| `corrupt` | present; bytes do NOT hash to the recorded ID |
| `excised` | absent; a tombstone covers it |
| `missing` | absent; no tombstone — data loss |

Per run:

| status | meaning |
|---|---|
| `sig-ok` | signature verifies against a trusted key |
| `sig-unknown-key` | signature present, key not in trusted set — provenance unverifiable, not corruption |
| `sig-invalid` | signature does not verify — tampering or corruption |
| `sig-missing` | no `.sig` file |
| `ts-ok` / `ts-pending` / `ts-missing` | timestamps verified / OTS awaiting upgrade / absent [DRAFT] |

An archive is *intact* iff no object is `corrupt` or `missing` and no run is
`sig-invalid`. Every other degradation is reported, not conflated.

## 15. Conformance

- A **reader** MUST locate and return objects given the layout in §3–§6, tolerating
  duplicates, and MUST parse manifests per §7, skipping unknown record types and keys.
- A **writer** MUST uphold immutability (§4, §5, §7), atomicity and crash-safety
  (§4, §5, §13), and dedup-by-hash (§4).
- An **identity implementation** MUST match the published test vectors bit-exactly for
  every `identity_v` it claims.
- A **verifier** MUST implement §14 and MUST NOT require `index/` or network access
  (timestamp verification MAY use the network; everything else works offline).

The conformance corpus lives in [`corpus/`](corpus/); identity test vectors in
[`vectors/`](vectors/). Both are versioned with this spec.

## 16. Open questions (tracked toward v1.0)

- Identity v1 body canonicalisation (§8.2) — needs the ground-truth corpus first.
- Timestamp aggregation (per-run root, root-of-roots) — §10.
- Pack-level metadata (creation time, format hints) — ZIP comment vs. nothing.
- Maximum manifest size / manifest splitting for very large runs.
- The stdlib-only recovery reader ships with this repo before v1.0.
