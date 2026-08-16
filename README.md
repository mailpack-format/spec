# mailpack

An open format for personal mail archives. A lifetime of mail — every school, job,
domain, and provider — consolidated into one folder of plain files, merged without
double-counting, and still readable in thirty years with no mailpack software at all.

**[Read the spec →](SPEC.md)** (v0.1, draft)

## Why a format?

Mailboxes accumulate for decades, and every migration is a chance to lose
attachments, botch a merge, or silently drop years of history. Existing archivers
store mail in opaque, app-private databases: the archive dies with the software, and
merging a fifteen-year-old export against a live mailbox double-counts everything.

mailpack is the format layer those tools are missing:

- **Plain files.** Messages are `.eml` entries inside standard ZIP archives. Recovery
  without our software means *double-click the pack*.
- **Content-addressed.** SHA-256 of raw bytes is storage identity; nothing ever
  rewrites a message.
- **Two identities.** Byte identity for storage, versioned *logical* identity for
  "is this the same email?" — because Takeout, IMAP, Graph, and PST all emit different
  bytes for the same message. This is what makes multi-decade merge work.
- **Evidence-grade, as a property.** Capture runs form a hash chain committed to by
  per-run Merkle roots, signed by the owner and independently timestamped (RFC 3161 +
  OpenTimestamps). Rewritten history is detectable; single records can be disclosed
  and verified without revealing the rest; and the spec's threat model states the
  limits as plainly as the guarantees.
- **Honest deletion, honest crashes.** Deletion leaves signed tombstones; interrupted
  runs stay visible forever and recover by re-emission, so verification distinguishes
  "excised by owner" from "missing" and "crashed and recovered" from "tampered".

## This repository

| path | contents |
|---|---|
| [`SPEC.md`](SPEC.md) | the format specification |
| [`vectors/`](vectors/) | logical-identity test vectors (per `identity_v`) |
| [`corpus/`](corpus/) | conformance corpus of pathological and real-world-shaped messages |

Planned before v1.0: a stdlib-only recovery reader — a single-file script, written
against the spec text alone, proving the recovery promise.

## Status

Draft. The pack layout freezes at spec v1.0; the logical-identity algorithm is
versioned per-manifest-line (`identity_v`) and evolves by publishing new versions with
test vectors, never by silent change.

Reference implementation: [mailpack-format/core](https://github.com/mailpack-format/core)
(Rust — the `mailpack-core` library and CLI). It currently covers layout, packs,
chained + merkle-rooted manifests, sessions with crash recovery, concurrency,
verification, and signing (envelope §10.1, key registry §10.2, `sig-*`
verification statuses); timestamp anchoring is specified here but not yet
implemented there.

## License

[MIT](LICENSE). Adoption by other tools — including commercial ones — is the point.
