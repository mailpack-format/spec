# mailpack

An open format for personal mail archives: content-addressed, deduplicated,
signed-manifested, independently timestamped — and recoverable with no mailpack
software at all.

**[Read the spec →](SPEC.md)** (v0.1-draft)

## Why a format?

Mailboxes accumulate for decades across schools, jobs, domains, and providers. Every
migration is a chance to lose attachments, botch a merge, or silently drop years of
history. Existing archivers store mail in opaque, app-private databases: the archive
dies with the software, and nothing about it can be proven to a stranger.

mailpack is the format layer those tools are missing:

- **Plain files.** Messages are `.eml` entries inside standard ZIP archives. Recovery
  without our software means *double-click the pack*.
- **Content-addressed.** SHA-256 of raw bytes is storage identity; nothing ever
  rewrites a message.
- **Two identities.** Byte identity for storage, versioned *logical* identity for
  "is this the same email?" — because Takeout, IMAP, Graph, and PST all emit different
  bytes for the same message.
- **Verifiable by a stranger.** Ed25519-signed manifests detect tampering; RFC 3161 and
  OpenTimestamps proofs establish existence in time without trusting the archive owner.
- **Honest deletion.** The owner can delete; every deletion leaves a signed tombstone,
  so verification distinguishes "excised by owner" from "missing".

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
(Rust — the `mailpack-core` library and CLI).

## License

[MIT](LICENSE). Adoption by other tools — including commercial ones — is the point.
