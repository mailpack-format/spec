# Identity test vectors

Test vectors for the logical-identity algorithm (SPEC.md §8), one directory per
version: `v1/`, `v2/`, …

Each vector is a raw message file plus an expected-output JSON file recording the
extracted components (`message-id`, `date`, `from`, `body-hash`) and the final
`logical_id`. Implementations claiming an `identity_v` must match every vector for that
version bit-exactly.

No vectors are published yet: identity v1 is DRAFT until the ground-truth corpus
settles its body canonicalisation.
