# Fuzzing

The fuzz harness lives with the node crate: targets, corpora and the parser
notes are in **`stellereum/docs/FUZZING.md`**, and the CI job is
`.github/workflows/fuzz.yml` (manual + nightly, 60 s per target).

Quick start:

```sh
cd stellereum
cargo +nightly fuzz build
cargo +nightly fuzz run consensus_msg_decode -- -max_total_time=60
```

A decoder crash is a P0: it is remote input. Fix, add the input to
`stellereum/fuzz/corpus/<target>/`, and record the fix in
`docs/OPEN_DEFECTS.md`.
