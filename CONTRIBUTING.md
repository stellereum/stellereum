# Contributing to Stellereum

Thanks for your interest. The project is in closed-testnet stage: review existing
issues first, then propose changes as focused pull requests.

## Ground rules

1. **Tests first.** `cargo test -p stellereum --lib` must stay green; new behavior
   ships with regression tests. Do not weaken existing assertions to make builds pass.
2. **Lints are law.** `cargo clippy --all-targets -- -D warnings` must be clean.
   No `todo!()`, `unimplemented!()`, or dummy returns in merged code.
3. **No consensus changes by drive-by.** Quorum values, vote counting, finality rules,
   signature domains and wire formats change only with a spec update and an audit
   note — open an issue with a reproducer (`sim`/devnet seed included) before large PRs.
4. **Live network is off-limits.** Never point test/experimental builds at shared
   infrastructure, never load-test public endpoints. Local stack only
   (`cargo run -p stellereum -- sim --blocks 3`, `scripts/local-cluster.sh`).

## Security

Never open a public issue for a suspected vulnerability — see [SECURITY.md](SECURITY.md).

## License

By contributing you agree your work is dual-licensed MIT **or** Apache-2.0,
like the rest of the tree (see `LICENSE-MIT`, `LICENSE-APACHE`).
