# Releases: build, sign, verify, roll back

## What a release is

A tag `v*` on `main`. `.github/workflows/release.yml` builds it with
`cargo build --release --locked`, then publishes five assets:

| Asset | Purpose |
|---|---|
| `stellereum-x86_64-unknown-linux-gnu` | the node binary |
| `…​.sha256` | digest, checked before every deploy |
| `…​.sbom.spdx.json` | SPDX SBOM (dependency inventory) |
| `…​.sig` + `…​.pem` | cosign **keyless** signature + the certificate that names the workflow identity |

`--locked` is the reproducibility contract: the release builds from the
committed lockfile. If a dependency moved without a lock bump, the release is
not the code that was reviewed.

## Verify before you deploy

```sh
cosign verify-blob \
  --certificate stellereum-x86_64-unknown-linux-gnu.pem \
  --signature   stellereum-x86_64-unknown-linux-gnu.sig \
  --certificate-identity-regexp '^https://github\.com/stellereum/stellereum/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  stellereum-x86_64-unknown-linux-gnu

sha256sum -c stellereum-x86_64-unknown-linux-gnu.sha256
```

A green `verify-blob` means "this binary was produced by this repository's
Release workflow, for this commit". `rolling-deploy.sh stage` already refuses a
binary whose digest does not match the one it was told to expect; it does not
check the signature, so the signature check is the operator's step before
staging.

## Supply chain in CI

- `deny` — `cargo-deny check` with `deny.toml` (advisories, licences, wildcard
  requirements, unknown registries).
- `audit` — `cargo-audit` via RustSec as an independent second opinion; a
  disagreement between the two is visible in review.

## Deploying a release

1. `shellcheck`-clean operator flow: `scripts/rolling-deploy.sh stage <binary>
   --nodes "A B C D"` (copies, does not touch the running binary).
2. `… activate --nodes "C"` — one node, and only while the set is 4/4. The script
   pauses `stell-node-guard.timer` around the restart (a live guard can start a
   second instance on the same store and corrupt the safety record).
3. Confirm `4/4`, `fragile: false`, no jail, and the digest on the node.
4. Repeat for A, D, B.

## Rolling back

The previous binary is kept on each node as `stellereum.prev`, so a rollback is
one rename plus a restart:

```sh
systemctl stop stell-node-guard.timer
cd /root/nodeX && cp -f stellereum.prev stellereum && systemctl restart stell-nodeX
systemctl start stell-node-guard.timer
```

**Schema guard**: the store records `schema_version` on first open. A binary
older than the store refuses to start with
`store schema version N is NEWER than this binary`. That is deliberate — running
old code over new data can misread it. If you truly must, set
`STELL_ALLOW_SCHEMA_DOWNGRADE=1` and treat the node's state as suspect
afterwards (re-sync from a snapshot rather than trusting it).

## Rollback rehearsal

`scripts/upgrade_drill.sh` and `scripts/upgrade_supervisor_drill.sh` exercise the
stage/activate/rollback path against a scratch cluster. Run one before changing
the release process, not after.
