# 4-validator stand — validator-list plan

Source of truth: read-only inspection of the live server on 2026-09-26.
Nothing on the server was modified; values below are copied verbatim.

## 1. Deployed convention (as found, not as assumed)

- `/root/nodeA/node.yaml`: `validators: ["inf1:c82d52e5...3610"]` — that id is
  **nodeB's** id (it matches nodeB's `NODE IDENTITY` log line and the `peers:`
  entry for nodeB in nodeA's own file). nodeA lists **the peer, not itself**.
- `/root/nodeB/node.yaml`: `validators: ["inf1:56d7b3a5...7298a"]` — that id is
  **nodeA's** id. nodeB lists **the peer, not itself**.
- `src/main.rs::build_validator_set` resolves this "others only" shape as
  `{own key} UNION {ed-pub of every peers: entry whose node-id is listed}`,
  so both nodes derive the set `{A, B}` and agree on the genesis root
  (`d0f01b28...ccab4` in the live logs; 2 validator accounts funded).
- The same convention extended to 4 nodes: **each node's `validators:` lists
  the OTHER THREE ids**, and each node carries a `peers:` entry (with ed-pub
  + x-pub + endpoints + `allow: ["*"]`) for each of them. Then every node's
  derived set is `{self} UNION {3 listed peers} = {A, B, C, D}`.

## 2. Known identities (live, verbatim)

| node  | node-id (validators: value)                        | ed-pub (consensus identity / funded account) | x-pub (transport) | P2P | RPC |
|-------|----------------------------------------------------|----------------------------------------------|-------------------|-----|-----|
| nodeA | `inf1:56d7b3a5570626a6822b992041367bb7e2b7298a`    | `c2313fba…788b8f27ad7f96772610996c3361` (full in yaml) | `04fe590d…899fc7c` | 9410 | 8545 |
| nodeB | `inf1:c82d52e5cae4787ab6150ed2b129f1635a1e3610`    | `9c675ebc…419175fcd` (full in yaml) | `b896e426…1dab0f40` | 9411 | 8546 |
| nodeC | `inf1:PLACEHOLDER_C_NODE_ID_…` (fill from its NODE IDENTITY line) | `PLACEHOLDER_C_ED_PUB_…` | `PLACEHOLDER_C_X_PUB_…` | 9412 | 8547 |
| nodeD | `inf1:PLACEHOLDER_D_NODE_ID_…` (fill from its NODE IDENTITY line) | `PLACEHOLDER_D_ED_PUB_…` | `PLACEHOLDER_D_X_PUB_…` | 9413 | 8548 |

Full A/B hex values live on the stand in `/root/nodeA/node.yaml` and
`/root/nodeB/node.yaml` (the templates carry placeholders for A/B/C/D — the
values are not stored in this repo).

## 3. The four `validators:` lists (explicit)

Quorum with unit power is `floor(2*total/3)+1`: 2-of-2 today needs BOTH;
4 validators need **3 of 4**, which is the first size that survives one
failure. Lists (order inside the list does not matter — the set is sorted —
but keep the same order everywhere for side-by-side diffing):

- **nodeA.validators** (currently `[B]`, must become):
  - `inf1:c82d52e5cae4787ab6150ed2b129f1635a1e3610` (B, already there)
  - `inf1:PLACEHOLDER_C_NODE_ID_00000000000000000000` (C, new)
  - `inf1:PLACEHOLDER_D_NODE_ID_00000000000000000000` (D, new)
- **nodeB.validators** (currently `[A]`, must become):
  - `inf1:56d7b3a5570626a6822b992041367bb7e2b7298a` (A, already there)
  - `inf1:PLACEHOLDER_C_NODE_ID_00000000000000000000` (C, new)
  - `inf1:PLACEHOLDER_D_NODE_ID_00000000000000000000` (D, new)
- **nodeC.validators** (new file, `nodeC.yaml.template` — already written so):
  - `inf1:56d7b3a5570626a6822b992041367bb7e2b7298a` (A)
  - `inf1:c82d52e5cae4787ab6150ed2b129f1635a1e3610` (B)
  - `inf1:PLACEHOLDER_D_NODE_ID_00000000000000000000` (D)
- **nodeD.validators** (new file, `nodeD.yaml.template` — already written so):
  - `inf1:56d7b3a5570626a6822b992041367bb7e2b7298a` (A)
  - `inf1:c82d52e5cae4787ab6150ed2b129f1635a1e3610` (B)
  - `inf1:PLACEHOLDER_C_NODE_ID_00000000000000000000` (C)

## 4. The four `peers:` lists (explicit — forgetting one silently splits the chain)

Every listed id MUST resolve to a `peers:` entry with the matching ed-pub in
the SAME file, otherwise `build_validator_set` silently builds a smaller set,
funds fewer genesis accounts, and that node runs a different chain:

- **nodeA.peers**: keep nodeB entry; ADD nodeC entry (C id/ed/x, `127.0.0.1:9412`)
  and nodeD entry (D id/ed/x, `127.0.0.1:9413`), both `allow: ["*"]`.
- **nodeB.peers**: keep nodeA entry; ADD nodeC (`127.0.0.1:9412`) and nodeD
  (`127.0.0.1:9413`) entries.
- **nodeC.peers**: nodeA (`127.0.0.1:9410`), nodeB (`127.0.0.1:9411`), nodeD
  (`127.0.0.1:9413`) — already in `nodeC.yaml.template`.
- **nodeD.peers**: nodeA (`127.0.0.1:9410`), nodeB (`127.0.0.1:9411`), nodeC
  (`127.0.0.1:9412`) — already in `nodeD.yaml.template`.

## 5. Bring-up order (prepare-only — DO NOT EXECUTE on the live stand now)

1. Back up `/root/nodeA/node.yaml`, `/root/nodeB/node.yaml`, `/root/env.A`,
   `/root/env.B` (read them; mode 600 on env files).
2. Generate C/D identities (empty-peers single start each; capture the
   `NODE IDENTITY` lines), fill all four placeholders in the templates above.
3. Decide the binary (see FAULT_RUNBOOK.md §0): current deployed binary
   (COMMITMENT_VERSION 2 lineage) OR fresh HEAD build (COMMITMENT_VERSION 5).
   Either way the 2→4 validator change alone alters the genesis root, so:
4. `stop` everything, `wipe` A/B data, `wipe4` C/D data, lay down all four
   yamls + envs, `start` (A/B) + `start4` (C/D), verify with `status4` that
   all four agree on genesis before injecting any fault.
