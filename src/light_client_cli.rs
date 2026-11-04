//! The `stellereum light-client` command: an EXTERNAL verifier.
//!
//! This is the Near `light_client` / Sui `sui_light_client` model: a program
//! that checks a claim about the chain WITHOUT running consensus and without
//! holding the state. It fetches a proof from a node's RPC and checks it
//! against a root a QUORUM committed to.
//!
//! # Why the trusted root cannot come from the server
//!
//! The node serves proofs against its own current state root. If the client
//! took that root from the server, the server could serve a proof against a
//! root it invented — the classic "the node hands out the root it believes
//! in" hole (production blocker A10). So the client NEVER trusts a root the
//! server asserts. It trusts a root only when it has checked, itself:
//!
//! 1. the node's **out-of-band** validator set (a file the operator pinned —
//!    `--validators`), never the set the server serves;
//! 2. the **quorum certificate** on the header that commits to the root,
//!    checked against that set: a precommit quorum of real validator power,
//!    bound to that height and that block hash;
//! 3. the Merkle proof itself, against that root.
//!
//! # Which header anchors a served proof
//!
//! The chain's convention: a block header commits to the state BEFORE its own
//! block (the state it builds on). So the header at height `H` commits to the
//! state at height `H-1`, and the node's live proofs — served against the
//! CURRENT state — are committed by the header at height `H+1`.
//!
//! That is why the client anchors a served proof with the header at
//! `height + 1`: it is the first header a quorum has certified for that root.
//! The client waits for it (the node has to finalize one more block), and
//! says so plainly if it never arrives.
//!
//! # What this does NOT prove
//!
//! The validator set is the entire trust anchor: if the set is wrong, or a
//! quorum of it is Byzantine, everything this client concludes is wrong — and
//! it concludes it confidently. Validator-set rotation IS supported, but only
//! through [`crate::light_client::ValidatorSetRotation`] enforced by
//! [`LightClient::rotate_validator_set`]: the rotation header must chain
//! normally onto the tip and carry a precommit quorum from the CURRENT set, so
//! a supermajority of OLD power signs the rotation point (see
//! `crate::light_client`'s module docs and `docs/LIGHT_CLIENT_VERIFY.md` §3).
//! The offline CLI exposes it via `light-anchor` (show), `light-verify`
//! (check a header/checkpoint file against the anchor) and `light-rotate`
//! (install a rotation proof file). The replacement set's CONTENTS are pinned
//! out-of-band exactly like the genesis set — never taken from the server.

use crate::consensus::{QuorumCertificate, ValidatorId, ValidatorSet, VoteKind};
use crate::light_client::{Checkpoint, LightAnchor, LightClient, LightError, ProofAnswer};
use crate::light_client::{LightHeader, ValidatorSetRotation};
use serde_json::{json, Value};
use std::path::Path;

/// What the `light-client` command was asked to do.
#[derive(Clone, Debug)]
pub struct LightClientOptions {
    /// The node's JSON-RPC endpoint.
    pub from: String,
    /// The account whose balance to verify (hex).
    pub verify: String,
    /// The OUT-OF-BAND validator set (JSON file).
    pub validators: std::path::PathBuf,
    /// How long to wait for the node to finalize the anchoring header.
    pub wait_seconds: u64,
    /// Print the RPC traffic.
    pub verbose: bool,
}

/// One JSON-RPC call over the vendored blocking HTTP client.
fn rpc_call(url: &str, method: &str, params: Value, verbose: bool) -> anyhow::Result<Value> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    if verbose {
        eprintln!("  rpc -> {method}");
    }
    let resp: Value = ureq::post(url).send_string(&body)?.into_json()?;
    if verbose {
        eprintln!("  rpc <- {method}: {resp}");
    }
    if let Some(e) = resp.get("error") {
        anyhow::bail!("RPC error from {method}: {e}");
    }
    Ok(resp.get("result").cloned().unwrap_or(Value::Null))
}

/// Parse a 32-byte hex string (with or without `0x`).
fn parse_hex32(s: &str) -> anyhow::Result<[u8; 32]> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let b = hex::decode(s).map_err(|e| anyhow::anyhow!("bad hex {s:?}: {e}"))?;
    b.try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes, got {}", s.len() / 2))
}

/// Parse a validator set from an already-parsed JSON value.
///
/// Accepts the same shapes as [`load_validator_set`]; `ctx` names the file
/// (or embedded section) for fail-closed errors.
pub fn validator_set_from_value(v: &Value, ctx: &str) -> anyhow::Result<ValidatorSet> {
    let entries: Vec<Value> = match &v {
        Value::Object(map) => map
            .get("validators")
            .and_then(|x| x.as_array())
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("the validator set {ctx} has no \"validators\" array")
            })?,
        Value::Array(a) => a.clone(),
        _ => {
            return Err(anyhow::anyhow!(
                "the validator set {ctx} must be an object or an array"
            ))
        }
    };
    let mut set = ValidatorSet::new();
    for (i, e) in entries.iter().enumerate() {
        let (id_hex, power) = match e {
            Value::Array(pair) if pair.len() == 2 => (
                pair[0].as_str().unwrap_or_default().to_string(),
                pair[1].clone(),
            ),
            Value::Object(_) => {
                let id = e
                    .get("validator")
                    .or_else(|| e.get("pubkey"))
                    .or_else(|| e.get("id"))
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| anyhow::anyhow!("validator entry {i} has no pubkey"))?;
                let p = e
                    .get("power")
                    .or_else(|| e.get("stake"))
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("validator entry {i} has no power"))?;
                (id.to_string(), p)
            }
            _ => return Err(anyhow::anyhow!("validator entry {i} is malformed")),
        };
        let id: ValidatorId =
            parse_hex32(&id_hex).map_err(|e| anyhow::anyhow!("validator entry {i}: {e}"))?;
        let power: u64 = match power {
            Value::Number(n) => n.as_u64().ok_or_else(|| {
                anyhow::anyhow!("validator entry {i}: the power is not an unsigned integer")
            })?,
            Value::String(s) => s.trim().parse::<u64>().map_err(|e| {
                anyhow::anyhow!("validator entry {i}: the power {s:?} is not a number: {e}")
            })?,
            _ => {
                return Err(anyhow::anyhow!(
                    "validator entry {i}: the power is not a number"
                ))
            }
        };
        set.add(id, power);
    }
    if set.is_empty() {
        anyhow::bail!(
            "the validator set {ctx} holds NO validator: no quorum certificate can ever \
             be verified against it"
        );
    }
    Ok(set)
}

/// Load the OUT-OF-BAND validator set.
///
/// Accepted shapes (all hex pubkeys, power as a number or a decimal string):
///
/// ```json
/// {"validators": [{"validator": "<64 hex>", "power": "1000"}, ...]}
/// [["<64 hex>", 1000], ...]
/// [{"validator": "<64 hex>", "power": 1000}, ...]
/// ```
///
/// The first shape is exactly what `stell_getValidators` serves, so an
/// operator can dump it ONCE and pin the file. Pinning matters: a set taken
/// from the server at verification time is circular — the server would be
/// able to certify its own chain.
pub fn load_validator_set(path: &Path) -> anyhow::Result<ValidatorSet> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        anyhow::anyhow!("cannot read the validator set file {}: {e}", path.display())
    })?;
    let v: Value = serde_json::from_str(&raw).map_err(|e| {
        anyhow::anyhow!(
            "the validator set file {} is not valid JSON: {e}",
            path.display()
        )
    })?;
    validator_set_from_value(&v, &format!("file {}", path.display()))
}

/// The header the node served, as the light client needs it.
#[derive(Clone, Debug)]
pub struct ServedHeader {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub cert: QuorumCertificate,
}

/// Parse the node's `stell_getFinalizedHeader` answer.
pub fn parse_served_header(v: &Value) -> anyhow::Result<ServedHeader> {
    let height = v
        .get("height")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| anyhow::anyhow!("the header has no height"))?;
    let block_hash = parse_hex32(
        v.get("block_hash")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow::anyhow!("the header has no block hash"))?,
    )?;
    let prev_hash = parse_hex32(
        v.get("prev_hash")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow::anyhow!("the header has no parent hash"))?,
    )?;
    let state_root = parse_hex32(
        v.get("state_root")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow::anyhow!("the header has no state root"))?,
    )?;
    let cert_json = v
        .get("cert")
        .ok_or_else(|| anyhow::anyhow!("the header carries no quorum certificate"))?;
    let cert_height = cert_json
        .get("height")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| anyhow::anyhow!("the certificate has no height"))?;
    let round = cert_json.get("round").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    let kind = match cert_json.get("kind").and_then(|x| x.as_str()) {
        Some("Precommit") => VoteKind::Precommit,
        Some("Prevote") => VoteKind::Prevote,
        Some(other) => anyhow::bail!("unknown certificate kind {other:?}"),
        None => anyhow::bail!("the certificate has no kind"),
    };
    let cert_hash = match cert_json.get("block_hash") {
        Some(Value::String(s)) => Some(parse_hex32(s)?),
        _ => None,
    };
    let mut signatures = Vec::new();
    if let Some(arr) = cert_json.get("signatures").and_then(|x| x.as_array()) {
        for s in arr {
            let voter = parse_hex32(
                s.get("validator")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| anyhow::anyhow!("a certificate signature has no validator"))?,
            )?;
            let sig = hex::decode(
                s.get("signature")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| anyhow::anyhow!("a certificate signature has no bytes"))?,
            )
            .map_err(|e| anyhow::anyhow!("a certificate signature is not hex: {e}"))?;
            signatures.push((voter, sig));
        }
    }
    Ok(ServedHeader {
        height,
        block_hash,
        prev_hash,
        state_root,
        cert: QuorumCertificate {
            height: cert_height,
            round,
            kind,
            block_hash: cert_hash,
            signatures,
        },
    })
}

/// Fetch the header at `height`, waiting for the node to produce it.
///
/// The anchoring header is the FIRST header a quorum certified for the root
/// the proof authenticates against, so it may not exist yet: the node has to
/// finalize one more block. The wait is bounded and the failure is explicit.
fn fetch_anchoring_header(
    url: &str,
    height: u64,
    wait_seconds: u64,
    verbose: bool,
) -> anyhow::Result<ServedHeader> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_seconds);
    let mut last_err: String;
    loop {
        match rpc_call(
            url,
            "stell_getFinalizedHeader",
            json!({ "height": height }),
            verbose,
        ) {
            Ok(v) => match parse_served_header(&v) {
                Ok(h) => return Ok(h),
                Err(e) => {
                    last_err = e.to_string();
                }
            },
            Err(e) => {
                last_err = e.to_string();
            }
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "the node did not serve the finalized header at height {height} within \
                 {wait_seconds}s (last error: {last_err}). That header is what COMMITS to \
                 the state the proof is about: without it the proof's root is the server's \
                 word, not a quorum's."
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

/// Run the external light client.
pub fn run(opts: &LightClientOptions) -> anyhow::Result<()> {
    // 1. The out-of-band validator set. Without it there is NO trust anchor.
    let validators = load_validator_set(&opts.validators)?;
    println!(
        "light client: validator set from {} — {} validators, {} total power, quorum {}",
        opts.validators.display(),
        validators.len(),
        validators.total_power(),
        validators.quorum_power()
    );

    // 2. The proof the server is offering.
    let raw = rpc_call(
        &opts.from,
        "stell_getProof",
        json!({ "address": opts.verify }),
        opts.verbose,
    )?;
    let answer = ProofAnswer::from_json(&raw)
        .map_err(|e| anyhow::anyhow!("the node's proof answer is unusable: {e}"))?;
    let height = answer
        .height
        .ok_or_else(|| anyhow::anyhow!("the node did not report a height for the proof"))?;
    println!(
        "light client: the node served a proof for {} at height {} against root {}",
        hex::encode(answer.address),
        height,
        hex::encode(answer.state_root)
    );

    // 3. The header that COMMITS to that root: the header at height+1 (the
    //    chain commits to the state BEFORE its own block).
    let header = fetch_anchoring_header(&opts.from, height + 1, opts.wait_seconds, opts.verbose)?;
    if header.state_root != answer.state_root {
        anyhow::bail!(
            "the node's header at height {} commits to root {}, but the proof it served is \
             against root {} — the node is talking about two different states",
            header.height,
            hex::encode(header.state_root),
            hex::encode(answer.state_root)
        );
    }
    if header.cert.height != header.height
        || header.cert.block_hash != Some(header.block_hash)
        || header.cert.kind != VoteKind::Precommit
    {
        anyhow::bail!(
            "the header at height {} does not carry a precommit certificate bound to its own \
             height and hash — it is not a finality proof",
            header.height
        );
    }

    // 4. The quorum certificate, checked against the OUT-OF-BAND set. This is
    //    the step that makes the root more than the server's word.
    let checkpoint = Checkpoint::new(
        header.height,
        header.block_hash,
        header.prev_hash,
        header.state_root,
        header.cert,
    );
    let client = LightClient::new(validators.clone(), checkpoint).map_err(|e| {
        anyhow::anyhow!(
            "the anchoring header was REFUSED by the light client: {e}. The node's chain is \
             not certified by the validator set you pinned."
        )
    })?;
    println!(
        "light client: the header at height {} carries a precommit quorum certificate that \
         verifies against your validator set — the root {} is now TRUSTED",
        header.height,
        hex::encode(header.state_root)
    );

    // 5. The proof itself.
    match client.verify_proof_answer(&answer) {
        Ok(proven) => {
            println!("light client: VERIFIED");
            println!("  address:  {}", hex::encode(proven.address));
            println!("  balance:  {} nano-STELL", proven.balance);
            println!("  nonce:    {}", proven.nonce);
            println!("  exists:   {}", proven.exists);
            println!("  height:   {}", proven.height);
            println!("  root:     {}", hex::encode(proven.state_root));
            for s in &proven.storage {
                println!(
                    "  storage {}: {}",
                    hex::encode(s.key),
                    match &s.value {
                        Some(v) => hex::encode(v),
                        None => "<absent>".to_string(),
                    }
                );
            }
            Ok(())
        }
        Err(e) => {
            let detail = match &e {
                LightError::RootUntrusted { root } => format!(
                    "the proof is against root {}, which the light client does not trust",
                    hex::encode(root)
                ),
                LightError::InvalidProof(m) => format!("the proof is not a valid proof: {m}"),
                LightError::NotIncluded { height, state_root } => format!(
                    "the proof does not authenticate at the trusted root (height {height}, root {})",
                    hex::encode(state_root)
                ),
            };
            anyhow::bail!("light client: REFUSED — {detail}")
        }
    }
}

// ============================================================================
// Offline anchor / verify / rotate (light-client 8.0, docs/LIGHT_CLIENT_VERIFY.md)
// ============================================================================

/// Deterministic digest of the validator set: blake3 over the sorted
/// `(validator_id, power)` entries. What `light-anchor` prints as `set hash`.
pub fn validator_set_digest(set: &ValidatorSet) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("STELL_LIGHT_SET_V1");
    for (id, power) in set.validators.iter() {
        h.update(id);
        h.update(&power.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

/// Load a quorum-certified checkpoint from a JSON file.
///
/// The file holds a [`Checkpoint`] in serde JSON form (as served by
/// `stell_getFinalizedCheckpoint`). Fail-closed: unreadable or malformed
/// files are refused here, never defaulted.
pub fn load_checkpoint_file(path: &Path) -> anyhow::Result<Checkpoint> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read checkpoint file {}: {e}", path.display()))?;
    serde_json::from_str::<Checkpoint>(&raw)
        .map_err(|e| anyhow::anyhow!("checkpoint file {} is not a Checkpoint: {e}", path.display()))
}

/// Load a finalized header from a JSON file.
///
/// The file holds a [`LightHeader`] in serde JSON form (as served by
/// `stell_getFinalizedHeader`). Fail-closed like [`load_checkpoint_file`].
pub fn load_light_header_file(path: &Path) -> anyhow::Result<LightHeader> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read header file {}: {e}", path.display()))?;
    serde_json::from_str::<LightHeader>(&raw)
        .map_err(|e| anyhow::anyhow!("header file {} is not a LightHeader: {e}", path.display()))
}

/// Load a rotation proof from a JSON file.
///
/// The file holds `{"rotation": <LightHeader>, "next_set": <validator set>}`
/// where the set uses the same out-of-band shapes as [`load_validator_set`]
/// (`"next_validators"` is accepted as an alias for `"next_set"`). The
/// supermajority-of-old-set rule itself is enforced by
/// [`LightClient::rotate_validator_set`] — this only parses, never judges.
///
/// A bare [`ValidatorSetRotation`] serde blob is NOT accepted on purpose:
/// [`ValidatorSet`] serializes its map with non-string keys, which JSON
/// cannot round-trip, so the pinned file shape is the only stable form.
pub fn load_rotation_proof_file(path: &Path) -> anyhow::Result<ValidatorSetRotation> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        anyhow::anyhow!("cannot read rotation proof file {}: {e}", path.display())
    })?;
    let v: Value = serde_json::from_str(&raw).map_err(|e| {
        anyhow::anyhow!(
            "rotation proof file {} is not valid JSON: {e}",
            path.display()
        )
    })?;
    let rotation_value = v.get("rotation").ok_or_else(|| {
        anyhow::anyhow!(
            "rotation proof file {} has no \"rotation\" header",
            path.display()
        )
    })?;
    let rotation: LightHeader = serde_json::from_value(rotation_value.clone()).map_err(|e| {
        anyhow::anyhow!(
            "rotation proof file {} has a bad rotation header: {e}",
            path.display()
        )
    })?;
    let next_value = v
        .get("next_set")
        .or_else(|| v.get("next_validators"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "rotation proof file {} has no \"next_set\" validator set",
                path.display()
            )
        })?;
    let next_set = validator_set_from_value(
        next_value,
        &format!("rotation proof file {}", path.display()),
    )?;
    Ok(ValidatorSetRotation::new(rotation, next_set))
}

/// Show the current anchor: `(set hash, height)` plus the quorum numbers.
///
/// Loads the out-of-band set and the checkpoint, then constructs a
/// [`LightClient`] — which re-verifies the checkpoint's precommit QC under
/// the set — so a bad anchor fails closed here instead of printing.
pub fn anchor_show(validators_path: &Path, checkpoint_path: &Path) -> anyhow::Result<String> {
    let set = load_validator_set(validators_path)?;
    let checkpoint = load_checkpoint_file(checkpoint_path)?;
    let client = LightClient::new(set.clone(), checkpoint.clone()).map_err(|e| {
        anyhow::anyhow!("the anchor was REFUSED by the light client: {e}")
    })?;
    let anchor = match client.anchor() {
        LightAnchor::Checkpoint(cp) => cp,
        LightAnchor::Genesis(_) => {
            return Err(anyhow::anyhow!("unexpected genesis anchor"));
        }
    };
    Ok(format!(
        "anchor height: {}\nanchor block: {}\nanchor root: {}\nset hash: {}\nvalidators: {}\ntotal power: {}\nquorum: {}\nset height: {}",
        anchor.height,
        hex::encode(anchor.block_hash),
        hex::encode(anchor.state_root),
        hex::encode(validator_set_digest(&set)),
        set.len(),
        set.total_power(),
        set.quorum_power(),
        client.validator_set_height(),
    ))
}

/// Verify a header/checkpoint file against the anchor.
///
/// The file may hold a [`LightHeader`] (accepted via
/// [`LightClient::apply_header` on top of the tip) or a [`Checkpoint`]
/// (adopted via [`LightClient::advance_to_checkpoint`]. Both paths verify a
/// precommit quorum under the set in force and refuse gaps, forks,
/// rollbacks and sub-quorum evidence fail-closed.
pub fn verify_header_file(
    validators_path: &Path,
    checkpoint_path: &Path,
    header_path: &Path,
) -> anyhow::Result<String> {
    let set = load_validator_set(validators_path)?;
    let checkpoint = load_checkpoint_file(checkpoint_path)?;
    let mut client =
        LightClient::new(set, checkpoint).map_err(|e| anyhow::anyhow!("bad anchor: {e}"))?;
    let tip_before = client.tip_height();
    if let Ok(header) = load_light_header_file(header_path) {
        let h = header.height;
        let hash = hex::encode(header.block_hash);
        client
            .apply_header(header)
            .map_err(|e| anyhow::anyhow!("header at height {h} REFUSED: {e}"))?;
        return Ok(format!(
            "verified header at height {h} ({hash}) on top of tip {tip_before}"
        ));
    }
    let cp = load_checkpoint_file(header_path).map_err(|e| {
        anyhow::anyhow!(
            "header file {} is neither a LightHeader nor a Checkpoint: {e}",
            header_path.display()
        )
    })?;
    let h = cp.height;
    let hash = hex::encode(cp.block_hash);
    client
        .advance_to_checkpoint(cp)
        .map_err(|e| anyhow::anyhow!("checkpoint at height {h} REFUSED: {e}"))?;
    Ok(format!(
        "verified checkpoint at height {h} ({hash}) over tip {tip_before}"
    ))
}

/// Rotate the anchor with a rotation proof file.
///
/// Loads the anchor, then installs the proof via
/// [`LightClient::rotate_validator_set`] — the supermajority-of-old-set rule,
/// the chaining/shape gate and the powerless-set refusal all live there and
/// are NOT reimplemented here. The replacement set's contents remain the
/// caller's out-of-band responsibility (see [`ValidatorSetRotation`]).
pub fn rotate_anchor(
    validators_path: &Path,
    checkpoint_path: &Path,
    rotation_path: &Path,
) -> anyhow::Result<String> {
    let set = load_validator_set(validators_path)?;
    let checkpoint = load_checkpoint_file(checkpoint_path)?;
    let mut client =
        LightClient::new(set, checkpoint).map_err(|e| anyhow::anyhow!("bad anchor: {e}"))?;
    let proof = load_rotation_proof_file(rotation_path)?;
    let h = proof.rotation.height;
    let hash = hex::encode(proof.rotation.block_hash);
    client
        .rotate_validator_set(proof)
        .map_err(|e| anyhow::anyhow!("rotation at height {h} REFUSED: {e}"))?;
    Ok(format!(
        "rotated to height {h} ({hash}); set height: {}; validators: {}",
        client.validator_set_height(),
        client.validators.len(),
    ))
}
