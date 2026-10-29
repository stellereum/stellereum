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
//! it concludes it confidently. There is no validator-set rotation story
//! here (see `crate::light_client`'s module docs).

use crate::consensus::{QuorumCertificate, ValidatorId, ValidatorSet, VoteKind};
use crate::light_client::{Checkpoint, LightClient, LightError, ProofAnswer};
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
fn rpc_call(
    url: &str,
    method: &str,
    params: Value,
    verbose: bool,
) -> anyhow::Result<Value> {
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
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let b = hex::decode(s).map_err(|e| anyhow::anyhow!("bad hex {s:?}: {e}"))?;
    b.try_into().map_err(|_| anyhow::anyhow!("expected 32 bytes, got {}", s.len() / 2))
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
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read the validator set file {}: {e}", path.display()))?;
    let v: Value = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("the validator set file {} is not valid JSON: {e}", path.display()))?;
    let entries: Vec<Value> = match &v {
        Value::Object(map) => map
            .get("validators")
            .and_then(|x| x.as_array())
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "the validator set file {} has no \"validators\" array",
                    path.display()
                )
            })?,
        Value::Array(a) => a.clone(),
        _ => {
            return Err(anyhow::anyhow!(
                "the validator set file {} must be an object or an array",
                path.display()
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
                    .ok_or_else(|| {
                        anyhow::anyhow!("validator entry {i} has no pubkey")
                    })?;
                let p = e
                    .get("power")
                    .or_else(|| e.get("stake"))
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("validator entry {i} has no power"))?;
                (id.to_string(), p)
            }
            _ => return Err(anyhow::anyhow!("validator entry {i} is malformed")),
        };
        let id: ValidatorId = parse_hex32(&id_hex)
            .map_err(|e| anyhow::anyhow!("validator entry {i}: {e}"))?;
        let power: u64 = match power {
            Value::Number(n) => n.as_u64().ok_or_else(|| {
                anyhow::anyhow!("validator entry {i}: the power is not an unsigned integer")
            })?,
            Value::String(s) => s.trim().parse::<u64>().map_err(|e| {
                anyhow::anyhow!("validator entry {i}: the power {s:?} is not a number: {e}")
            })?,
            _ => return Err(anyhow::anyhow!("validator entry {i}: the power is not a number")),
        };
        set.add(id, power);
    }
    if set.is_empty() {
        anyhow::bail!(
            "the validator set file {} holds NO validator: no quorum certificate can ever \
             be verified against it",
            path.display()
        );
    }
    Ok(set)
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
    let mut last_err = String::new();
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
