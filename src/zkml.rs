//! Session keys and zkML lightweight proof verification engine
//! For high-frequency AI agents and autonomous trade execution.
//! Implements verifiable machine learning inference (quantized neural network with ReLU)
//! and delegated session key management with gas spend budgeting and replay protection.
//!
//! # ⚠️ "zkML" HERE MEANS "VERIFIABLE INFERENCE", NOT ZERO-KNOWLEDGE
//!
//! The namespace name is the product name and it predates the audit; what it
//! does NOT mean is a zero-knowledge proof system. **Both** §2 verify opcodes
//! — [`crate::svm::OpCode::SysCallVerifyZkMlReexec`] and
//! [`crate::svm::OpCode::SysCallVerifyZkMlAttestation`] — verify by
//! **RE-EXECUTION** of the registered model, not by a SNARK/STARK. See
//! [`crate::zkml_attestation`] for the full audit of what the attestation path
//! actually checks, and [`zkml_capabilities`] for the machine-readable
//! statement of it (served over RPC as `stell_zkmlCapabilities`).

use ed25519_dalek::{Signer, SigningKey};
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::post_quantum::{
    derive_pq_address, verify_pq_signature, FalconKeypair, PqScheme, DEFAULT_SALT,
    FALCON512_PUBKEY_LEN, HYBRID_PUBKEY_LEN, HYBRID_SIG_LEN,
};

// ===========================================================================
// MACHINE-READABLE CAPABILITY STATEMENT (audit W8.3 / production blocker A5)
// ===========================================================================

/// What ONE §2 zkML opcode actually guarantees.
///
/// Every field is a claim the chain can stand behind. The defaults are the
/// CONSERVATIVE ones: an integrator that reads only `zero_knowledge` and
/// `succinct` learns the truth without having to know the history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkMlOpcodeCapability {
    /// The opcode's stable wire name (the `OpCode` variant name).
    pub opcode: String,
    /// What the opcode really does, in one line.
    pub honest_name: String,
    /// The verification is SOUND: a forged proof (invented activations,
    /// lying outputs) is rejected.
    pub sound: bool,
    /// The proof is ZERO-KNOWLEDGE: the verifier learns nothing beyond the
    /// statement. **Always `false` today.**
    pub zero_knowledge: bool,
    /// Verification is SUCCINCT: the verifier does NOT run the model.
    /// **Always `false` today.**
    pub succinct: bool,
    /// The inputs and outputs are HIDDEN from the verifier. **Always `false`
    /// today.**
    pub hiding: bool,
    /// The verifier's work is linear in the model's parameter count.
    pub verifier_work: String,
    /// What the verifier must already hold for the check to mean anything.
    pub trusted_setup: String,
}

/// The machine-readable statement of what the zkML subsystem actually offers.
///
/// Exposed over RPC as `stell_zkmlCapabilities` so a wallet, an indexer or an
/// integrator can tell — from DATA, not from a marketing name — that the
/// on-chain inference check is a sound **re-execution attestation** and not a
/// zero-knowledge proof. This is the artifact that closes production blocker
/// A5 ("zk-SNARK ❌ не настоящий ZK").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkMlCapabilities {
    /// The protocol family this chain actually implements.
    pub protocol: String,
    /// The honest one-line summary.
    pub summary: String,
    /// A zero-knowledge proof system is offered. **Always `false`.**
    pub zero_knowledge: bool,
    /// A succinct proof system is offered. **Always `false`.**
    pub succinct: bool,
    /// The inputs/outputs are hidden from the verifier. **Always `false`.**
    pub hiding: bool,
    /// The check is SOUND (a forged proof is rejected). **`true`.**
    pub sound: bool,
    /// Is there a trusted setup? `false` — there is nothing to set up.
    pub trusted_setup: bool,
    /// A human-readable statement of what the "setup attestation" is.
    pub setup_note: String,
    /// Per-opcode detail.
    pub opcodes: Vec<ZkMlOpcodeCapability>,
    /// The residual, stated plainly: what a real ZK proof would need.
    pub residual: String,
}

/// The machine-readable capability statement of the zkML subsystem.
///
/// See [`ZkMlCapabilities`]. Deterministic, allocation-light and cheap
/// enough to serve on every RPC call.
pub fn zkml_capabilities() -> ZkMlCapabilities {
    ZkMlCapabilities {
        protocol: "verifiable-inference-by-re-execution".to_string(),
        summary: "On-chain inference is verified by RE-EXECUTION of the committed \
                  quantized model, bound by a BLAKE3 Merkle trace root and a \
                  Fiat-Shamir challenge. This is SOUND, but it is NOT \
                  zero-knowledge and NOT succinct: the verifier runs the whole \
                  model, and the inputs and outputs are public."
            .to_string(),
        zero_knowledge: false,
        succinct: false,
        hiding: false,
        sound: true,
        trusted_setup: false,
        setup_note: "There is no ceremony, no toxic waste and no Powers-of-Tau: the \
                     registered 'setup attestation' is a free-form operator LABEL \
                     carried in committed state. The chain only refuses the \
                     documented test-only prefix 'TEST-ONLY-DETERMINISTIC-SETUP'."
            .to_string(),
        opcodes: vec![
            ZkMlOpcodeCapability {
                opcode: "SysCallVerifyZkMlReexec".to_string(),
                honest_name: "verify-inference-by-re-execution".to_string(),
                sound: true,
                zero_knowledge: false,
                succinct: false,
                hiding: false,
                verifier_work: "linear in the registered model's parameter count".to_string(),
                trusted_setup: "the committed model registry (append-only, hash-matched)"
                    .to_string(),
            },
            ZkMlOpcodeCapability {
                opcode: "SysCallVerifyZkMlAttestation".to_string(),
                honest_name: "verify-inference-attestation-by-re-execution".to_string(),
                sound: true,
                zero_knowledge: false,
                succinct: false,
                hiding: false,
                verifier_work: "linear in the registered model's parameter count".to_string(),
                trusted_setup: "the committed model registry plus the committed model SPEC \
                                (constrained format + I/O shape + a setup LABEL)"
                    .to_string(),
            },
        ],
        residual: "A real zero-knowledge proof would need an R1CS/AIR circuit over the \
                   quantized forward pass, a polynomial commitment with a soundness \
                   argument, and a Fiat-Shamir transcript over that commitment. Until \
                   then the honest name for this subsystem is 'verifiable inference by \
                   re-execution'."
            .to_string(),
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Falcon-512 signature over `message` with the master's real keypair.
///
/// This MUST take the keypair, not the public key: a signature cannot be
/// produced from a public key. The old `sign_falcon512(pubkey, msg)` returned a
/// BLAKE3 "check digest" — a 1/256 forgeable pseudo-signature that only the
/// `#[cfg(test)]` shortcut of `verify_falcon_signature_or_test` accepted,
/// while `SessionKeyAuthorization::verify_signature` verifies through
/// `verify_pq_signature` (real FIPS 206 ring math) — so every Falcon-512 grant
/// it produced failed verification by construction.
///
/// AUDIT W6.1: that shortcut is GONE (the verifier is now the real FIPS 206
/// verifier in every build, test and release), and this helper signs with the
/// real keypair.
pub fn sign_falcon512(fk: &FalconKeypair, message: &[u8]) -> Vec<u8> {
    fk.sign(message)
}

/// Helper to construct a Hybrid public key from Ed25519 verifying key and Falcon-512 public key.
pub fn make_hybrid_pubkey(ed_pk: &[u8; 32], falcon_pk: &[u8]) -> Vec<u8> {
    assert_eq!(
        falcon_pk.len(),
        FALCON512_PUBKEY_LEN,
        "Falcon-512 public key must be {} bytes",
        FALCON512_PUBKEY_LEN
    );
    let mut pk = Vec::with_capacity(HYBRID_PUBKEY_LEN);
    pk.extend_from_slice(ed_pk);
    pk.extend_from_slice(falcon_pk);
    pk
}

/// Hybrid signature combining Ed25519 and Falcon-512 signatures.
///
/// Both halves are real: the Ed25519 half from `ed_sk`, the Falcon-512 half
/// from `fk`. Verification (`verify_pq_signature(Hybrid, ..)`) requires both to
/// be genuine.
pub fn sign_hybrid(ed_sk: &SigningKey, fk: &FalconKeypair, message: &[u8]) -> Vec<u8> {
    let mut sig = Vec::with_capacity(HYBRID_SIG_LEN);
    let ed_sig = ed_sk.sign(message);
    sig.extend_from_slice(&ed_sig.to_bytes());
    sig.extend_from_slice(&fk.sign(message));
    sig
}

/// Domain separator for session-key delegation grants (protocol v1). Every
/// grant signature covers `SESSION_KEY_DOMAIN || chain_id || ...`, so a grant
/// is unambiguous about both the protocol version and the chain it was made
/// for: two chains with identical (master, session, budget, validity) inputs
/// still produce different grant signatures, and a grant cannot be
/// byte-replayed as another chain's grant without invalidating the master's
/// signature.
pub const SESSION_KEY_DOMAIN: &[u8] = b"STELL_SESSKEY_V1";

/// The chain id a node is compiled/configured for when it has no explicit
/// override. It mirrors the value `main.rs` wires into the RPC state (`5757`)
/// and the wallet CLI's `--chain-id` default, so a default-constructed engine
/// enforces the same network id as the node it runs in.
///
/// The value a node actually compares against lives on the state engine (see
/// `InMemoryStateEngine::chain_id`), NOT in any committed structure: chain id
/// is node-local policy, so two chains with identical state must still hash
/// identically. This constant is only the default seed for that field.
pub const DEFAULT_CHAIN_ID: u64 = 5757;

/// Env var selecting this node's chain id. Two deployments of one binary MUST
/// be distinguishable (testnet vs mainnet share nothing, not even identity),
/// so the id is deployment configuration, not a compile-time constant.
/// Unset / unparsable / zero → [`DEFAULT_CHAIN_ID`].
pub const CHAIN_ID_ENV: &str = "STELL_CHAIN_ID";

/// This node's effective chain id: `STELL_CHAIN_ID` when it parses to a
/// non-zero `u64`, else [`DEFAULT_CHAIN_ID`].
///
/// Every place that used to hardcode `5757` (this module's default, the RPC
/// state, the state engine, the EVM adapter) must read THIS, so one binary
/// serves any number of networks with distinct identities.
pub fn effective_chain_id() -> u64 {
    std::env::var(CHAIN_ID_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_CHAIN_ID)
}

/// Parse a candidate chain-id env value the same way [`effective_chain_id`]
/// does (pure, for tests): `None` on unset/unparsable/zero.
pub fn parse_chain_id_env(v: Option<&str>) -> u64 {
    v.and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|id| *id > 0)
        .unwrap_or(DEFAULT_CHAIN_ID)
}

/// Fail-closed peer chain-id check (task (c)): a connected peer that reports a
/// different chain id is on a DIFFERENT network. Continuing would silently
/// partition (or cross-apply foreign blocks), so the caller must ABORT
/// startup / refuse the peer with this loud error — never proceed.
pub fn check_peer_chain_id(local: u64, peer: u64) -> Result<(), String> {
    if local == peer {
        return Ok(());
    }
    Err(format!(
        "[chain-id] REFUSING: peer reports chain id {peer} but this node is {local} \
         (STELL_CHAIN_ID={local}). A mismatch means a different network (testnet vs mainnet): \
         continuing would silently partition. Fix STELL_CHAIN_ID to match the network you intend \
         to join, or point at peers of your own chain."
    ))
}

/// Fail-closed multi-peer variant: every reported id must equal `local`, or
/// the first mismatch aborts with [`check_peer_chain_id`]'s loud error.
pub fn verify_peer_chain_ids(local: u64, peers: &[u64]) -> Result<(), String> {
    for peer in peers {
        check_peer_chain_id(local, *peer)?;
    }
    Ok(())
}

/// Scope bit: plain native value transfers (transactions with an EMPTY payload).
pub const SCOPE_TRANSFER: u64 = 1 << 0;
/// Scope bit: transactions carrying an SVM payload (contract/token/orderbook ops).
pub const SCOPE_SVM_PAYLOAD: u64 = 1 << 1;
/// Scope bit: transactions carrying an actor-mailbox send
/// (`OpCode::SysCallActorSend`).
///
/// A payload with an actor send requires this bit IN ADDITION to
/// [`SCOPE_SVM_PAYLOAD`] (see `Transaction::required_scope`): it is an extra
/// capability layered on top of "may run a payload", not a replacement for
/// it. Replacing the payload bit with this one would let a grant that only
/// ever asked for "send messages" also run arbitrary token / staking / order
/// syscalls in the same payload - a scope escalation. The bit is appended
/// (`1 << 2`), so every already-issued grant's scope mask keeps its meaning
/// and its bytes.
pub const SCOPE_ACTOR_SEND: u64 = 1 << 2;
/// Convenience mask: everything is allowed.
pub const SCOPE_ALL: u64 = u64::MAX;

/// Delegated Session Key for AI Agents
///
/// Layout note (bincode verdict): `Transaction`/`Block` must never gain a new
/// field (bincode 1.3 is non-self-describing, so any field breaks decoding of
/// persisted blocks). The delegation therefore rides INSIDE the transaction's
/// existing `signature: Vec<u8>` as an envelope; this struct itself is only
/// ever serialized inside that envelope, which no pre-envelope block contains.
/// Existing Ed25519 grants encode byte-identically to legacy formats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionKeyAuthorization {
    pub master_address: [u8; 32],
    pub session_pubkey: [u8; 32],
    pub valid_until: u64,
    pub max_gas_spend: u64,
    /// Gas already consumed against `max_gas_spend`. Set by the master when it
    /// re-issues a grant; it is NOT covered by the master's signature (like the
    /// original layout) but it IS covered by the transaction signature, because
    /// the whole struct is committed into the signed message.
    pub gas_spent: u64,
    /// Bitmask of operations this grant covers (see `SCOPE_*`).
    pub scope: u64,
    /// Hard cap on `tx.amount` per transaction under this grant.
    pub max_value_per_tx: u64,
    /// Chain this grant was minted for, bound into the master's signature.
    pub chain_id: u64,
    /// Ed25519 signature from master_address over the domain-separated grant
    /// message (see [`SessionKeyAuthorization::grant_message`]).
    pub master_signature: Vec<u8>,

    /// Cryptographic scheme of the master (delegating) key: Ed25519, Falcon-512, or Hybrid.
    pub master_scheme: PqScheme,
    /// Cryptographic scheme of the session key: Ed25519, Falcon-512, or Hybrid.
    pub session_scheme: PqScheme,
    /// Full master public key bytes when master is post-quantum or hybrid (None for Ed25519).
    pub master_pubkey: Option<Vec<u8>>,
    /// Full session public key bytes when session key is post-quantum or hybrid (None for Ed25519).
    pub session_pubkey_bytes: Option<Vec<u8>>,
}

impl Serialize for SessionKeyAuthorization {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            #[derive(Serialize)]
            struct HumanReadable<'a> {
                master_address: &'a [u8; 32],
                session_pubkey: &'a [u8; 32],
                valid_until: u64,
                max_gas_spend: u64,
                gas_spent: u64,
                scope: u64,
                max_value_per_tx: u64,
                chain_id: u64,
                master_signature: &'a [u8],
                master_scheme: PqScheme,
                session_scheme: PqScheme,
                master_pubkey: &'a Option<Vec<u8>>,
                session_pubkey_bytes: &'a Option<Vec<u8>>,
            }
            let hr = HumanReadable {
                master_address: &self.master_address,
                session_pubkey: &self.session_pubkey,
                valid_until: self.valid_until,
                max_gas_spend: self.max_gas_spend,
                gas_spent: self.gas_spent,
                scope: self.scope,
                max_value_per_tx: self.max_value_per_tx,
                chain_id: self.chain_id,
                master_signature: &self.master_signature,
                master_scheme: self.master_scheme,
                session_scheme: self.session_scheme,
                master_pubkey: &self.master_pubkey,
                session_pubkey_bytes: &self.session_pubkey_bytes,
            };
            hr.serialize(serializer)
        } else if self.is_pure_ed25519() {
            let mut state = serializer.serialize_struct("SessionKeyAuthorization", 9)?;
            state.serialize_field("master_address", &self.master_address)?;
            state.serialize_field("session_pubkey", &self.session_pubkey)?;
            state.serialize_field("valid_until", &self.valid_until)?;
            state.serialize_field("max_gas_spend", &self.max_gas_spend)?;
            state.serialize_field("gas_spent", &self.gas_spent)?;
            state.serialize_field("scope", &self.scope)?;
            state.serialize_field("max_value_per_tx", &self.max_value_per_tx)?;
            state.serialize_field("chain_id", &self.chain_id)?;
            state.serialize_field("master_signature", &self.master_signature)?;
            state.end()
        } else {
            let mut state = serializer.serialize_struct("SessionKeyAuthorization", 13)?;
            state.serialize_field("master_address", &self.master_address)?;
            state.serialize_field("session_pubkey", &self.session_pubkey)?;
            state.serialize_field("valid_until", &self.valid_until)?;
            state.serialize_field("max_gas_spend", &self.max_gas_spend)?;
            state.serialize_field("gas_spent", &self.gas_spent)?;
            state.serialize_field("scope", &self.scope)?;
            state.serialize_field("max_value_per_tx", &self.max_value_per_tx)?;
            state.serialize_field("chain_id", &self.chain_id)?;
            state.serialize_field("master_signature", &self.master_signature)?;
            let master_scheme_id = self.master_scheme.id();
            let session_scheme_id = self.session_scheme.id();
            state.serialize_field("master_scheme", &master_scheme_id)?;
            state.serialize_field("session_scheme", &session_scheme_id)?;
            state.serialize_field("master_pubkey", &self.master_pubkey)?;
            state.serialize_field("session_pubkey_bytes", &self.session_pubkey_bytes)?;
            state.end()
        }
    }
}

impl<'de> Deserialize<'de> for SessionKeyAuthorization {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            #[derive(Deserialize)]
            struct HumanReadable {
                master_address: [u8; 32],
                session_pubkey: [u8; 32],
                valid_until: u64,
                max_gas_spend: u64,
                gas_spent: u64,
                scope: u64,
                max_value_per_tx: u64,
                chain_id: u64,
                master_signature: Vec<u8>,
                #[serde(default = "default_scheme")]
                master_scheme: PqScheme,
                #[serde(default = "default_scheme")]
                session_scheme: PqScheme,
                #[serde(default)]
                master_pubkey: Option<Vec<u8>>,
                #[serde(default)]
                session_pubkey_bytes: Option<Vec<u8>>,
            }
            fn default_scheme() -> PqScheme {
                PqScheme::Ed25519
            }
            let hr = HumanReadable::deserialize(deserializer)?;
            Ok(SessionKeyAuthorization {
                master_address: hr.master_address,
                session_pubkey: hr.session_pubkey,
                valid_until: hr.valid_until,
                max_gas_spend: hr.max_gas_spend,
                gas_spent: hr.gas_spent,
                scope: hr.scope,
                max_value_per_tx: hr.max_value_per_tx,
                chain_id: hr.chain_id,
                master_signature: hr.master_signature,
                master_scheme: hr.master_scheme,
                session_scheme: hr.session_scheme,
                master_pubkey: hr.master_pubkey,
                session_pubkey_bytes: hr.session_pubkey_bytes,
            })
        } else {
            struct BincodeVisitor;
            impl<'de> Visitor<'de> for BincodeVisitor {
                type Value = SessionKeyAuthorization;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a SessionKeyAuthorization struct")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let master_address: [u8; 32] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("missing master_address"))?;
                    let session_pubkey: [u8; 32] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("missing session_pubkey"))?;
                    let valid_until: u64 = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("missing valid_until"))?;
                    let max_gas_spend: u64 = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("missing max_gas_spend"))?;
                    let gas_spent: u64 = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("missing gas_spent"))?;
                    let scope: u64 = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("missing scope"))?;
                    let max_value_per_tx: u64 = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("missing max_value_per_tx"))?;
                    let chain_id: u64 = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("missing chain_id"))?;
                    let master_signature: Vec<u8> = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("missing master_signature"))?;

                    let master_scheme_id: Option<u8> = match seq.next_element::<u8>() {
                        Ok(Some(id)) => Some(id),
                        _ => None,
                    };
                    let (master_scheme, session_scheme, master_pubkey, session_pubkey_bytes) =
                        match master_scheme_id {
                            None => (PqScheme::Ed25519, PqScheme::Ed25519, None, None),
                            Some(mid) => {
                                let master_scheme =
                                    PqScheme::from_id(mid).map_err(serde::de::Error::custom)?;
                                let session_scheme_id: u8 =
                                    seq.next_element()?.ok_or_else(|| {
                                        serde::de::Error::custom("missing session_scheme")
                                    })?;
                                let session_scheme = PqScheme::from_id(session_scheme_id)
                                    .map_err(serde::de::Error::custom)?;
                                let master_pubkey: Option<Vec<u8>> =
                                    seq.next_element()?.unwrap_or(None);
                                let session_pubkey_bytes: Option<Vec<u8>> =
                                    seq.next_element()?.unwrap_or(None);
                                (
                                    master_scheme,
                                    session_scheme,
                                    master_pubkey,
                                    session_pubkey_bytes,
                                )
                            }
                        };

                    Ok(SessionKeyAuthorization {
                        master_address,
                        session_pubkey,
                        valid_until,
                        max_gas_spend,
                        gas_spent,
                        scope,
                        max_value_per_tx,
                        chain_id,
                        master_signature,
                        master_scheme,
                        session_scheme,
                        master_pubkey,
                        session_pubkey_bytes,
                    })
                }
            }

            deserializer.deserialize_struct(
                "SessionKeyAuthorization",
                &[
                    "master_address",
                    "session_pubkey",
                    "valid_until",
                    "max_gas_spend",
                    "gas_spent",
                    "scope",
                    "max_value_per_tx",
                    "chain_id",
                    "master_signature",
                    "master_scheme",
                    "session_scheme",
                    "master_pubkey",
                    "session_pubkey_bytes",
                ],
                BincodeVisitor,
            )
        }
    }
}

impl SessionKeyAuthorization {
    /// True when this grant uses the legacy pure Ed25519 scheme without extensions.
    pub fn is_pure_ed25519(&self) -> bool {
        self.master_scheme == PqScheme::Ed25519
            && self.session_scheme == PqScheme::Ed25519
            && self.master_pubkey.is_none()
            && self.session_pubkey_bytes.is_none()
    }

    /// True when either the master key or the session key is post-quantum / hybrid.
    pub fn is_post_quantum(&self) -> bool {
        self.master_scheme.is_post_quantum() || self.session_scheme.is_post_quantum()
    }

    /// Master public key bytes (or 32-byte address for Ed25519).
    pub fn master_pubkey(&self) -> &[u8] {
        self.master_pubkey
            .as_deref()
            .unwrap_or(&self.master_address)
    }

    /// Session public key bytes (or 32-byte session pubkey for Ed25519).
    pub fn session_pubkey_bytes(&self) -> &[u8] {
        self.session_pubkey_bytes
            .as_deref()
            .unwrap_or(&self.session_pubkey)
    }

    /// The exact bytes the master signs: domain separator, chain id, then the
    /// grant parameters. Any change to any covered field invalidates the
    /// signature (this is what the tamper tests pin).
    pub fn grant_message(
        master_address: &[u8; 32],
        session_pubkey: &[u8; 32],
        valid_until: u64,
        max_gas_spend: u64,
        scope: u64,
        max_value_per_tx: u64,
        chain_id: u64,
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(SESSION_KEY_DOMAIN.len() + 8 * 5 + 64);
        msg.extend_from_slice(SESSION_KEY_DOMAIN);
        msg.extend_from_slice(&chain_id.to_be_bytes());
        msg.extend_from_slice(master_address);
        msg.extend_from_slice(session_pubkey);
        msg.extend_from_slice(&valid_until.to_be_bytes());
        msg.extend_from_slice(&max_gas_spend.to_be_bytes());
        msg.extend_from_slice(&scope.to_be_bytes());
        msg.extend_from_slice(&max_value_per_tx.to_be_bytes());
        msg
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_delegation(
        master_key: &SigningKey,
        session_pubkey: [u8; 32],
        valid_until: u64,
        max_gas_spend: u64,
        scope: u64,
        max_value_per_tx: u64,
        chain_id: u64,
    ) -> Self {
        let master_pub = master_key.verifying_key().to_bytes();
        let msg = Self::grant_message(
            &master_pub,
            &session_pubkey,
            valid_until,
            max_gas_spend,
            scope,
            max_value_per_tx,
            chain_id,
        );

        let sig = master_key.sign(&msg);

        Self {
            master_address: master_pub,
            session_pubkey,
            valid_until,
            max_gas_spend,
            gas_spent: 0,
            scope,
            max_value_per_tx,
            chain_id,
            master_signature: sig.to_vec(),
            master_scheme: PqScheme::Ed25519,
            session_scheme: PqScheme::Ed25519,
            master_pubkey: None,
            session_pubkey_bytes: None,
        }
    }

    /// Sign a delegation grant where master key is a Falcon-512 post-quantum key.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_delegation_falcon512(
        master_fk: &FalconKeypair,
        session_scheme: PqScheme,
        session_pubkey_raw: &[u8],
        valid_until: u64,
        max_gas_spend: u64,
        scope: u64,
        max_value_per_tx: u64,
        chain_id: u64,
    ) -> Self {
        let master_pubkey = master_fk.public_key();
        let master_address = derive_pq_address(PqScheme::Falcon512, master_pubkey, &DEFAULT_SALT);
        let (session_pubkey, session_pubkey_bytes) = if session_scheme == PqScheme::Ed25519 {
            let addr = <[u8; 32]>::try_from(session_pubkey_raw)
                .expect("Ed25519 session pubkey must be 32 bytes");
            (addr, None)
        } else {
            let addr = derive_pq_address(session_scheme, session_pubkey_raw, &DEFAULT_SALT);
            (addr, Some(session_pubkey_raw.to_vec()))
        };

        let msg = Self::grant_message(
            &master_address,
            &session_pubkey,
            valid_until,
            max_gas_spend,
            scope,
            max_value_per_tx,
            chain_id,
        );
        let master_signature = sign_falcon512(master_fk, &msg);

        Self {
            master_address,
            session_pubkey,
            valid_until,
            max_gas_spend,
            gas_spent: 0,
            scope,
            max_value_per_tx,
            chain_id,
            master_signature,
            master_scheme: PqScheme::Falcon512,
            session_scheme,
            master_pubkey: Some(master_pubkey.to_vec()),
            session_pubkey_bytes,
        }
    }

    /// Sign a delegation grant where master key is a Hybrid (Ed25519 + Falcon-512) key.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_delegation_hybrid(
        master_ed_sk: &SigningKey,
        master_fk: &FalconKeypair,
        session_scheme: PqScheme,
        session_pubkey_raw: &[u8],
        valid_until: u64,
        max_gas_spend: u64,
        scope: u64,
        max_value_per_tx: u64,
        chain_id: u64,
    ) -> Self {
        let ed_pk = master_ed_sk.verifying_key().to_bytes();
        let hybrid_pk = make_hybrid_pubkey(&ed_pk, master_fk.public_key());
        let master_address = derive_pq_address(PqScheme::Hybrid, &hybrid_pk, &DEFAULT_SALT);
        let (session_pubkey, session_pubkey_bytes) = if session_scheme == PqScheme::Ed25519 {
            let addr = <[u8; 32]>::try_from(session_pubkey_raw)
                .expect("Ed25519 session pubkey must be 32 bytes");
            (addr, None)
        } else {
            let addr = derive_pq_address(session_scheme, session_pubkey_raw, &DEFAULT_SALT);
            (addr, Some(session_pubkey_raw.to_vec()))
        };

        let msg = Self::grant_message(
            &master_address,
            &session_pubkey,
            valid_until,
            max_gas_spend,
            scope,
            max_value_per_tx,
            chain_id,
        );
        let master_signature = sign_hybrid(master_ed_sk, master_fk, &msg);

        Self {
            master_address,
            session_pubkey,
            valid_until,
            max_gas_spend,
            gas_spent: 0,
            scope,
            max_value_per_tx,
            chain_id,
            master_signature,
            master_scheme: PqScheme::Hybrid,
            session_scheme,
            master_pubkey: Some(hybrid_pk),
            session_pubkey_bytes,
        }
    }

    /// Sign a delegation grant where master key is Ed25519 and session key is post-quantum or hybrid.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_delegation_ed25519_master(
        master_key: &SigningKey,
        session_scheme: PqScheme,
        session_pubkey_raw: &[u8],
        valid_until: u64,
        max_gas_spend: u64,
        scope: u64,
        max_value_per_tx: u64,
        chain_id: u64,
    ) -> Self {
        let master_pub = master_key.verifying_key().to_bytes();
        let (session_pubkey, session_pubkey_bytes) = if session_scheme == PqScheme::Ed25519 {
            let addr = <[u8; 32]>::try_from(session_pubkey_raw)
                .expect("Ed25519 session pubkey must be 32 bytes");
            (addr, None)
        } else {
            let addr = derive_pq_address(session_scheme, session_pubkey_raw, &DEFAULT_SALT);
            (addr, Some(session_pubkey_raw.to_vec()))
        };

        let msg = Self::grant_message(
            &master_pub,
            &session_pubkey,
            valid_until,
            max_gas_spend,
            scope,
            max_value_per_tx,
            chain_id,
        );
        let master_signature = master_key.sign(&msg).to_vec();

        Self {
            master_address: master_pub,
            session_pubkey,
            valid_until,
            max_gas_spend,
            gas_spent: 0,
            scope,
            max_value_per_tx,
            chain_id,
            master_signature,
            master_scheme: PqScheme::Ed25519,
            session_scheme,
            master_pubkey: None,
            session_pubkey_bytes,
        }
    }

    /// General constructor for constructing PQ or hybrid grants directly.
    #[allow(clippy::too_many_arguments)]
    pub fn new_pq(
        master_scheme: PqScheme,
        master_address: [u8; 32],
        master_pubkey: Option<Vec<u8>>,
        session_scheme: PqScheme,
        session_pubkey: [u8; 32],
        session_pubkey_bytes: Option<Vec<u8>>,
        valid_until: u64,
        max_gas_spend: u64,
        gas_spent: u64,
        scope: u64,
        max_value_per_tx: u64,
        chain_id: u64,
        master_signature: Vec<u8>,
    ) -> Self {
        Self {
            master_address,
            session_pubkey,
            valid_until,
            max_gas_spend,
            gas_spent,
            scope,
            max_value_per_tx,
            chain_id,
            master_signature,
            master_scheme,
            session_scheme,
            master_pubkey,
            session_pubkey_bytes,
        }
    }

    /// Verify the master's grant signature only (no time/scope/budget check).
    /// Covers domain separator, chain id, session pubkey, validity window and
    /// both caps — flipping ANY of those fields invalidates it.
    /// Supports Ed25519, Falcon-512, and Hybrid master keys.
    pub fn verify_signature(&self) -> bool {
        // FULL-PQ: non-PQ schemes are always refused (no classical fallback).
        if !self.master_scheme.is_post_quantum() || !self.session_scheme.is_post_quantum() {
            return false;
        }

        let msg = Self::grant_message(
            &self.master_address,
            &self.session_pubkey,
            self.valid_until,
            self.max_gas_spend,
            self.scope,
            self.max_value_per_tx,
            self.chain_id,
        );

        match self.master_scheme {
            PqScheme::Ed25519 => {
                // FULL-PQ: classical master scheme removed.
                false
            }
            PqScheme::Falcon512 | PqScheme::Hybrid | PqScheme::MlDsa44 => {
                let Some(pk) = &self.master_pubkey else {
                    return false;
                };
                let expected_addr = derive_pq_address(self.master_scheme, pk, &DEFAULT_SALT);
                if expected_addr != self.master_address {
                    return false;
                }
                verify_pq_signature(self.master_scheme, pk, &msg, &self.master_signature)
            }
        }
    }

    /// Gas budget not yet consumed by this grant.
    pub fn remaining_gas(&self) -> u64 {
        self.max_gas_spend.saturating_sub(self.gas_spent)
    }

    /// True when the grant's scope mask covers every bit in `required`.
    pub fn grants_scope(&self, required: u64) -> bool {
        self.scope & required == required
    }

    /// Verify delegation validity at an explicit time (block time in consensus).
    /// This is the deterministic check — never use wall-clock inside execution.
    pub fn verify_at(&self, current_time: u64) -> bool {
        current_time <= self.valid_until && self.verify_signature()
    }

    /// Off-chain convenience: validity against wall-clock time.
    pub fn verify(&self) -> bool {
        self.verify_at(now_secs())
    }

    /// Check delegation validity and deduct consumed gas budget.
    ///
    /// SECURITY: expiry is evaluated against the caller-supplied `current_time`
    /// (the block timestamp in consensus), NOT the local wall clock, so every
    /// node makes the same decision.
    pub fn verify_and_spend_gas(
        &mut self,
        gas_amount: u64,
        current_time: u64,
    ) -> Result<(), String> {
        if current_time > self.valid_until {
            return Err("Session key has expired".to_string());
        }
        if self.gas_spent.saturating_add(gas_amount) > self.max_gas_spend {
            return Err(format!(
                "Session key gas limit exceeded (spent: {}, requested: {}, max: {})",
                self.gas_spent, gas_amount, self.max_gas_spend
            ));
        }
        if !self.verify_signature() {
            return Err("Invalid session key delegation signature".to_string());
        }

        self.gas_spent += gas_amount;
        Ok(())
    }

    /// Verify a transaction payload signed by this session key.
    /// Supports Ed25519, Falcon-512, and Hybrid session keys.
    pub fn verify_session_signature(&self, message: &[u8], signature_bytes: &[u8]) -> bool {
        // FULL-PQ: non-PQ schemes are always refused (no classical fallback).
        if !self.master_scheme.is_post_quantum() || !self.session_scheme.is_post_quantum() {
            return false;
        }

        match self.session_scheme {
            PqScheme::Ed25519 => {
                // FULL-PQ: classical session scheme removed.
                false
            }
            PqScheme::Falcon512 | PqScheme::Hybrid | PqScheme::MlDsa44 => {
                let Some(pk) = &self.session_pubkey_bytes else {
                    return false;
                };
                let expected_addr = derive_pq_address(self.session_scheme, pk, &DEFAULT_SALT);
                if expected_addr != self.session_pubkey {
                    return false;
                }
                verify_pq_signature(self.session_scheme, pk, message, signature_bytes)
            }
        }
    }
}

// ===========================================================================
// Session-key REGISTRY (phase 2): stateful, committed, revocable.
// ===========================================================================

/// Why the on-chain session-key registry refused a transaction.
///
/// The registry is the STATEFUL half of the session gate; the stateless half
/// is `Transaction::check_session_policy`, which validates the grant the
/// transaction carries. Callers run both (see
/// `InMemoryStateEngine::session_gate`), so this enum only ever reports what
/// the REGISTERED record says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionRegistryError {
    /// The master revoked this session key on chain. Terminal: no re-presented
    /// grant, and no re-run of the same transaction, can un-revoke it.
    Revoked,
    /// The registry already binds this session pubkey to a different master.
    /// Two masters must not share one budget: whoever registered first owns
    /// the record, and a grant from anyone else is refused rather than allowed
    /// to ride - or reset - that budget.
    MasterMismatch,
    /// The registered record's `valid_until` has passed at `now` (the block
    /// timestamp in consensus).
    Expired,
    /// The registered record's scope mask does not cover this transaction
    /// kind, or `amount` exceeds its `max_value_per_tx`.
    OutOfScope,
    /// Cumulative spend (`record.gas_spent` + everything already committed by
    /// an earlier transaction of the same grant in this same pass) plus this
    /// transaction's declared `gas_limit` exceeds the registered maximum.
    BudgetExhausted,
}

impl std::fmt::Display for SessionRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SessionRegistryError::Revoked => "session key has been revoked",
            SessionRegistryError::MasterMismatch => {
                "session key is registered to a different master"
            }
            SessionRegistryError::Expired => "registered session key has expired",
            SessionRegistryError::OutOfScope => {
                "registered session key does not cover this transaction (scope/value cap)"
            }
            SessionRegistryError::BudgetExhausted => {
                "registered session key has no remaining gas budget"
            }
        };
        write!(f, "{s}")
    }
}

/// One registered session key, keyed by its PUBLIC key.
///
/// `master`, `valid_until`, `max_gas_spend`, `scope` and `max_value_per_tx`
/// are copied from the grant the first transaction under it carries (lazy
/// registration - there is no registration transaction). From then on the
/// RECORD is the source of truth: re-presenting a grant never raises any of
/// these ceilings and never lowers `gas_spent`, because `gas_spent` is the one
/// field the master's signature does not cover (see `SessionKeyAuthorization`)
/// and therefore the one a presenter could otherwise forge back to zero.
///
/// `revoked` is terminal: nothing in this file ever sets it back to `false`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKeyRecord {
    /// The delegator (`tx.from` of every transaction under this key).
    pub master: [u8; 32],
    pub valid_until: u64,
    pub max_gas_spend: u64,
    /// Cumulative gas actually consumed by transactions that APPLIED under
    /// this key. Only applied transactions charge it, so a refused transaction
    /// costs the grant nothing.
    pub gas_spent: u64,
    pub scope: u64,
    /// Per-transaction value cap, copied from the grant at registration.
    pub max_value_per_tx: u64,
    /// Set by `OpCode::SysCallRevokeSession` and never cleared.
    pub revoked: bool,
}

/// In-block (or in-selection-pass) overlay of session gas that has been
/// COMMITTED by an earlier transaction of the same grant but is not yet in the
/// registry, because the deduction only lands when a transaction actually
/// applies. Admission and the proposer filter both carry one of these so two
/// transactions of one grant in the same block cannot each pass against the
/// same remaining budget.
#[derive(Clone, Debug, Default)]
pub struct SessionSpendSim(HashMap<[u8; 32], u64>);

impl SessionSpendSim {
    /// Gas this pass has already committed to `pk`.
    pub fn pending(&self, pk: &[u8; 32]) -> u64 {
        self.0.get(pk).copied().unwrap_or(0)
    }

    /// Commit `gas` of `pk`'s budget for the rest of this pass.
    pub fn add(&mut self, pk: [u8; 32], gas: u64) {
        let e = self.0.entry(pk).or_insert(0);
        *e = e.saturating_add(gas);
    }
}

/// The on-chain session-key registry: `session pubkey -> record`, lazily
/// registered and cumulatively metered.
///
/// `BTreeMap` on purpose: iteration order is a function of the contents, so
/// the commitment digest (src/commitment.rs) can hash it without re-sorting
/// and two nodes with identical state produce identical bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKeyRegistry {
    pub entries: BTreeMap<[u8; 32], SessionKeyRecord>,
}

impl SessionKeyRegistry {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, session_pubkey: &[u8; 32]) -> Option<&SessionKeyRecord> {
        self.entries.get(session_pubkey)
    }

    /// Terminal revocation check. `false` for an unregistered key: a key that
    /// was never used has never been revoked either (and cannot be, see the
    /// handler in src/svm.rs).
    pub fn is_revoked(&self, session_pubkey: &[u8; 32]) -> bool {
        self.entries
            .get(session_pubkey)
            .map(|r| r.revoked)
            .unwrap_or(false)
    }

    /// Record a PREVENTIVE revocation ("tombstone") for a session key that has
    /// never applied a transaction on chain.
    ///
    /// The lazy registry cannot revoke an unused grant: there is no record to
    /// flag, and the VM's `SysCallRevokeSession` deliberately fails closed on
    /// an unknown key so nobody can pre-tombstone a victim's key by guessing
    /// its public key. That left a real hole - a master who revoked a grant
    /// before the agent ever used it had no way to make the revocation stick,
    /// and a later-presented copy of the still-valid grant would be accepted.
    ///
    /// A tombstone closes it. It is stored in `entries` like any other record -
    /// same committed digest domain, so it is part of the state root and
    /// survives snapshot/restore/reorg - with `revoked = true` and every grant
    /// ceiling zeroed. `entry().or_insert()` means it can never overwrite a
    /// record that already exists, and `note_applied` can never clear
    /// `revoked`, so once placed the denial is terminal.
    ///
    /// The caller MUST have authenticated the master first: writing a tombstone
    /// for an arbitrary pubkey would let anyone deny a key they do not own. See
    /// `InMemoryStateEngine::execute_payload`, which only calls this when the
    /// same legacy (master-signed) payload carries a matching
    /// `SysCallPublishSessionGrant` signed by that master.
    pub fn note_tombstone(&mut self, session_pubkey: [u8; 32], master: [u8; 32]) {
        self.entries
            .entry(session_pubkey)
            .or_insert(SessionKeyRecord {
                master,
                valid_until: 0,
                max_gas_spend: 0,
                gas_spent: 0,
                scope: 0,
                max_value_per_tx: 0,
                revoked: true,
            });
    }

    /// The registry half of the session gate: revocation, master binding,
    /// expiry/scope/value of the REGISTERED record, and the cumulative budget
    /// (`record.gas_spent + sim.pending + gas_limit <= record.max_gas_spend`).
    ///
    /// `grant` must already have passed `Transaction::check_session_policy`
    /// (signature, master binding, and the grant's own expiry/scope/value/
    /// budget - which is what makes the two halves an intersection: a
    /// re-presented grant can only ever narrow what the record allows, never
    /// widen it).
    ///
    /// `sim` carries the gas earlier transactions of this same pass have
    /// committed; every transaction this returns `Ok` for is added to it, so
    /// the caller's simulation and the eventual deduction agree.
    #[allow(clippy::too_many_arguments)]
    pub fn check(
        &self,
        grant: &SessionKeyAuthorization,
        amount: u64,
        gas_limit: u64,
        required_scope: u64,
        now: u64,
        sim: &mut SessionSpendSim,
    ) -> Result<(), SessionRegistryError> {
        let pk = grant.session_pubkey;
        let Some(rec) = self.entries.get(&pk) else {
            // Lazy registration has not happened yet (first use ever, or the
            // first use is happening right now in this pass): the grant the
            // transaction carries is the only ceiling there is - the stateless
            // policy already validated it - but the pass's own in-flight
            // transactions still count against it.
            if sim.pending(&pk).saturating_add(gas_limit) > grant.max_gas_spend {
                return Err(SessionRegistryError::BudgetExhausted);
            }
            sim.add(pk, gas_limit);
            return Ok(());
        };

        if rec.revoked {
            return Err(SessionRegistryError::Revoked);
        }
        if rec.master != grant.master_address {
            return Err(SessionRegistryError::MasterMismatch);
        }
        if now > rec.valid_until {
            return Err(SessionRegistryError::Expired);
        }
        if rec.scope & required_scope != required_scope {
            return Err(SessionRegistryError::OutOfScope);
        }
        if amount > rec.max_value_per_tx {
            return Err(SessionRegistryError::OutOfScope);
        }
        let committed = rec.gas_spent.saturating_add(sim.pending(&pk));
        if committed.saturating_add(gas_limit) > rec.max_gas_spend {
            return Err(SessionRegistryError::BudgetExhausted);
        }
        sim.add(pk, gas_limit);
        Ok(())
    }

    /// Record that a transaction under `grant` APPLIED and consumed
    /// `gas_used` of the budget.
    ///
    /// * First use: the grant is registered (master / validity / scope /
    ///   both caps copied from it) with `gas_spent = gas_used`. Registering
    ///   requires a signature by the SESSION private key (the transaction
    ///   would not verify without it), so no third party can squat a key it
    ///   does not hold.
    /// * Later uses: only `gas_spent` moves. The stored ceilings are never
    ///   rewritten, so a re-presented grant cannot extend its own budget -
    ///   only spend more of it.
    ///
    /// Infallible by design: it runs after the transaction has already been
    /// committed, so it must not be able to fail. The `.min(max_gas_spend)`
    /// clamp keeps `gas_spent <= max_gas_spend` true even if two single-tx
    /// applies raced each other's gate.
    pub fn note_applied(&mut self, grant: &SessionKeyAuthorization, gas_used: u64) {
        let pk = grant.session_pubkey;
        match self.entries.get_mut(&pk) {
            Some(rec) => {
                rec.gas_spent = rec
                    .gas_spent
                    .saturating_add(gas_used)
                    .min(rec.max_gas_spend);
            }
            None => {
                let rec = SessionKeyRecord {
                    master: grant.master_address,
                    valid_until: grant.valid_until,
                    max_gas_spend: grant.max_gas_spend,
                    gas_spent: gas_used.min(grant.max_gas_spend),
                    scope: grant.scope,
                    max_value_per_tx: grant.max_value_per_tx,
                    revoked: false,
                };
                self.entries.insert(pk, rec);
            }
        }
    }
}

/// Hard cap on the parameters a single registration may put on chain.
///
/// 16_384 i64 parameters = 128 KiB of weights (plus the per-layer dims). It
/// bounds BOTH directions of the §2 cost: how much state one
/// `SysCallRegisterZkMlModel` can write, and how much work every verifying
/// node re-executes per `SysCallVerifyZkMlReexec` (the re-execution is linear in
/// this - see the opcode's gas arm and its in-handler re-execution charge).
pub const MAX_ZKML_MODEL_PARAMS: usize = 16_384;

/// Quantized Neural Network layer with weights, biases and ReLU activation
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QuantizedLayer {
    pub in_dim: usize,
    pub out_dim: usize,
    pub weights: Vec<i64>, // row-major in_dim * out_dim
    pub biases: Vec<i64>,  // length out_dim
}

impl QuantizedLayer {
    pub fn new(in_dim: usize, out_dim: usize, weights: Vec<i64>, biases: Vec<i64>) -> Self {
        assert_eq!(weights.len(), in_dim * out_dim);
        assert_eq!(biases.len(), out_dim);
        Self {
            in_dim,
            out_dim,
            weights,
            biases,
        }
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update((self.in_dim as u64).to_be_bytes());
        hasher.update((self.out_dim as u64).to_be_bytes());
        for w in &self.weights {
            hasher.update(w.to_be_bytes());
        }
        for b in &self.biases {
            hasher.update(b.to_be_bytes());
        }
        hasher.finalize().into()
    }

    /// Structural well-formedness of one layer.
    ///
    /// `forward` is written for the fast path and ASSERTS (input width,
    /// `weights[i * out_dim + j]`, `biases[j]`), so a layer that arrives over
    /// the wire through bincode - which does not run `QuantizedLayer::new`'s
    /// constructor asserts - would otherwise panic a node that merely looked at
    /// it. Every path that accepts an attacker-supplied model (the committed
    /// registry) must reject malformed layers with this first.
    pub fn validate(&self) -> bool {
        self.in_dim > 0
            && self.out_dim > 0
            && self.in_dim.checked_mul(self.out_dim) == Some(self.weights.len())
            && self.biases.len() == self.out_dim
    }

    /// CONSTRAINED-FORMAT gate for ONE layer (the `validate` extension
    /// the attestation path enforces at spec registration).
    ///
    /// The legacy `validate` stays exactly as permissive as before (unbounded
    /// `i64` + saturation keeps working through the re-execution path); this
    /// is the ADDITIONAL predicate the attestation path demands: weights must
    /// fit `i8` (see `crate::zkml_attestation::ATTEST_MIN_WEIGHT/MAX_WEIGHT`). Biases are
    /// bounded transitively by the model-level worst-case accumulator check
    /// (`QuantizedLinearModel::is_attestation_compatible`), which needs the whole
    /// layer stack, not one layer.
    pub fn validate_constrained_bounds(&self) -> bool {
        if !self.validate() {
            return false;
        }
        if self.in_dim > crate::zkml_attestation::ATTEST_MAX_DIM
            || self.out_dim > crate::zkml_attestation::ATTEST_MAX_DIM
        {
            return false;
        }
        self.weights.iter().all(|w| {
            *w >= crate::zkml_attestation::ATTEST_MIN_WEIGHT
                && *w <= crate::zkml_attestation::ATTEST_MAX_WEIGHT
        })
    }

    pub fn forward(&self, inputs: &[i64]) -> (Vec<i64>, Vec<i64>) {
        assert_eq!(inputs.len(), self.in_dim);
        let mut z = Vec::with_capacity(self.out_dim);
        let mut a = Vec::with_capacity(self.out_dim);

        for j in 0..self.out_dim {
            let mut sum = self.biases[j];
            for (i, &inp) in inputs.iter().enumerate().take(self.in_dim) {
                sum = sum.saturating_add(inp.saturating_mul(self.weights[i * self.out_dim + j]));
            }
            z.push(sum);
            // ReLU activation: a = max(0, z)
            a.push(if sum > 0 { sum } else { 0 });
        }
        (z, a)
    }
}

/// Multi-layer quantized model
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QuantizedLinearModel {
    pub layers: Vec<QuantizedLayer>,
}

impl QuantizedLinearModel {
    pub fn new(layers: Vec<QuantizedLayer>) -> Self {
        Self { layers }
    }

    /// Structural well-formedness of the whole model: at least one layer, every
    /// layer valid, and consecutive layers dimensionally chained (layer N's
    /// `out_dim` is layer N+1's `in_dim`).
    ///
    /// Registration (`OpCode::SysCallRegisterZkMlModel`) runs this BEFORE the
    /// model joins the committed registry, so re-execution later only ever sees
    /// a model whose `forward` cannot assert - a proof carrying attacker-chosen
    /// input widths therefore reverts instead of panicking a verifier.
    pub fn validate(&self) -> bool {
        if self.layers.is_empty() {
            return false;
        }
        let mut expect_in: Option<usize> = None;
        for l in &self.layers {
            if !l.validate() {
                return false;
            }
            if let Some(want) = expect_in {
                if l.in_dim != want {
                    return false;
                }
            }
            expect_in = Some(l.out_dim);
        }
        true
    }

    /// Number of i64 parameters (weights + biases). This is the unit both gas
    /// arms price: registration writes them into committed state and
    /// verification re-executes them.
    pub fn param_count(&self) -> usize {
        self.layers
            .iter()
            .map(|l| l.weights.len() + l.biases.len())
            .sum()
    }

    pub fn compute_model_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update((self.layers.len() as u64).to_be_bytes());
        for l in &self.layers {
            hasher.update(l.compute_hash());
        }
        hasher.finalize().into()
    }

    /// CONSTRAINED-FORMAT gate for the whole model (enforced at VK
    /// REGISTRATION, never at model registration: legacy unbounded-`i64`
    /// models register and re-execute exactly as before).
    ///
    /// Demands: structurally valid, every layer `validate_constrained_bounds`
    /// (i8 weights, capped dims), the layer count capped, the public I/O
    /// shape capped, and - the load-bearing one - every layer's worst-case
    /// accumulator over ALL admissible inputs (u16 external, propagated
    /// 32-bit hidden activations) inside `[-2^31, 2^31 - 1]`, so no input
    /// can overflow the 32-bit accumulator range. Quantization is
    /// fixed-point identity (`scale = 1`, `zero_point = 0`) by construction:
    /// the re-execution computes the integer forward pass exactly, and there are no
    /// scale fields to disagree about.
    ///
    /// Single implementation of the gate: [`crate::zkml_attestation::ModelView`]'s
    /// `check_compatible` (the setup/prove helpers call the same function,
    /// so the registry path and the direct-helper path cannot drift).
    pub fn is_attestation_compatible(&self) -> bool {
        if !self.validate() {
            return false;
        }
        if self.layers.len() > crate::zkml_attestation::ATTEST_MAX_LAYERS {
            return false;
        }
        if !self.layers.iter().all(|l| l.validate_constrained_bounds()) {
            return false;
        }
        self.attestation_view().check_compatible().is_ok()
    }

    /// Plain-data model view (weights/biases/dims) for the attestation helpers.
    /// Structural validity is NOT re-checked here - `check_compatible`
    /// (called by `is_attestation_compatible` and by every setup/prove helper)
    /// verifies lengths and chaining.
    pub fn attestation_view(&self) -> crate::zkml_attestation::ModelView {
        crate::zkml_attestation::ModelView {
            weights: self.layers.iter().map(|l| l.weights.clone()).collect(),
            biases: self.layers.iter().map(|l| l.biases.clone()).collect(),
            dims: self.layers.iter().map(|l| (l.in_dim, l.out_dim)).collect(),
        }
    }
}

/// Verifiable zkML proof structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkMlProof {
    pub model_hash: [u8; 32],
    pub public_inputs: Vec<u64>,
    pub public_outputs: Vec<u64>,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LayerInferenceTrace {
    pub pre_activations: Vec<i64>,
    pub post_activations: Vec<i64>,
    pub layer_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InferenceTraceProof {
    pub traces: Vec<LayerInferenceTrace>,
    pub fiat_shamir_challenge: [u8; 32],
}

impl ZkMlProof {
    pub fn new(
        model_hash: [u8; 32],
        inputs: Vec<u64>,
        outputs: Vec<u64>,
        proof_bytes: Vec<u8>,
    ) -> Self {
        Self {
            model_hash,
            public_inputs: inputs,
            public_outputs: outputs,
            proof_bytes,
        }
    }

    /// Bytes this proof occupies on the wire (the transcript bincode writes
    /// for the variant carrying it).
    ///
    /// Used by `opcode_gas` for `OpCode::SysCallVerifyZkMlReexec`: the proof is
    /// hashed into the tx signing message like every other payload byte, so the
    /// sender pays for carrying it, and a proof flood cannot be cheaper than
    /// the block space it burns.
    pub fn wire_len(&self) -> usize {
        self.proof_bytes
            .len()
            .saturating_add(self.public_inputs.len().saturating_mul(8))
            .saturating_add(self.public_outputs.len().saturating_mul(8))
            .saturating_add(32) // model_hash
    }

    /// TEST FIXTURE: fabricate a proof that PASSES [`ZkMlProof::verify_inference`]
    /// while claiming outputs the model never produces.
    ///
    /// This exists so tests can pin the audit's core claim end to end: the
    /// structural check is fooled by a ReLU-consistent, Fiat-Shamir-bound trace
    /// with no relation to the real forward pass (the trace's activations are
    /// invented, the `layer_hash` is copied), while
    /// [`ZkMlProof::verify_inference_against`] - and therefore the live
    /// `OpCode::SysCallVerifyZkMlReexec` handler - rejects it.
    ///
    /// NOT a prover. `claimed_outputs` must fit in a non-negative `i64`
    /// (ReLU-consistent by construction: `post = pre >= 0`).
    #[doc(hidden)]
    pub fn forge_structural_proof(
        model: &QuantizedLinearModel,
        inputs: &[u64],
        claimed_outputs: &[u64],
    ) -> Self {
        let model_hash = model.compute_model_hash();
        let post: Vec<i64> = claimed_outputs.iter().map(|&x| x as i64).collect();
        let traces = vec![LayerInferenceTrace {
            pre_activations: post.clone(),
            post_activations: post,
            layer_hash: model
                .layers
                .first()
                .map(|l| l.compute_hash())
                .unwrap_or([0u8; 32]),
        }];

        let mut hasher = Sha256::new();
        hasher.update(model_hash);
        for x in inputs {
            hasher.update(x.to_be_bytes());
        }
        for y in claimed_outputs {
            hasher.update(y.to_be_bytes());
        }
        for t in &traces {
            hasher.update(t.layer_hash);
            for v in &t.post_activations {
                hasher.update(v.to_be_bytes());
            }
        }
        let challenge: [u8; 32] = hasher.finalize().into();

        Self {
            model_hash,
            public_inputs: inputs.to_vec(),
            public_outputs: claimed_outputs.to_vec(),
            proof_bytes: bincode::serialize(&InferenceTraceProof {
                traces,
                fiat_shamir_challenge: challenge,
            })
            .unwrap_or_default(),
        }
    }

    /// Generate an authentic verifiable zkML proof for a model and inputs
    pub fn prove_reexec(model: &QuantizedLinearModel, inputs: &[i64]) -> (Vec<i64>, Self) {
        let model_hash = model.compute_model_hash();
        let mut current_input = inputs.to_vec();
        let mut traces = Vec::new();

        for layer in &model.layers {
            let (z, a) = layer.forward(&current_input);
            traces.push(LayerInferenceTrace {
                pre_activations: z,
                post_activations: a.clone(),
                layer_hash: layer.compute_hash(),
            });
            current_input = a;
        }

        let final_outputs = current_input;

        // Compute Fiat-Shamir non-interactive challenge
        let mut hasher = Sha256::new();
        hasher.update(model_hash);
        for x in inputs {
            hasher.update(x.to_be_bytes());
        }
        for y in &final_outputs {
            hasher.update(y.to_be_bytes());
        }
        for t in &traces {
            hasher.update(t.layer_hash);
            for v in &t.post_activations {
                hasher.update(v.to_be_bytes());
            }
        }
        let fiat_shamir_challenge: [u8; 32] = hasher.finalize().into();

        let trace_proof = InferenceTraceProof {
            traces,
            fiat_shamir_challenge,
        };

        let proof_bytes = bincode::serialize(&trace_proof).unwrap_or_default();
        let u_inputs: Vec<u64> = inputs.iter().map(|&x| x as u64).collect();
        let u_outputs: Vec<u64> = final_outputs.iter().map(|&y| y as u64).collect();

        let proof = Self {
            model_hash,
            public_inputs: u_inputs,
            public_outputs: u_outputs,
            proof_bytes,
        };

        (final_outputs, proof)
    }

    /// Verification against a KNOWN model: re-executes the model on the
    /// public inputs and checks the outputs AND every traced activation match.
    ///
    /// **This is re-execution, not a zk-SNARK.** There is no circuit, no
    /// trusted setup and no succinctness: the verifier runs the whole forward
    /// pass (cost linear in the model's parameters) and compares. The claim
    /// this supports is exactly "these outputs come from THIS model on THESE
    /// inputs", which is what makes it sound for a value-bearing decision -
    /// and no more than that.
    ///
    /// A4: `verify_inference` alone is only a structural consistency check — it
    /// never verifies the matrix multiplication, so a prover can fabricate
    /// ReLU-consistent traces for arbitrary outputs. This method re-runs the
    /// (deterministic, integer) model, which makes the claim sound as long as the
    /// verifier knows the model by hash (e.g. from an on-chain model registry -
    /// `OpCode::SysCallVerifyZkMlReexec` fetches it from
    /// [`ZkMlModelRegistry`] and hash-matches it).
    ///
    /// Never panics on attacker-chosen input: an input width the model does not
    /// accept returns `false` (so the live opcode reverts) instead of tripping
    /// `QuantizedLayer::forward`'s assertion.
    pub fn verify_inference_against(&self, model: &QuantizedLinearModel) -> bool {
        if !model.validate() {
            return false;
        }
        if model.compute_model_hash() != self.model_hash {
            return false;
        }
        // Recompute the deterministic forward pass.
        let mut current: Vec<i64> = self.public_inputs.iter().map(|&x| x as i64).collect();
        let mut expected: Vec<(Vec<i64>, Vec<i64>)> = Vec::new();
        for layer in &model.layers {
            if current.len() != layer.in_dim {
                return false;
            }
            let (z, a) = layer.forward(&current);
            expected.push((z, a.clone()));
            current = a;
        }
        // Public outputs must equal the recomputed final activations.
        if current.len() != self.public_outputs.len() {
            return false;
        }
        for (a, &o) in current.iter().zip(self.public_outputs.iter()) {
            if (*a as u64) != o {
                return false;
            }
        }
        // Structural validity (Fiat-Shamir binding + ReLU constraints).
        if !self.verify_inference() {
            return false;
        }
        // And the supplied trace must equal the recomputed one, layer by layer.
        let Ok(trace_proof) = bincode::deserialize::<InferenceTraceProof>(&self.proof_bytes) else {
            return false;
        };
        if trace_proof.traces.len() != expected.len() {
            return false;
        }
        for (t, (z, a)) in trace_proof.traces.iter().zip(expected.iter()) {
            if &t.pre_activations != z || &t.post_activations != a {
                return false;
            }
        }
        true
    }

    /// Verify inference computational correctness at consensus level without heavy TEE/SGX.
    ///
    /// WARNING: this is a STRUCTURAL check only (Fiat-Shamir binding + ReLU
    /// constraints + output shape). It does NOT verify the linear layers, so it is
    /// NOT sound on its own - a fabricated, ReLU-consistent trace with invented
    /// activations passes it (regression
    /// `forged_proof_passes_structural_but_fails_sound_check`, and the live-path
    /// twin `forged_proof_is_rejected_on_the_live_block_path`). Use
    /// [`ZkMlProof::verify_inference_against`] with a known model for
    /// value-bearing decisions: that is what the block path's
    /// `OpCode::SysCallVerifyZkMlReexec` calls. The legacy
    /// `OpCode::SysCallVerifyZkMl` calls THIS method and therefore carries no
    /// soundness at all - it is unreachable on the block path (`VmContext.zkml_proof`
    /// is never supplied) and stays fail-closed.
    pub fn verify_inference(&self) -> bool {
        if self.proof_bytes.is_empty() {
            return false;
        }

        let trace_proof: InferenceTraceProof = match bincode::deserialize(&self.proof_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };

        if trace_proof.traces.is_empty() {
            return false;
        }

        // Verify Fiat-Shamir commitment consistency
        let mut hasher = Sha256::new();
        hasher.update(self.model_hash);
        for x in &self.public_inputs {
            hasher.update(x.to_be_bytes());
        }
        for y in &self.public_outputs {
            hasher.update(y.to_be_bytes());
        }
        for t in &trace_proof.traces {
            hasher.update(t.layer_hash);
            for v in &t.post_activations {
                hasher.update(v.to_be_bytes());
            }
        }
        let expected_challenge: [u8; 32] = hasher.finalize().into();
        if expected_challenge != trace_proof.fiat_shamir_challenge {
            return false;
        }

        // Verify layer activation constraints: a = max(0, z)
        for t in &trace_proof.traces {
            if t.pre_activations.len() != t.post_activations.len() {
                return false;
            }
            for (z, a) in t.pre_activations.iter().zip(t.post_activations.iter()) {
                let expected_a = if *z > 0 { *z } else { 0 };
                if *a != expected_a {
                    return false;
                }
            }
        }

        // Verify final layer outputs match public_outputs
        let last_trace = &trace_proof.traces[trace_proof.traces.len() - 1];
        if last_trace.post_activations.len() != self.public_outputs.len() {
            return false;
        }
        for (a, &pub_out) in last_trace
            .post_activations
            .iter()
            .zip(self.public_outputs.iter())
        {
            if (*a as u64) != pub_out {
                return false;
            }
        }

        true
    }
}

/// One entry of the committed §2 model registry.
///
/// `model_hash` is what the proof is matched against (and what
/// `verify_inference_against` re-derives from `model` before it re-executes),
/// `model` is the weights the re-execution actually runs. Both are committed
/// (see `commitment::zkml_models_digest`): two nodes that disagreed about a
/// model's weights would disagree about what a proof verifies against, under
/// one state root.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ZkMlModelRecord {
    pub model_hash: [u8; 32],
    pub model: QuantizedLinearModel,
    /// Verification SPEC for the attestation path, set once by
    /// `register_spec`, never swapped.
    ///
    /// ⚠️ NOT a Groth16 verifying key (audit W8.3 / production blocker A5):
    /// it is the model's constrained format + its I/O shape + a free-form
    /// setup LABEL. There is no proving key and no ceremony behind it.
    ///
    /// `None` is the common case (re-execution-only models, and every model
    /// registered before the spec wave): the commitment spec domain writes
    /// zero bytes while NO record carries a spec, so the genesis root and
    /// `COMMITMENT_VERSION` are untouched. In-memory only like the rest of
    /// the registry (no persistence tree this wave), so extending the record
    /// changes no persisted encoding.
    pub spec: Option<crate::zkml_attestation::ModelSpec>,
}

/// The committed §2 model registry: `model_id -> (code/weights hash, weights)`.
///
/// This is what turns "re-execute a model" into a CONSENSUS statement: the
/// model is not something each verifier fetches out-of-band, it is state every
/// node derives from the same blocks and folds into the same state root
/// (conditionally - an empty registry contributes zero digest bytes, see
/// `commitment::zkml_models_digest`).
///
/// Rules (enforced by [`ZkMlModelRegistry::register`], which is what
/// `OpCode::SysCallRegisterZkMlModel` calls):
///  * APPEND-ONLY, first writer wins: an id that is already registered cannot
///    be re-registered or overwritten, so nobody can swap the weights a proof
///    is checked against after the fact. (The flip side - someone squatting an
///    id first with their own model - is a naming/griefing question for
///    governance, not a soundness hole: a proof for the squatter's model still
///    only ever proves the squatter's model.)
///  * MALFORMED models are rejected before they can be re-executed
///    (`QuantizedLinearModel::validate`), and
///  * a registration is bounded by [`MAX_ZKML_MODEL_PARAMS`].
///
/// `BTreeMap` because the commitment digest iterates it and PROTOCOL.md I2
/// requires identical bytes for identical state on every node.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ZkMlModelRegistry {
    pub models: BTreeMap<[u8; 32], ZkMlModelRecord>,
}

impl ZkMlModelRegistry {
    pub fn len(&self) -> usize {
        self.models.len()
    }

    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }

    pub fn get(&self, model_id: &[u8; 32]) -> Option<&ZkMlModelRecord> {
        self.models.get(model_id)
    }

    /// Register `model` under `model_id`. Returns the model's hash (what a
    /// proof must carry), or an error describing why the registration is
    /// refused - the opcode turns any error into a transaction revert.
    ///
    /// WHO CAN REGISTER (audit Z1 model-registry access): anyone. The live
    /// caller (`OpCode::SysCallRegisterZkMlModel`) imposes no allowlist — any
    /// transaction payer who pays the gas registers. This is safe, not an
    /// oversight, because the registry is APPEND-ONLY first-wins (an id that
    /// is already registered cannot be re-registered or overwritten, so
    /// nobody can swap the weights a proof is checked against after the
    /// fact), every model is validated (`validate`) and bounded
    /// ([`MAX_ZKML_MODEL_PARAMS`]), and proofs match by MODEL HASH
    /// (`verify_inference_against` re-derives the hash from the registered
    /// weights) — trusting an id only ever proves that id's model.
    /// Residual: id-squatting is naming grief only (a squatter's model still
    /// proves just the squatter's model). GATING PRECONDITION (deferred): a
    /// governed id namespace (e.g. a `GovAction` reserving model-id prefixes)
    /// plus a handler-side allowlist check — i.e. an opcode/handler change,
    /// not a tightening of this function.
    pub fn register(
        &mut self,
        model_id: [u8; 32],
        model: QuantizedLinearModel,
    ) -> Result<[u8; 32], String> {
        if self.models.contains_key(&model_id) {
            return Err("model id already registered (registry is append-only)".to_string());
        }
        if !model.validate() {
            return Err(
                "malformed model: layers must be non-empty, dimensionally chained and \
                 carry weights/biases matching their declared shapes"
                    .to_string(),
            );
        }
        let params = model.param_count();
        if params > MAX_ZKML_MODEL_PARAMS {
            return Err(format!(
                "model too large: {params} parameters > {MAX_ZKML_MODEL_PARAMS} cap"
            ));
        }
        let model_hash = model.compute_model_hash();
        self.models.insert(
            model_id,
            ZkMlModelRecord {
                model_hash,
                model,
                spec: None,
            },
        );
        Ok(model_hash)
    }

    /// Attach a VERIFICATION SPEC to an ALREADY-REGISTERED model, enabling the
    /// attestation verify path (`OpCode::SysCallVerifyZkMlAttestation`).
    ///
    /// ⚠️ HONESTY (audit W8.3 / production blocker A5): what is attached is
    /// NOT a Groth16 verifying key and NOT a proving key. It is the model's
    /// constrained format + I/O shape + a free-form setup LABEL. The
    /// attestation path RE-EXECUTES the model; it is not succinct and not
    /// zero-knowledge.
    ///
    /// Rules (mirroring `register`'s append-only discipline):
    ///  * the model id must exist (a spec cannot precede its model);
    ///  * ONE spec per model, first writer wins: an existing `spec` is never
    ///    overwritten, so the weights a proof is checked against cannot be
    ///    rebound after the fact;
    ///  * the model must satisfy the constrained format
    ///    (`QuantizedLinearModel::is_attestation_compatible` - i8 weights, u16
    ///    inputs, bounded accumulator, capped dims): legacy unbounded-`i64`
    ///    models keep their re-execution path but are REFUSED here;
    ///  * the spec itself must parse, match its `spec_hash`, pin this model's
    ///    exact I/O shape, and carry a non-empty setup attestation
    ///    (`crate::zkml_attestation::check_model_spec`).
    ///
    /// Any refusal is returned as an error the opcode turns into a revert.
    pub fn register_spec(
        &mut self,
        model_id: [u8; 32],
        spec: crate::zkml_attestation::ModelSpec,
    ) -> Result<(), String> {
        let rec = self
            .models
            .get_mut(&model_id)
            .ok_or_else(|| "unknown zkML model: register it first".to_string())?;
        if rec.spec.is_some() {
            return Err("spec already registered (registry is append-only)".to_string());
        }
        if !rec.model.is_attestation_compatible() {
            return Err("model is not in the constrained format (i8 weights, \
                  u16 inputs, bounded accumulator, capped dims); the re-execution \
                  path still accepts it, the attestation path does not"
                .to_string());
        }
        let view = rec.model.attestation_view();
        crate::zkml_attestation::check_model_spec(&view, &spec)?;
        rec.spec = Some(spec);
        Ok(())
    }

    /// True when at least one record carries a verification spec. The
    /// commitment spec domain keys off this (empty => zero bytes, genesis root
    /// pinned).
    pub fn has_any_spec(&self) -> bool {
        self.models.values().any(|r| r.spec.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The capability statement is the artifact an integrator reads, so it
    /// must say the CONSERVATIVE truth: no zero-knowledge, no succinctness,
    /// no hiding — and it must name every zkML opcode it describes.
    ///
    /// This is the regression pin for production blocker A5 ("zk-SNARK ❌ не
    /// настоящий ZK"): if someone re-introduces a "zk" claim in the statement
    /// (or in the opcode list), this test fails.
    #[test]
    fn capability_statement_is_honest_and_machine_readable() {
        let caps = zkml_capabilities();
        assert!(
            !caps.zero_knowledge,
            "the chain must not claim zero-knowledge"
        );
        assert!(!caps.succinct, "the chain must not claim succinctness");
        assert!(!caps.hiding, "the chain must not claim hiding");
        assert!(
            !caps.trusted_setup,
            "there is no ceremony, so there is no setup"
        );
        assert!(caps.sound, "the re-execution check IS sound — say so");
        assert!(
            caps.protocol.contains("re-execution"),
            "the protocol name must say re-execution: {}",
            caps.protocol
        );
        assert!(
            caps.summary.to_lowercase().contains("not"),
            "the summary must carry the negation: {}",
            caps.summary
        );
        // Every zkML verify opcode is described, and each description is
        // honest about the three properties that matter.
        let opcodes: Vec<&str> = caps.opcodes.iter().map(|o| o.opcode.as_str()).collect();
        assert!(
            opcodes.contains(&"SysCallVerifyZkMlReexec"),
            "the re-execution opcode must be described: {opcodes:?}"
        );
        assert!(
            opcodes.contains(&"SysCallVerifyZkMlAttestation"),
            "the attestation opcode must be described: {opcodes:?}"
        );
        for o in &caps.opcodes {
            assert!(o.sound, "{} must be reported as sound", o.opcode);
            assert!(
                !o.zero_knowledge,
                "{} must not claim zero-knowledge",
                o.opcode
            );
            assert!(!o.succinct, "{} must not claim succinctness", o.opcode);
            assert!(!o.hiding, "{} must not claim hiding", o.opcode);
            assert!(
                !o.honest_name.is_empty() && !o.trusted_setup.is_empty(),
                "{} must say what it does and what it trusts",
                o.opcode
            );
        }
        // It serializes: the RPC serves exactly this.
        let json = serde_json::to_string(&caps).expect("capabilities serialize");
        assert!(json.contains("\"zero_knowledge\":false"));
        assert!(json.contains("SysCallVerifyZkMlAttestation"));
    }

    fn model() -> QuantizedLinearModel {
        QuantizedLinearModel::new(vec![QuantizedLayer::new(
            2,
            2,
            vec![2, -1, 1, 3],
            vec![1, -2],
        )])
    }

    #[test]
    fn honest_proof_verifies_against_known_model() {
        let m = model();
        let (out, proof) = ZkMlProof::prove_reexec(&m, &[3, 4]);
        assert_eq!(out, vec![11, 7]);
        assert!(proof.verify_inference());
        assert!(proof.verify_inference_against(&m));
    }

    #[test]
    fn forged_proof_passes_structural_but_fails_sound_check() {
        // Fabricate a proof with a lying output but a structurally-consistent,
        // Fiat-Shamir-bound trace. Without re-execution this is accepted (A4).
        let m = model();
        let model_hash = m.compute_model_hash();
        let inputs = vec![3u64, 4u64];
        let lie = vec![999u64, 999u64];
        let traces = vec![LayerInferenceTrace {
            pre_activations: vec![999, 999],
            post_activations: vec![999, 999],
            layer_hash: m.layers[0].compute_hash(),
        }];
        let mut hasher = Sha256::new();
        hasher.update(model_hash);
        for x in &inputs {
            hasher.update(x.to_be_bytes());
        }
        for y in &lie {
            hasher.update(y.to_be_bytes());
        }
        for t in &traces {
            hasher.update(t.layer_hash);
            for v in &t.post_activations {
                hasher.update(v.to_be_bytes());
            }
        }
        let challenge: [u8; 32] = hasher.finalize().into();
        let proof_bytes = bincode::serialize(&InferenceTraceProof {
            traces,
            fiat_shamir_challenge: challenge,
        })
        .unwrap();
        let forged = ZkMlProof {
            model_hash,
            public_inputs: inputs,
            public_outputs: lie,
            proof_bytes,
        };

        assert!(
            forged.verify_inference(),
            "structural check is fooled by the forgery"
        );
        assert!(
            !forged.verify_inference_against(&m),
            "sound check against the known model must reject the forgery"
        );
    }
}
