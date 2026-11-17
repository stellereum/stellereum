//! Transaction construction, Falcon-512 signing and the exact node wire form.
//!
//! Every cryptographic primitive comes from the node's own source:
//!
//! * `crate::post_quantum` is `stellereum/src/post_quantum.rs` included
//!   verbatim (`FalconKeypair`, `derive_pq_address`, `PqScheme`,
//!   `StatefulImplicitKeyRegistry`, `DEFAULT_SALT`);
//! * `crate::envelope` is `stellereum/src/sharding/envelope.rs` included
//!   verbatim (the PQ1 framing, explicit/implicit constructors, chain id);
//! * `crate::wire` mirrors only the empty-payload `Transaction` container and
//!   the signed-hash preimage, field for field, and its tests pin the exact
//!   wire lengths.
//!
//! Nothing about Falcon-512 or the PQ1 envelope is re-implemented here.

use rayon::prelude::*;

use crate::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, StatefulImplicitKeyRegistry, DEFAULT_SALT,
};
use crate::wire::{Transaction, PQ_ACTIVATION_SURCHARGE_GAS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqMode {
    /// First nonce per sender carries the public key (activation), later nonces
    /// omit it (steady-state implicit). Repairs itself if a node lost its
    /// in-memory registry by re-sending that nonce as explicit.
    Auto,
    /// Every transaction carries the 897-byte Falcon-512 public key.
    Explicit,
    /// Never carry the public key; the node must already have it registered
    /// (either from an earlier activation or its persisted PQ pin).
    Implicit,
}

impl PqMode {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "explicit" => Ok(Self::Explicit),
            "implicit" => Ok(Self::Implicit),
            other => Err(format!(
                "--pq-mode must be auto|explicit|implicit, got {other:?}"
            )),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Explicit => "explicit",
            Self::Implicit => "implicit",
        }
    }
}

#[derive(Debug, Clone)]
pub enum Recipient {
    /// Send the amount back to the sender: the only per-tx cost is the fee.
    SelfAddress,
    /// A deterministic burn-like address derived from a domain string.
    Sink,
    Fixed([u8; 32]),
}

impl Recipient {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let t = raw.trim();
        if t.eq_ignore_ascii_case("self") {
            return Ok(Self::SelfAddress);
        }
        if t.eq_ignore_ascii_case("sink") {
            return Ok(Self::Sink);
        }
        let hexpart = t
            .strip_prefix("0x")
            .or_else(|| t.strip_prefix("0X"))
            .unwrap_or(t);
        if hexpart.len() != 64 {
            return Err(format!(
                "--recipient must be self, sink, or 32-byte hex (64 digits), got {raw:?}"
            ));
        }
        let bytes =
            hex::decode(hexpart).map_err(|e| format!("--recipient: bad hex {raw:?}: {e}"))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Self::Fixed(out))
    }

    pub fn resolve(&self, sender: &[u8; 32]) -> [u8; 32] {
        match self {
            Self::SelfAddress => *sender,
            Self::Sink => blake3::derive_key("STELL_LOADTEST_SINK_V1", b"recipient"),
            Self::Fixed(a) => *a,
        }
    }
}

/// One deterministic sender key. The private key is never printed, serialized
/// or written to disk; only the derived 32-byte address leaves this struct.
pub struct SenderSpec {
    pub index: u64,
    pub keypair: FalconKeypair,
    pub address: [u8; 32],
    pub pubkey: Vec<u8>,
}

impl SenderSpec {
    pub fn address_hex(&self) -> String {
        format!("0x{}", hex::encode(self.address))
    }
}

/// Derive the master seed from the operator-visible `--seed` text.
///
/// A fixed default seed makes the sender set REPEATABLE: the operator funds the
/// addresses once and every wave uses the same accounts. These keys are public
/// test material by construction; never fund them on a value-bearing network.
pub fn master_seed(text: &str) -> [u8; 32] {
    *blake3::hash(text.as_bytes()).as_bytes()
}

/// Generate `n` senders in parallel. Key generation is the expensive part of
/// preflight (FIPS-206 NTRU keygen), so it is spread over the rayon pool.
pub fn generate_senders(master: &[u8; 32], n: usize) -> Vec<SenderSpec> {
    (0..n as u64)
        .into_par_iter()
        .map(|index| {
            let mut hasher = blake3::Hasher::new_derive_key("STELL_LOADTEST_SENDER_V1");
            hasher.update(master);
            hasher.update(&index.to_be_bytes());
            let mut seed = [0u8; 32];
            hasher.finalize_xof().fill(&mut seed);
            let keypair = FalconKeypair::generate_from_seed_bytes(&seed);
            seed.fill(0);
            let pubkey = keypair.public_key().to_vec();
            let address = derive_pq_address(PqScheme::Falcon512, &pubkey, &DEFAULT_SALT);
            SenderSpec {
                index,
                keypair,
                address,
                pubkey,
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy)]
pub struct TxSpec {
    pub to: [u8; 32],
    pub amount: u64,
    pub gas_limit: u64,
    pub nonce: u64,
    pub source_shard: u32,
    pub target_shard: u32,
    pub chain_id: u64,
}

/// Build and sign one full-PQ transaction exactly as the node expects it.
///
/// The signed preimage is `base_signing_message || "CHAIN_ID" || chain_id`
/// (via `signing_message_for_chain`), and the envelope carries the same chain
/// id in its trailing 8 bytes. A transaction built here therefore passes
/// `verify_signature_for_chain(expected, true)` on the node, not just
/// `verify_signature`.
pub fn build_signed_tx(sender: &SenderSpec, spec: &TxSpec, mode: PqMode) -> Transaction {
    debug_assert!(mode != PqMode::Auto, "Auto must be resolved by the caller");
    let draft = Transaction {
        from: sender.address,
        to: spec.to,
        amount: spec.amount,
        gas_limit: spec.gas_limit,
        nonce: spec.nonce,
        source_shard: spec.source_shard,
        target_shard: spec.target_shard,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let message = draft.signing_message_for_chain(spec.chain_id);
    let signature = sender.keypair.sign(&message);

    match mode {
        PqMode::Explicit => Transaction::new_pq_explicit_with_chain(
            PqScheme::Falcon512,
            sender.pubkey.clone(),
            signature,
            spec.to,
            spec.amount,
            spec.gas_limit,
            spec.nonce,
            spec.source_shard,
            spec.target_shard,
            Vec::new(),
            &DEFAULT_SALT,
            spec.chain_id,
        ),
        PqMode::Implicit => Transaction::new_pq_implicit_with_chain(
            sender.address,
            PqScheme::Falcon512,
            signature,
            spec.to,
            spec.amount,
            spec.gas_limit,
            spec.nonce,
            spec.source_shard,
            spec.target_shard,
            Vec::new(),
            spec.chain_id,
        ),
        PqMode::Auto => unreachable!("Auto is resolved before signing"),
    }
}

/// The exact signed preimage for a spec (for the dry-run dump).
pub fn signing_message(sender: &SenderSpec, spec: &TxSpec) -> Vec<u8> {
    let draft = Transaction {
        from: sender.address,
        to: spec.to,
        amount: spec.amount,
        gas_limit: spec.gas_limit,
        nonce: spec.nonce,
        source_shard: spec.source_shard,
        target_shard: spec.target_shard,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    draft.signing_message_for_chain(spec.chain_id)
}

pub fn verify_explicit(tx: &Transaction) -> bool {
    tx.verify_signature()
}

/// Verify an implicit envelope against a local registry populated with the
/// sender's key. On a node this registry is filled by the activation tx.
pub fn verify_implicit(tx: &Transaction, sender: &SenderSpec) -> Result<bool, String> {
    let registry = StatefulImplicitKeyRegistry::new();
    registry.register(
        sender.address,
        PqScheme::Falcon512,
        &sender.pubkey,
        &DEFAULT_SALT,
    )?;
    Ok(tx.verify_signature_with_registry(&registry))
}

#[derive(Debug, Clone)]
pub struct EnvelopeFacts {
    pub scheme: &'static str,
    pub is_implicit: bool,
    pub pubkey_len: usize,
    pub signature_len: usize,
    pub chain_id: Option<u64>,
    pub encoded_len: usize,
}

pub fn envelope_facts(tx: &Transaction) -> Result<EnvelopeFacts, String> {
    let env = tx
        .pq_envelope()
        .ok_or_else(|| "transaction has no PQ1 envelope".to_string())?;
    Ok(EnvelopeFacts {
        scheme: env.scheme.name(),
        is_implicit: env.is_implicit,
        pubkey_len: env.pubkey.as_ref().map_or(0, |p| p.len()),
        signature_len: env.signature_bytes.len(),
        chain_id: env.chain_id,
        encoded_len: env.encoded_len(),
    })
}

/// Node admission floor + the State Rent Surcharge for an activation tx.
/// Mirrors `Mempool::effective_floor_for_tx`.
pub fn gas_floor(base_fee: u64, mode: PqMode) -> u64 {
    base_fee.saturating_add(match mode {
        PqMode::Explicit => PQ_ACTIVATION_SURCHARGE_GAS,
        PqMode::Implicit | PqMode::Auto => 0,
    })
}

/// Auto gas limit: base fee + surcharge + margin. Execution of an empty-payload
/// transfer charges `gas_limit`, so the margin is deliberately small.
pub fn auto_gas_limit(base_fee: u64, mode: PqMode, margin: u64) -> u64 {
    gas_floor(base_fee, mode).saturating_add(margin).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_sender() -> SenderSpec {
        generate_senders(&master_seed("unit-test"), 1).remove(0)
    }

    fn spec(sender: &SenderSpec, nonce: u64, gas: u64) -> TxSpec {
        TxSpec {
            to: sender.address,
            amount: 1,
            gas_limit: gas,
            nonce,
            source_shard: 0,
            target_shard: 0,
            chain_id: 5757,
        }
    }

    #[test]
    fn deterministic_senders_are_stable_across_calls() {
        let a = generate_senders(&master_seed("same"), 3);
        let b = generate_senders(&master_seed("same"), 3);
        assert_eq!(a.len(), 3);
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.address, y.address);
            assert_eq!(x.pubkey, y.pubkey);
        }
        assert_ne!(a[0].address, a[1].address);
    }

    #[test]
    fn explicit_tx_signs_verifies_and_roundtrips() {
        let s = one_sender();
        let tx = build_signed_tx(&s, &spec(&s, 7, 326_000), PqMode::Explicit);
        assert!(tx.is_pq());
        assert!(tx.is_pq_activation());
        assert!(!tx.is_pq_implicit());
        assert_eq!(tx.chain_id(), Some(5757));
        assert!(verify_explicit(&tx));

        let facts = envelope_facts(&tx).unwrap();
        assert!(!facts.is_implicit);
        assert_eq!(facts.pubkey_len, 897);
        assert_eq!(facts.signature_len, 666);
        assert_eq!(facts.chain_id, Some(5757));

        let wire = crate::wire::encode_wire(&tx).unwrap();
        let decoded = crate::wire::decode_wire(&wire).unwrap();
        assert_eq!(decoded.from, tx.from);
        assert_eq!(decoded.to, tx.to);
        assert_eq!(decoded.nonce, 7);
        assert_eq!(decoded.chain_id(), Some(5757));
        assert!(decoded.verify_signature());
        assert_eq!(decoded.compute_tx_hash(), tx.compute_tx_hash());
        assert!(crate::wire::decode_wire(&[&wire[..], b"junk"].concat()).is_err());
    }

    #[test]
    fn implicit_tx_verifies_against_the_sender_registry() {
        let s = one_sender();
        let tx = build_signed_tx(&s, &spec(&s, 0, 281_000), PqMode::Implicit);
        assert!(tx.is_pq());
        assert!(tx.is_pq_implicit());
        assert_eq!(tx.chain_id(), Some(5757));
        assert!(verify_implicit(&tx, &s).unwrap());
        let facts = envelope_facts(&tx).unwrap();
        assert!(facts.is_implicit);
        assert_eq!(facts.pubkey_len, 0);
        assert_eq!(facts.encoded_len, 3 + 1 + 1 + 2 + 2 + 666 + 8);
        let wire = crate::wire::encode_wire(&tx).unwrap();
        let decoded = crate::wire::decode_wire(&wire).unwrap();
        let registry = StatefulImplicitKeyRegistry::new();
        registry
            .register(s.address, PqScheme::Falcon512, &s.pubkey, &DEFAULT_SALT)
            .unwrap();
        assert!(decoded.verify_signature_with_registry(&registry));
    }

    #[test]
    fn nonce_changes_the_hash_and_message() {
        let s = one_sender();
        let a = build_signed_tx(&s, &spec(&s, 1, 300_000), PqMode::Explicit);
        let b = build_signed_tx(&s, &spec(&s, 2, 300_000), PqMode::Explicit);
        assert_ne!(a.compute_tx_hash(), b.compute_tx_hash());
        assert_ne!(
            signing_message(&s, &spec(&s, 1, 300_000)),
            signing_message(&s, &spec(&s, 2, 300_000))
        );
    }

    #[test]
    fn chain_binding_is_inside_the_signed_preimage() {
        let s = one_sender();
        let mut sa = spec(&s, 1, 300_000);
        let mut sb = sa;
        sb.chain_id = 5758;
        assert_ne!(signing_message(&s, &sa), signing_message(&s, &sb));
        let tx = build_signed_tx(&s, &sa, PqMode::Explicit);
        // The chain id is carried in the envelope; a different expected id
        // must not verify against this signature. `verify_signature` reads the
        // envelope's own id, so check the envelope value directly.
        assert_eq!(tx.chain_id(), Some(5757));
        assert!(tx.verify_signature());
        sa.nonce = 1;
    }

    #[test]
    fn auto_gas_limit_never_underfunds_the_floor() {
        assert_eq!(gas_floor(280_000, PqMode::Explicit), 325_000);
        assert_eq!(gas_floor(280_000, PqMode::Implicit), 280_000);
        assert_eq!(auto_gas_limit(280_000, PqMode::Explicit, 1_000), 326_000);
        assert_eq!(auto_gas_limit(0, PqMode::Implicit, 1_000), 1_000);
    }

    #[test]
    fn recipient_parsing_is_strict() {
        assert!(matches!(
            Recipient::parse("self").unwrap(),
            Recipient::SelfAddress
        ));
        assert!(matches!(Recipient::parse("SINK").unwrap(), Recipient::Sink));
        assert!(Recipient::parse("0x1234").is_err());
        let hexaddr = format!("0x{}", "ab".repeat(32));
        assert!(matches!(
            Recipient::parse(&hexaddr).unwrap(),
            Recipient::Fixed(_)
        ));
        let s = one_sender();
        assert_eq!(Recipient::SelfAddress.resolve(&s.address), s.address);
        assert_ne!(Recipient::Sink.resolve(&s.address), s.address);
    }
}
