use crate::post_quantum::{PqScheme, StatefulImplicitKeyRegistry, DEFAULT_SALT, PQ_ENVELOPE_MAGIC};
use serde::{Deserialize, Serialize};

static GLOBAL_IMPLICIT_KEY_REGISTRY: std::sync::OnceLock<StatefulImplicitKeyRegistry> =
    std::sync::OnceLock::new();

/// Global thread-safe implicit key registry for post-quantum wire verification.
pub fn global_implicit_key_registry() -> &'static StatefulImplicitKeyRegistry {
    GLOBAL_IMPLICIT_KEY_REGISTRY.get_or_init(StatefulImplicitKeyRegistry::new)
}

/// Signature envelope carrying post-quantum or hybrid signature payload.
///
/// Encoded format:
/// `b"PQ1" (3B) || scheme_id (1B) || is_implicit (1B) || [pubkey_len (2B) || pubkey || salt (16B)]? || sig_len (2B) || sig_bytes`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignatureEnvelope {
    pub scheme: PqScheme,
    pub is_implicit: bool,
    pub pubkey: Option<Vec<u8>>,
    pub signature_bytes: Vec<u8>,
    pub salt: [u8; 16],
    #[serde(default)]
    pub chain_id: Option<u64>,
}

impl PqSignatureEnvelope {
    /// Create envelope with explicit public key attached and default salt.
    pub fn new_explicit(scheme: PqScheme, pubkey: Vec<u8>, signature_bytes: Vec<u8>) -> Self {
        Self {
            scheme,
            is_implicit: false,
            pubkey: Some(pubkey),
            signature_bytes,
            salt: DEFAULT_SALT,
            chain_id: None,
        }
    }

    /// Create envelope with explicit public key and custom salt attached.
    pub fn new_explicit_with_salt(
        scheme: PqScheme,
        pubkey: Vec<u8>,
        signature_bytes: Vec<u8>,
        salt: [u8; 16],
    ) -> Self {
        Self {
            scheme,
            is_implicit: false,
            pubkey: Some(pubkey),
            signature_bytes,
            salt,
            chain_id: None,
        }
    }

    /// Create envelope with explicit public key, custom salt, and chain_id bound.
    pub fn new_explicit_with_chain(
        scheme: PqScheme,
        pubkey: Vec<u8>,
        signature_bytes: Vec<u8>,
        salt: [u8; 16],
        chain_id: u64,
    ) -> Self {
        Self {
            scheme,
            is_implicit: false,
            pubkey: Some(pubkey),
            signature_bytes,
            salt,
            chain_id: Some(chain_id),
        }
    }

    /// Create envelope relying on implicit registered public key.
    pub fn new_implicit(scheme: PqScheme, signature_bytes: Vec<u8>) -> Self {
        Self {
            scheme,
            is_implicit: true,
            pubkey: None,
            signature_bytes,
            salt: DEFAULT_SALT,
            chain_id: None,
        }
    }

    /// Create envelope relying on implicit registered public key with chain_id bound.
    pub fn new_implicit_with_chain(
        scheme: PqScheme,
        signature_bytes: Vec<u8>,
        chain_id: u64,
    ) -> Self {
        Self {
            scheme,
            is_implicit: true,
            pubkey: None,
            signature_bytes,
            salt: DEFAULT_SALT,
            chain_id: Some(chain_id),
        }
    }

    /// Encodes envelope into canonical bytes prefixed by `b"PQ1"`.
    /// Includes `salt` (16 bytes) in explicit envelopes (`is_implicit = false`).
    /// Appends `chain_id` (8 bytes) if bound (Finding F1).
    pub fn encode(&self) -> Vec<u8> {
        let salt_len = if !self.is_implicit { 16 } else { 0 };
        let pk_len = self.pubkey.as_ref().map_or(0, |k| k.len());
        let chain_len = if self.chain_id.is_some() { 8 } else { 0 };
        let mut out = Vec::with_capacity(
            3 + 1 + 1 + 2 + pk_len + salt_len + 2 + self.signature_bytes.len() + chain_len,
        );
        out.extend_from_slice(PQ_ENVELOPE_MAGIC);
        out.push(self.scheme.id());
        out.push(if self.is_implicit { 1 } else { 0 });

        if let Some(pk) = &self.pubkey {
            let pk_len_u16 = pk.len() as u16;
            out.extend_from_slice(&pk_len_u16.to_le_bytes());
            out.extend_from_slice(pk);
        } else {
            out.extend_from_slice(&0u16.to_le_bytes());
        }

        if !self.is_implicit {
            out.extend_from_slice(&self.salt);
        }

        let sig_len = self.signature_bytes.len() as u16;
        out.extend_from_slice(&sig_len.to_le_bytes());
        out.extend_from_slice(&self.signature_bytes);
        if let Some(cid) = self.chain_id {
            out.extend_from_slice(&cid.to_be_bytes());
        }
        out
    }

    /// Canonical wire byte length for this envelope without allocating.
    pub fn encoded_len(&self) -> usize {
        let salt_len = if !self.is_implicit { 16 } else { 0 };
        let pk_len = self.pubkey.as_ref().map_or(0, |k| k.len());
        let chain_len = if self.chain_id.is_some() { 8 } else { 0 };
        3 + 1 + 1 + 2 + pk_len + salt_len + 2 + self.signature_bytes.len() + chain_len
    }

    /// Wire byte length for legacy envelopes without salt.
    pub fn legacy_encode_len(&self) -> usize {
        let chain_len = if self.chain_id.is_some() { 8 } else { 0 };
        3 + 1
            + 1
            + 2
            + self.pubkey.as_ref().map_or(0, |k| k.len())
            + 2
            + self.signature_bytes.len()
            + chain_len
    }

    /// Decodes envelope from byte slice.
    ///
    /// STRICT (audit W6.5 — signature malleability): every length in the
    /// framing is now PINNED to the scheme, so a given (scheme, key,
    /// signature) has exactly ONE valid byte form per framing:
    ///
    /// * the flag byte is `0` (explicit) or `1` (implicit). A flag of `2`
    ///   used to be read as "implicit" (`bytes[4] != 0`), so a byte-flipped
    ///   flag produced a second, differently-framed but equally accepted
    ///   envelope for the same signature.
    /// * an IMPLICIT envelope carries NO public key (`pk_len == 0`). The old
    ///   decoder SKIPPED `pk_len` bytes and returned `pubkey: None` anyway:
    ///   the same logical signature then had an unbounded number of valid
    ///   encodings (insert N junk bytes right after the flag byte), and the
    ///   skipped bytes were never validated. That defeats any byte-based
    ///   dedup / replay filter or transaction id derived from the envelope
    ///   bytes — a re-mint of a valid transaction.
    /// * an EXPLICIT envelope carries EXACTLY `scheme.pubkey_size()` key
    ///   bytes (the old decoder accepted ANY length, including zero, which
    ///   decoded to an explicit envelope with NO key at all).
    /// * the signature is EXACTLY `scheme.signature_size()` bytes (the old
    ///   decoder accepted any length).
    /// * no trailing bytes.
    ///
    /// The historical salt placements are still READ (a transaction already
    /// in flight must decode), but they are mutually exclusive: the salt is
    /// 16 bytes, the key length is pinned to the scheme and the signature
    /// length is pinned to the scheme, so exactly one framing can match a
    /// given byte string.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 7 {
            return Err("Envelope bytes too short".to_string());
        }
        if &bytes[0..3] != PQ_ENVELOPE_MAGIC {
            return Err("Missing PQ1 magic header".to_string());
        }

        let scheme = PqScheme::from_id(bytes[3])?;
        if bytes[4] > 1 {
            return Err("Envelope flag byte must be 0 (explicit) or 1 (implicit)".to_string());
        }
        let is_implicit = bytes[4] == 1;

        let pk_len = u16::from_le_bytes([bytes[5], bytes[6]]) as usize;

        if is_implicit {
            if pk_len != 0 {
                return Err("Implicit envelope must not carry a public key".to_string());
            }
            let mut cursor = 7;
            if bytes.len() < cursor + 2 {
                return Err("Truncated signature length in envelope".to_string());
            }
            let sig_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
            cursor += 2;
            if sig_len != scheme.signature_size() {
                return Err(format!(
                    "Envelope signature length mismatch for {}: expected {}, got {}",
                    scheme.name(),
                    scheme.signature_size(),
                    sig_len
                ));
            }
            if bytes.len() != cursor + sig_len && bytes.len() != cursor + sig_len + 8 {
                return Err("Truncated signature bytes in envelope".to_string());
            }
            let signature_bytes = bytes[cursor..cursor + sig_len].to_vec();
            cursor += sig_len;
            let chain_id = if bytes.len() == cursor + 8 {
                Some(u64::from_be_bytes(
                    bytes[cursor..cursor + 8].try_into().unwrap(),
                ))
            } else {
                None
            };
            return Ok(Self {
                scheme,
                is_implicit: true,
                pubkey: None,
                signature_bytes,
                salt: DEFAULT_SALT,
                chain_id,
            });
        }

        // EXPLICIT. The key length is fixed by the scheme. It is read either
        // at offset 5 (canonical framing: key first) or at offset 21 (legacy
        // framing: salt first); both are pinned to `scheme.pubkey_size()`.
        let expected_pk_len = scheme.pubkey_size();
        let pk_len_at_21 = if bytes.len() >= 23 {
            u16::from_le_bytes([bytes[21], bytes[22]]) as usize
        } else {
            0
        };

        let _sig_len_error = |got: usize| {
            format!(
                "Envelope signature length mismatch for {}: expected {}, got {}",
                scheme.name(),
                scheme.signature_size(),
                got
            )
        };

        // Canonical framing: key, then (optional) salt, then signature.
        if pk_len == expected_pk_len {
            let mut cursor = 7 + pk_len;
            // With salt (what `encode()` produces for an explicit envelope).
            if bytes.len() >= cursor + 16 + 2 {
                let maybe_sig_len =
                    u16::from_le_bytes([bytes[cursor + 16], bytes[cursor + 17]]) as usize;
                if maybe_sig_len == scheme.signature_size()
                    && (cursor + 16 + 2 + maybe_sig_len == bytes.len()
                        || cursor + 16 + 2 + maybe_sig_len + 8 == bytes.len())
                {
                    let mut salt = [0u8; 16];
                    salt.copy_from_slice(&bytes[cursor..cursor + 16]);
                    cursor += 16;
                    cursor += 2;
                    let signature_bytes = bytes[cursor..cursor + maybe_sig_len].to_vec();
                    cursor += maybe_sig_len;
                    let chain_id = if bytes.len() == cursor + 8 {
                        Some(u64::from_be_bytes(
                            bytes[cursor..cursor + 8].try_into().unwrap(),
                        ))
                    } else {
                        None
                    };
                    return Ok(Self {
                        scheme,
                        is_implicit: false,
                        pubkey: Some(bytes[7..7 + pk_len].to_vec()),
                        signature_bytes,
                        salt,
                        chain_id,
                    });
                }
            }
            // Legacy framing: no salt at all.
            if bytes.len() >= cursor + 2 {
                let sig_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
                cursor += 2;
                if sig_len == scheme.signature_size()
                    && (bytes.len() == cursor + sig_len || bytes.len() == cursor + sig_len + 8)
                {
                    let signature_bytes = bytes[cursor..cursor + sig_len].to_vec();
                    cursor += sig_len;
                    let chain_id = if bytes.len() == cursor + 8 {
                        Some(u64::from_be_bytes(
                            bytes[cursor..cursor + 8].try_into().unwrap(),
                        ))
                    } else {
                        None
                    };
                    return Ok(Self {
                        scheme,
                        is_implicit: false,
                        pubkey: Some(bytes[7..7 + pk_len].to_vec()),
                        signature_bytes,
                        salt: DEFAULT_SALT,
                        chain_id,
                    });
                }
            }
            return Err("Truncated envelope bytes".to_string());
        }

        // Legacy framing: salt BEFORE the key.
        if pk_len_at_21 == expected_pk_len {
            let cursor_sig = 23 + pk_len_at_21;
            if bytes.len() >= cursor_sig + 2 {
                let sig_len =
                    u16::from_le_bytes([bytes[cursor_sig], bytes[cursor_sig + 1]]) as usize;
                if sig_len == scheme.signature_size()
                    && (cursor_sig + 2 + sig_len == bytes.len()
                        || cursor_sig + 2 + sig_len + 8 == bytes.len())
                {
                    let mut salt = [0u8; 16];
                    salt.copy_from_slice(&bytes[5..21]);
                    let signature_bytes = bytes[cursor_sig + 2..cursor_sig + 2 + sig_len].to_vec();
                    let rem = cursor_sig + 2 + sig_len;
                    let chain_id = if bytes.len() == rem + 8 {
                        Some(u64::from_be_bytes(bytes[rem..rem + 8].try_into().unwrap()))
                    } else {
                        None
                    };
                    return Ok(Self {
                        scheme,
                        is_implicit: false,
                        pubkey: Some(bytes[23..23 + pk_len_at_21].to_vec()),
                        signature_bytes,
                        salt,
                        chain_id,
                    });
                }
            }
        }

        Err(format!(
            "Explicit envelope public key length mismatch for {}: expected {}, got {}",
            scheme.name(),
            expected_pk_len,
            pk_len
        ))
    }

    /// Decodes a `PQ1` signature envelope strictly in canonical layout (`H` and above).
    ///
    /// Unlike [`Self::decode`] (kept for pre-hardening heights `< H`), this decoder
    /// eliminates `tx_hash` malleability by accepting **only** the canonical wire
    /// encoding produced by [`Self::encode`]:
    ///
    /// - Explicit (`flag == 0`):
    ///   `b"PQ1" || scheme_id (1B) || 0x00 || pk_len (2B LE == scheme.pubkey_size()) || pubkey || salt (16B) || sig_len (2B LE == scheme.signature_size()) || sig_bytes || [chain_id (8B BE)]`
    /// - Implicit (`flag == 1`):
    ///   `b"PQ1" || scheme_id (1B) || 0x01 || pk_len (2B LE == 0) || sig_len (2B LE == scheme.signature_size()) || sig_bytes || [chain_id (8B BE)]`
    ///
    /// Legacy explicit framings (`salt || key` and salt-free `key || sig`), invalid
    /// flag bytes, non-zero `pk_len` on implicit envelopes, mismatched key/signature
    /// lengths, and any trailing bytes are unconditionally rejected.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 7 {
            return Err("Envelope bytes too short".to_string());
        }
        if &bytes[0..3] != PQ_ENVELOPE_MAGIC {
            return Err("Missing PQ1 magic header".to_string());
        }

        let scheme = PqScheme::from_id(bytes[3])?;
        if bytes[4] > 1 {
            return Err("Envelope flag byte must be 0 (explicit) or 1 (implicit)".to_string());
        }
        let is_implicit = bytes[4] == 1;
        let pk_len = u16::from_le_bytes([bytes[5], bytes[6]]) as usize;

        if is_implicit {
            if pk_len != 0 {
                return Err("Implicit envelope must not carry a public key".to_string());
            }
            let mut cursor = 7;
            if bytes.len() < cursor + 2 {
                return Err("Truncated signature length in envelope".to_string());
            }
            let sig_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
            cursor += 2;
            if sig_len != scheme.signature_size() {
                return Err(format!(
                    "Envelope signature length mismatch for {}: expected {}, got {}",
                    scheme.name(),
                    scheme.signature_size(),
                    sig_len
                ));
            }
            if bytes.len() < cursor + sig_len {
                return Err("Truncated signature bytes in envelope".to_string());
            }
            if bytes.len() != cursor + sig_len && bytes.len() != cursor + sig_len + 8 {
                return Err("Canonical envelope has trailing bytes".to_string());
            }
            let signature_bytes = bytes[cursor..cursor + sig_len].to_vec();
            cursor += sig_len;
            let chain_id = if bytes.len() == cursor + 8 {
                Some(u64::from_be_bytes(
                    bytes[cursor..cursor + 8].try_into().unwrap(),
                ))
            } else {
                None
            };
            return Ok(Self {
                scheme,
                is_implicit: true,
                pubkey: None,
                signature_bytes,
                salt: DEFAULT_SALT,
                chain_id,
            });
        }

        let expected_pk_len = scheme.pubkey_size();
        if pk_len != expected_pk_len {
            return Err(format!(
                "Canonical explicit envelope public key length mismatch for {}: expected {}, got {}",
                scheme.name(),
                expected_pk_len,
                pk_len
            ));
        }

        let mut cursor = 7;
        if bytes.len() < cursor + pk_len + 16 + 2 {
            return Err("Truncated canonical explicit envelope bytes".to_string());
        }
        let pubkey = bytes[cursor..cursor + pk_len].to_vec();
        cursor += pk_len;

        let mut salt = [0u8; 16];
        salt.copy_from_slice(&bytes[cursor..cursor + 16]);
        cursor += 16;

        let sig_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
        cursor += 2;
        if sig_len != scheme.signature_size() {
            return Err(format!(
                "Envelope signature length mismatch for {}: expected {}, got {}",
                scheme.name(),
                scheme.signature_size(),
                sig_len
            ));
        }
        if bytes.len() < cursor + sig_len {
            return Err("Truncated signature bytes in canonical envelope".to_string());
        }
        if bytes.len() != cursor + sig_len && bytes.len() != cursor + sig_len + 8 {
            return Err("Canonical envelope has trailing bytes".to_string());
        }

        let signature_bytes = bytes[cursor..cursor + sig_len].to_vec();
        cursor += sig_len;
        let chain_id = if bytes.len() == cursor + 8 {
            Some(u64::from_be_bytes(
                bytes[cursor..cursor + 8].try_into().unwrap(),
            ))
        } else {
            None
        };

        Ok(Self {
            scheme,
            is_implicit: false,
            pubkey: Some(pubkey),
            signature_bytes,
            salt,
            chain_id,
        })
    }

    /// Decodes a `PQ1` envelope with height-gated canonical strictness:
    /// - `canonical == false` (pre-hardening heights `< H`): uses [`Self::decode`].
    /// - `canonical == true` (hardening heights `>= H` and ingress): uses [`Self::decode_canonical`].
    pub fn decode_at_height(bytes: &[u8], canonical: bool) -> Result<Self, String> {
        if canonical {
            Self::decode_canonical(bytes)
        } else {
            Self::decode(bytes)
        }
    }
}

/// Tag that separates a legacy signature from a session-key envelope inside
/// `Transaction::signature`:
///
/// * legacy  : `64B ed25519 sig` (master key == `tx.from`)
/// * envelope: `64B ed25519 sig` (SESSION key) ++ `b"SK1"` ++ `bincode(SessionKeyAuthorization)`
/// * falcon  : `666B Falcon-512 sig` (SESSION key) ++ `b"SF1"` ++ `bincode(SessionKeyAuthorization)`
///   (see [`SESSION_FALCON_SIG_TAG`]; the live framing — `SK1`/Ed grants stay refused)
///
/// This is how delegation rides inside the pre-existing `signature: Vec<u8>`
/// field: `Transaction`/`Block` gain NO new field, so bincode 1.3 keeps
/// decoding every persisted block byte-for-byte, and an old node rejects an
/// envelope at `Signature::from_slice` (64-byte expected, envelope is longer)
/// — fail-closed, exactly as required by the bincode verdict.
pub const SESSION_SIG_TAG: &[u8; 3] = b"SK1";

/// Tag that separates a Falcon-512 session signature from its delegation
/// grant inside `Transaction::signature` (the PQ mirror of [`SESSION_SIG_TAG`]):
///
/// * Falcon envelope: `666B Falcon-512 sig` (SESSION key) ++ `b"SF1"` ++ `bincode(SessionKeyAuthorization)`
///
/// Same shape, same rules, only the signature scheme changes: the session key
/// signs `base_signing_message + delegation commitment` with
/// [`crate::post_quantum::FalconKeypair::sign`], and the grant MUST be Falcon-delegated
/// (`master_scheme`/`session_scheme` post-quantum — Ed grants stay refused by
/// `verify_signature`/`check_session_policy` below). The distinct tag keeps the
/// two framings unambiguous on the wire: a parser never has to guess whether
/// the leading signature is 64 or 666 bytes, and the grant's own
/// `session_scheme` disambiguates any future session-scheme class. Like `SK1`,
/// this rides the pre-existing `signature: Vec<u8>` field, so
/// `Transaction`/`Block` gain NO new field (bincode 1.3 compat).
pub const SESSION_FALCON_SIG_TAG: &[u8; 3] = b"SF1";

/// Tag that separates a legacy signature from a chain-id bound envelope inside
/// `Transaction::signature` (Finding F1):
///
/// `64B ed25519 sig` ++ `b"CH1"` ++ `chain_id (8B, big-endian)`
pub const CHAIN_SIG_TAG: &[u8; 3] = b"CH1";

/// Tag that separates a legacy signature from a Phase-2 EVM (secp256k1)
/// settlement envelope inside `Transaction::signature`:
///
/// `b"EV1"` ++ `canonical EVM raw transaction bytes`
/// (RLP legacy, or `0x02` EIP-1559 envelope).
///
/// `Transaction`/`Block` gain NO new field (bincode 1.3 compat — the §5 M3
/// rule: a new struct field would change every persisted block's bytes and
/// break the pinned golden vectors in `actor_envelope_compat_tests`). The
/// envelope rides the pre-existing `signature: Vec<u8>` field, exactly like
/// the `SK1`/`CH1`/`SC1` envelopes before it, and an old node rejects it at
/// `Signature::from_slice` (64 bytes expected, an EV1 envelope is never 64)
/// — fail-closed, as required.
pub const EVM_SIG_TAG: &[u8; 3] = b"EV1";

/// Chain id every EVM-settled transaction must carry. Strict equality, no
/// negotiation: this is the EIP-155 replay-protection domain AND the
/// consensus chain id in one value.
pub const EVM_CHAIN_ID: u64 = 5757;

// Compile-time drift guards: the consensus envelope, the EVM adapter and the
// session-grant default must agree on one chain id, or EVM settlement and
// grant binding silently diverge.
const _: () = assert!(EVM_CHAIN_ID == crate::evm_adapter::CHAIN_ID);
const _: () = assert!(EVM_CHAIN_ID == crate::zkml::DEFAULT_CHAIN_ID);

/// Maximum raw EVM bytes accepted inside an EV1 envelope. Mirrors the RPC
/// gate `evm_adapter::MAX_EVM_RAW_TX_BYTES` (generous for calldata); the
/// mempool wire estimator accounts the envelope bytes, so packing still
/// respects the block gossip cap.
pub const MAX_EVM_ENVELOPE_BYTES: usize = 128 * 1024;

/// Commitment tag bound into the signed message for chain-id-bound transactions.
pub const CHAIN_ID_COMMITMENT_TAG: &[u8; 8] = b"CHAIN_ID";

/// PAYMASTER (gasless / sponsored transactions) — v1 envelope.
///
/// DESIGN (see `docs/PAYMASTER.md` for the full contract):
///
/// A funded sponsor account declares `sponsor: <addr>` plus a `sponsor_sig`
/// on the transaction. Nodes verify BOTH signatures: the USER's signature
/// authorizes the action (and binds the sponsor grant, so the grant cannot be
/// swapped after signing), and the SPONSOR's signature authorizes the FEE for
/// THIS exact transaction (it commits to the tx core fields plus the caps, so
/// the grant cannot be grafted onto another transaction).
///
/// * the fee (base + gas + failure-fee on revert) debits ONLY the sponsor;
///   the user's balance is untouched (they still pay `amount` + payload value
///   — the sponsor pays FEE, not value);
/// * the USER's nonce advances on success AND on attributable failure
///   (anti-replay: a sponsored failure is not replayable for free);
/// * the sponsor sets a per-tx fee cap (`max_fee_per_tx`), an expiry
///   (`valid_until`) and an allowlist (`allowed_targets`, empty = any);
///   per-epoch/total spend is enforced by the sponsor's own signing policy
///   plus the mempool's joint reservation, NOT by consensus state (v1);
/// * v1 composes ONLY with a plain legacy ed25519 inner signature. A sponsor
///   envelope on a session-keyed, chain-bound, PQ or EVM transaction is
///   refused fail-closed (`SponsorPolicyError::BadGrant` / `SponsorUnsupported`).
///
/// WIRE: the envelope rides the pre-existing `signature: Vec<u8>` field as a
/// TRAILING suffix — `inner_sig_blob ++ bincode(SponsorAuthorization) ++
/// len_be32 ++ b"SP1"` — exactly like the priority-fee envelope before it, so
/// `Transaction`/`Block` gain NO new bincode field and every pre-sponsor
/// persisted block still decodes byte-for-byte (an old node rejects the longer
/// blob at `Signature::from_slice`, fail-closed).
///
/// HASH: `compute_tx_hash` mixes in `SPONSOR_COMMITMENT_TAG` + the auth ONLY
/// when a sponsor envelope is present, so a legacy (no-sponsor) transaction
/// hashes byte-identically to before (pinned by `sponsor_legacy_hash_unchanged`).
pub const SPONSOR_SIG_TAG: &[u8; 3] = b"SP1";

/// Commitment tag bound into the user's signed message AND the tx hash for
/// sponsored transactions.
pub const SPONSOR_COMMITMENT_TAG: &[u8; 8] = b"SPONSOR_";

/// Domain separator for the sponsor's fee authorization signature.
pub const SPONSOR_FEE_DOMAIN: &[u8; 14] = b"SPONSOR_FEE_V1";

/// Hard cap on the decoded sponsor auth bytes (fail-closed parse bound; a
/// bigger blob is refused, never truncated). 64 targets * 32B + fixed fields
/// fit comfortably.
pub const SPONSOR_AUTH_MAX_BYTES: usize = 4096;

/// Hard cap on allowlisted targets per grant (DoS bound on wire + verify).
pub const SPONSOR_MAX_TARGETS: usize = 64;

/// Why a session-keyed transaction fails the delegation policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionPolicyError {
    /// `now > delegation.valid_until`.
    Expired,
    /// The grant's scope mask does not cover this transaction kind, or the
    /// amount exceeds `max_value_per_tx`.
    OutOfScope,
    /// The grant cannot cover this transaction's declared gas: the remaining
    /// budget (`max_gas_spend - gas_spent`) is too small. In phase 1 this is
    /// the stateless form of revocation (a spent-out grant authorizes
    /// nothing); the stateful registry lands in phase 2.
    BudgetExhausted,
    /// The grant itself is unusable: it does not parse, is not minted for this
    /// sender (`master_address != tx.from`) or the master's grant signature is
    /// invalid / tampered with.
    BadGrant,
}

impl std::fmt::Display for SessionPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SessionPolicyError::Expired => "session key delegation has expired",
            SessionPolicyError::OutOfScope => {
                "session key delegation does not cover this transaction (scope/value cap)"
            }
            SessionPolicyError::BudgetExhausted => {
                "session key delegation has no remaining gas budget"
            }
            SessionPolicyError::BadGrant => "invalid session key delegation grant",
        };
        write!(f, "{s}")
    }
}

/// Why a sponsored transaction fails the sponsor policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SponsorPolicyError {
    /// `now > valid_until` at the checking clock.
    Expired,
    /// `tx.to` is not in `allowed_targets` (non-empty allowlist).
    OutOfScope,
    /// The fee execution will actually charge exceeds `max_fee_per_tx`.
    CapExceeded,
    /// The grant is unusable: malformed envelope, self-contradictory, or a
    /// v1-unsupported composition (session/PQ/EVM/chain inner).
    BadGrant,
}

impl std::fmt::Display for SponsorPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SponsorPolicyError::Expired => "sponsor grant has expired",
            SponsorPolicyError::OutOfScope => {
                "sponsor grant does not cover this recipient (allowlist)"
            }
            SponsorPolicyError::CapExceeded => {
                "sponsor grant per-tx fee cap does not cover this transaction's fee"
            }
            SponsorPolicyError::BadGrant => "invalid sponsor grant",
        };
        write!(f, "{s}")
    }
}

/// A sponsor's fee authorization for ONE transaction (the paymaster grant).
///
/// The sponsor signs [`super::Transaction::sponsor_message`] (domain
/// `SPONSOR_FEE_V1`) with the key `sponsor` (ed25519: the address IS the
/// pubkey). The user signs [`super::Transaction::signing_message`], which commits to
/// the FULL auth (including `sponsor_sig`), so neither side can be swapped
/// after signing.
///
/// `#[serde(default)]` on the forward-compat fields (`allowed_targets`):
/// older encodings (or JSON wallets that omit the field) decode as "no
/// allowlist". Absence of the whole envelope is the legacy path — a
/// transaction without it behaves byte-identically to before.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorAuthorization {
    /// The funded account that will be debited the fee. Must differ from
    /// `tx.from` to take effect (`sponsor == from` is the plain path: the fee
    /// is debited from the user and the envelope is fee-routing inert, though
    /// its signature is still verified).
    pub sponsor: [u8; 32],
    /// Hard ceiling on the fee execution may charge for this transaction
    /// (`max(gas_limit, floor) + surcharge`). A transaction whose fee exceeds
    /// this is refused at admission, at proposal and at execution.
    pub max_fee_per_tx: u64,
    /// Unix seconds: the grant authorizes nothing after this (checked against
    /// the admission clock at entry and the block timestamp at propose/apply).
    pub valid_until: u64,
    /// Recipient allowlist (contract/method scoping at the recipient
    /// granularity). Empty = any recipient. Capped at
    /// [`SPONSOR_MAX_TARGETS`] (longer lists fail closed at parse).
    #[serde(default)]
    pub allowed_targets: Vec<[u8; 32]>,
    /// Chain this grant was minted for, committed into both signatures.
    pub chain_id: u64,
    /// Post-quantum (Falcon-512) signature by `sponsor` over [`super::Transaction::sponsor_message`].
    pub sponsor_sig: Vec<u8>,
    /// Sponsor signature scheme (FULL-PQ Paymaster v2 requires `Some(PqScheme::Falcon512)`).
    #[serde(default)]
    pub sponsor_scheme: Option<PqScheme>,
    /// Sponsor public key bytes (897 bytes for Falcon-512), bound to `sponsor` via `derive_pq_address`.
    #[serde(default)]
    pub sponsor_pubkey: Option<Vec<u8>>,
    /// Address derivation salt for `sponsor` (defaults to `DEFAULT_SALT` when omitted).
    #[serde(default)]
    pub sponsor_salt: Option<[u8; 16]>,
}
