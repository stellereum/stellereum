//! Post-Quantum Cryptography & Address Utilities for Stellereum L1
//! Implements Stellereum PQ-BFT v4 specification:
//! - PqScheme: Ed25519 (1), Falcon-512 (2), ML-DSA-44 (3), Hybrid (4)
//! - derive_pq_address(scheme, pubkey, salt)
//! - Sample keypair generation with automatic memory zeroization
//! - Visual checksum formatting compatible with standard 32-byte wallet addresses

use colored::Colorize;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain separation prefix for Stellereum PQ addresses (V4)
pub const PQ_ADDRESS_DOMAIN: &[u8] = b"STL_ADDR_V4";

/// Default 16-byte zero salt for standard address derivation
pub const DEFAULT_SALT: [u8; 16] = [0u8; 16];

/// Canonical public key byte sizes
pub const ED25519_PUBKEY_LEN: usize = 32;
pub const FALCON512_PUBKEY_LEN: usize = 897;
pub const MLDSA44_PUBKEY_LEN: usize = 1312;
pub const HYBRID_PUBKEY_LEN: usize = ED25519_PUBKEY_LEN + FALCON512_PUBKEY_LEN; // 929 bytes

/// Canonical signature byte sizes
pub const ED25519_SIG_LEN: usize = 64;
pub const FALCON512_SIG_LEN: usize = 666;
pub const MLDSA44_SIG_LEN: usize = 2420;
pub const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + FALCON512_SIG_LEN; // 730 bytes

#[allow(unused_imports)]
pub use stellereum::post_quantum::{
    verify_pq_signature, PqSignatureEnvelope, StatefulImplicitKeyRegistry, PQ_ENVELOPE_MAGIC,
};

/// Cryptographic signature scheme identifiers defined in Stellereum PQ-BFT v4
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum)]
#[repr(u8)]
pub enum PqScheme {
    /// Classic fast Ed25519 (32-byte public key)
    #[value(name = "ed25519", alias = "1")]
    Ed25519 = 1,
    /// Post-quantum lattice-based Falcon-512 (897-byte public key, NIST Level 1)
    #[value(name = "falcon512", alias = "falcon-512", alias = "2")]
    Falcon512 = 2,
    /// Post-quantum lattice-based ML-DSA-44 (1312-byte public key, FIPS 204 / Dilithium2)
    #[value(name = "mldsa44", alias = "ml-dsa-44", alias = "mldsa-44", alias = "3")]
    MlDsa44 = 3,
    /// Hybrid dual-signature combining Ed25519 and Falcon-512 (929-byte public key)
    #[value(name = "hybrid", alias = "4")]
    Hybrid = 4,
}

/// Post-quantum schemes supported for sample keypair generation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum)]
pub enum PqGenScheme {
    /// Post-quantum lattice-based Falcon-512
    #[value(name = "falcon512", alias = "falcon-512")]
    Falcon512,
    /// Post-quantum lattice-based ML-DSA-44
    #[value(name = "mldsa44", alias = "ml-dsa-44", alias = "mldsa-44")]
    MlDsa44,
    /// Hybrid dual-signature (Ed25519 + Falcon-512)
    #[value(name = "hybrid")]
    Hybrid,
}

impl From<PqGenScheme> for PqScheme {
    fn from(s: PqGenScheme) -> Self {
        match s {
            PqGenScheme::Falcon512 => PqScheme::Falcon512,
            PqGenScheme::MlDsa44 => PqScheme::MlDsa44,
            PqGenScheme::Hybrid => PqScheme::Hybrid,
        }
    }
}

/// Post-quantum schemes supported for transfer transactions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum)]
pub enum PqTransferScheme {
    /// Post-quantum lattice-based Falcon-512
    #[value(name = "falcon512", alias = "falcon-512", alias = "2")]
    Falcon512,
    /// Hybrid dual-signature (Ed25519 + Falcon-512)
    #[value(name = "hybrid", alias = "4")]
    Hybrid,
}

impl From<PqTransferScheme> for PqScheme {
    fn from(s: PqTransferScheme) -> Self {
        match s {
            PqTransferScheme::Falcon512 => PqScheme::Falcon512,
            PqTransferScheme::Hybrid => PqScheme::Hybrid,
        }
    }
}

/// Schemes supported for wallet creation and payments
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum, Default,
)]
pub enum WalletScheme {
    /// Post-quantum lattice-based Falcon-512 (default)
    #[value(name = "falcon512", alias = "falcon-512", alias = "2")]
    #[default]
    Falcon512,
    /// Hybrid dual-signature (Ed25519 + Falcon-512)
    #[value(name = "hybrid", alias = "4")]
    Hybrid,
    /// Classical fast Ed25519
    #[value(name = "ed25519", alias = "1")]
    Ed25519,
}

impl WalletScheme {
    pub const fn id(&self) -> u8 {
        match self {
            Self::Ed25519 => 1,
            Self::Falcon512 => 2,
            Self::Hybrid => 4,
        }
    }

    pub const fn name(&self) -> &'static str {
        match self {
            Self::Falcon512 => "Falcon-512",
            Self::Hybrid => "Hybrid (Ed25519 + Falcon-512)",
            Self::Ed25519 => "Ed25519",
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Falcon512 => "falcon512",
            Self::Hybrid => "hybrid",
            Self::Ed25519 => "ed25519",
        }
    }

    pub const fn is_post_quantum(&self) -> bool {
        match self {
            Self::Falcon512 | Self::Hybrid => true,
            Self::Ed25519 => false,
        }
    }
}

impl std::fmt::Display for WalletScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for WalletScheme {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "falcon512" | "falcon" | "2" => Ok(Self::Falcon512),
            "hybrid" | "4" => Ok(Self::Hybrid),
            "ed25519" | "1" => Ok(Self::Ed25519),
            other => Err(format!(
                "Unknown scheme: '{other}'. Available schemes: falcon512, hybrid, ed25519"
            )),
        }
    }
}

impl From<WalletScheme> for PqScheme {
    fn from(s: WalletScheme) -> Self {
        match s {
            WalletScheme::Falcon512 => PqScheme::Falcon512,
            WalletScheme::Hybrid => PqScheme::Hybrid,
            WalletScheme::Ed25519 => PqScheme::Ed25519,
        }
    }
}

impl From<WalletScheme> for stellereum::post_quantum::PqScheme {
    fn from(s: WalletScheme) -> Self {
        match s {
            WalletScheme::Falcon512 => stellereum::post_quantum::PqScheme::Falcon512,
            WalletScheme::Hybrid => stellereum::post_quantum::PqScheme::Hybrid,
            WalletScheme::Ed25519 => stellereum::post_quantum::PqScheme::Ed25519,
        }
    }
}

impl From<PqScheme> for stellereum::post_quantum::PqScheme {
    fn from(s: PqScheme) -> Self {
        match s {
            PqScheme::Ed25519 => stellereum::post_quantum::PqScheme::Ed25519,
            PqScheme::Falcon512 => stellereum::post_quantum::PqScheme::Falcon512,
            PqScheme::MlDsa44 => stellereum::post_quantum::PqScheme::MlDsa44,
            PqScheme::Hybrid => stellereum::post_quantum::PqScheme::Hybrid,
        }
    }
}

impl From<stellereum::post_quantum::PqScheme> for PqScheme {
    fn from(s: stellereum::post_quantum::PqScheme) -> Self {
        match s {
            stellereum::post_quantum::PqScheme::Ed25519 => PqScheme::Ed25519,
            stellereum::post_quantum::PqScheme::Falcon512 => PqScheme::Falcon512,
            stellereum::post_quantum::PqScheme::MlDsa44 => PqScheme::MlDsa44,
            stellereum::post_quantum::PqScheme::Hybrid => PqScheme::Hybrid,
        }
    }
}

impl PartialEq<PqScheme> for stellereum::post_quantum::PqScheme {
    fn eq(&self, other: &PqScheme) -> bool {
        self.id() == other.id()
    }
}

impl PartialEq<stellereum::post_quantum::PqScheme> for PqScheme {
    fn eq(&self, other: &stellereum::post_quantum::PqScheme) -> bool {
        self.id() == other.id()
    }
}

impl PqScheme {
    /// Numeric identifier for the scheme (0x01 .. 0x04)
    pub const fn id(&self) -> u8 {
        *self as u8
    }

    /// Construct scheme from byte identifier
    pub fn from_id(id: u8) -> Result<Self, String> {
        match id {
            1 => Ok(Self::Ed25519),
            2 => Ok(Self::Falcon512),
            // Audit HIGH-2: ML-DSA-44 is fail-closed DISABLED node-side
            // (node `from_id(3)` errs) — mirror the refusal here so the
            // wallet can never construct disabled-scheme keys.
            3 => Err("ML-DSA-44 is disabled (fail-closed): use falcon512 or hybrid".to_string()),
            4 => Ok(Self::Hybrid),
            other => Err(format!("Unknown scheme ID: {other}")),
        }
    }

    /// Human-readable scheme name
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::Falcon512 => "Falcon-512",
            Self::MlDsa44 => "ML-DSA-44",
            Self::Hybrid => "Hybrid (Ed25519 + Falcon-512)",
        }
    }

    /// Expected canonical public key length in bytes
    pub const fn pubkey_size(&self) -> usize {
        match self {
            Self::Ed25519 => ED25519_PUBKEY_LEN,
            Self::Falcon512 => FALCON512_PUBKEY_LEN,
            Self::MlDsa44 => MLDSA44_PUBKEY_LEN,
            Self::Hybrid => HYBRID_PUBKEY_LEN,
        }
    }

    /// Whether this scheme provides quantum resistance
    pub const fn is_post_quantum(&self) -> bool {
        match self {
            Self::Ed25519 => false,
            Self::Falcon512 | Self::MlDsa44 | Self::Hybrid => true,
        }
    }
}

impl std::fmt::Display for PqScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for PqScheme {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "ed25519" | "1" => Ok(Self::Ed25519),
            "falcon512" | "falcon" | "2" => Ok(Self::Falcon512),
            // Audit HIGH-2: disabled like node side (also blocks CLI pq-generate).
            "mldsa44" | "mldsa" | "dilithium" | "dilithium2" | "3" => {
                Err("ML-DSA-44 is disabled (fail-closed): use falcon512 or hybrid".to_string())
            }
            "hybrid" | "4" => Ok(Self::Hybrid),
            other => Err(format!(
                "Unknown scheme: '{other}'. Available schemes: ed25519, falcon512, hybrid"
            )),
        }
    }
}

/// Derives a 32-byte account address according to Stellereum PQ-BFT v4:
/// address = BLAKE3("STL_ADDR_V4" || scheme_id || public_key_bytes || salt)
pub fn derive_pq_address(scheme: PqScheme, pubkey: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PQ_ADDRESS_DOMAIN);
    hasher.update(&[scheme.id()]);
    hasher.update(pubkey);
    hasher.update(salt);
    *hasher.finalize().as_bytes()
}

/// Visual checksum formatter for standard hex addresses
/// Highlights prefix (8 chars cyan bold) and suffix (8 chars green bold)
pub fn format_address_with_visual_checksum(address_hex: &str) -> String {
    let clean = address_hex.strip_prefix("0x").unwrap_or(address_hex);
    if clean.len() == 64 {
        if let Ok(decoded) = hex::decode(clean) {
            if decoded.len() == 32 {
                let mut b = [0u8; 32];
                b.copy_from_slice(&decoded);
                let stl57 = stellereum::address::encode_stl57_address(&b);
                if stl57.len() > 15 {
                    let prefix = &stl57[..5];
                    let mid = &stl57[5..stl57.len() - 10];
                    let suffix = &stl57[stl57.len() - 10..];
                    return format!(
                        "{}{}{}\n  └─ Raw Hex: {}",
                        prefix.yellow().bold(),
                        mid.cyan().bold(),
                        suffix.green().bold(),
                        format!("0x{clean}").dimmed()
                    );
                } else {
                    return format!(
                        "{}\n  └─ Raw Hex: {}",
                        stl57.yellow().bold(),
                        format!("0x{clean}").dimmed()
                    );
                }
            }
        }
    }

    if address_hex.len() < 16 {
        return address_hex.to_string();
    }
    let prefix = &address_hex[..8];
    let mid = &address_hex[8..address_hex.len() - 8];
    let suffix = &address_hex[address_hex.len() - 8..];
    format!(
        "{}{}{}",
        prefix.cyan().bold(),
        mid.white(),
        suffix.green().bold()
    )
}

/// Formats 32-byte address with visual checksum
pub fn format_pq_address(address: &[u8; 32]) -> String {
    format_address_with_visual_checksum(&hex::encode(address))
}

/// Formats 32-byte address as plain lowercase hex string
pub fn format_pq_address_hex(address: &[u8; 32]) -> String {
    hex::encode(address)
}

/// Secure container for private key bytes that is automatically zeroized upon drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PqSecretKey {
    bytes: Vec<u8>,
}

/// Post-quantum keypair representation containing public key and securely scrubbed secret key
pub struct PqKeyPair {
    pub scheme: PqScheme,
    pub public_key: Vec<u8>,
    _secret_key: PqSecretKey,
}

impl std::fmt::Debug for PqKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqKeyPair")
            .field("scheme", &self.scheme)
            .field("public_key_len", &self.public_key.len())
            .field("secret_key", &"[REDACTED_SECURE]")
            .finish()
    }
}

impl PqKeyPair {
    pub fn scheme(&self) -> PqScheme {
        self.scheme
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }

    pub fn derive_address(&self, salt: &[u8; 16]) -> [u8; 32] {
        derive_pq_address(self.scheme, &self.public_key, salt)
    }

    /// Deterministically derive post-quantum keypair from a 32-byte seed
    pub fn from_seed(scheme: PqScheme, seed: &[u8; 32]) -> Self {
        match scheme {
            PqScheme::Ed25519 => {
                let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
                let pubkey = signing_key.verifying_key().to_bytes().to_vec();
                PqKeyPair {
                    scheme,
                    public_key: pubkey,
                    _secret_key: PqSecretKey {
                        bytes: signing_key.to_bytes().to_vec(),
                    },
                }
            }
            PqScheme::Falcon512 => {
                let mut hasher = blake3::Hasher::new_derive_key("STELL_PQ_FALCON512_SEED_V4");
                hasher.update(seed);
                let falcon_sec = *hasher.finalize().as_bytes();

                let falcon_kp =
                    stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&falcon_sec);

                PqKeyPair {
                    scheme,
                    public_key: falcon_kp.public_key.clone(),
                    _secret_key: PqSecretKey {
                        bytes: falcon_sec.to_vec(),
                    },
                }
            }
            PqScheme::MlDsa44 => {
                let mut hasher = blake3::Hasher::new_derive_key("STELL_PQ_MLDSA44_SEED_V4");
                hasher.update(seed);
                let mldsa_sec = *hasher.finalize().as_bytes();

                let mut pk_hasher = blake3::Hasher::new_derive_key("STELL_PQ_MLDSA44_PUBKEY_V4");
                pk_hasher.update(&mldsa_sec);
                let mut pubkey = vec![0u8; MLDSA44_PUBKEY_LEN];
                let mut reader = pk_hasher.finalize_xof();
                reader.fill(&mut pubkey);
                pubkey[0] = 0x01;

                PqKeyPair {
                    scheme,
                    public_key: pubkey,
                    _secret_key: PqSecretKey {
                        bytes: mldsa_sec.to_vec(),
                    },
                }
            }
            PqScheme::Hybrid => {
                let mut ed_hasher = blake3::Hasher::new_derive_key("STELL_PQ_HYBRID_ED25519_V4");
                ed_hasher.update(seed);
                let ed_seed = *ed_hasher.finalize().as_bytes();
                let ed_signing_key = ed25519_dalek::SigningKey::from_bytes(&ed_seed);
                let ed_pubkey = ed_signing_key.verifying_key().to_bytes();

                let mut f_hasher = blake3::Hasher::new_derive_key("STELL_PQ_HYBRID_FALCON512_V4");
                f_hasher.update(seed);
                let falcon_sec = *f_hasher.finalize().as_bytes();

                let falcon_kp =
                    stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&falcon_sec);

                let mut pubkey = Vec::with_capacity(HYBRID_PUBKEY_LEN);
                pubkey.extend_from_slice(&ed_pubkey);
                pubkey.extend_from_slice(&falcon_kp.public_key);

                let mut secret_bytes = Vec::with_capacity(64);
                secret_bytes.extend_from_slice(&ed_signing_key.to_bytes());
                secret_bytes.extend_from_slice(&falcon_sec);

                PqKeyPair {
                    scheme,
                    public_key: pubkey,
                    _secret_key: PqSecretKey {
                        bytes: secret_bytes,
                    },
                }
            }
        }
    }

    /// Sign message with secret key according to scheme
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self.scheme {
            PqScheme::Falcon512 => {
                sign_falcon512(&self._secret_key.bytes, &self.public_key, message)
            }
            PqScheme::Hybrid => sign_hybrid(&self._secret_key.bytes, &self.public_key, message),
            PqScheme::Ed25519 => {
                use ed25519_dalek::Signer;
                let sk = ed25519_dalek::SigningKey::from_bytes(
                    self._secret_key
                        .bytes
                        .as_slice()
                        .try_into()
                        .expect("32 bytes"),
                );
                sk.sign(message).to_bytes().to_vec()
            }
            // Audit HIGH-2: ML-DSA-44 is disabled node-side (verify always
            // false) — the wallet must not mint signatures that can never
            // verify (funds-lock footgun). Fail closed with an empty sig.
            PqScheme::MlDsa44 => Vec::new(),
        }
    }
}

impl crate::client::PqSigner for PqKeyPair {
    fn scheme(&self) -> stellereum::post_quantum::PqScheme {
        self.scheme.into()
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn derive_address(&self, salt: &[u8; 16]) -> [u8; 32] {
        self.derive_address(salt)
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.sign(message)
    }
}

/// Signs a message with Falcon-512 conforming to Stellereum PQ-BFT v4 verification rules.
/// Fails closed (returns empty signature) if `secret_key` is shorter than 32 bytes.
pub fn sign_falcon512(secret_key: &[u8], _pubkey: &[u8], message: &[u8]) -> Vec<u8> {
    if secret_key.len() < 32 {
        return Vec::new();
    }
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&secret_key[..32]);
    let falcon_kp = stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&seed);
    falcon_kp.sign_with_seed(message, &seed)
}

/// Signs a message with Hybrid scheme (Ed25519 + Falcon-512).
pub fn sign_hybrid(secret_bytes: &[u8], pubkey: &[u8], message: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let ed_secret: [u8; 32] = secret_bytes[..32]
        .try_into()
        .expect("Hybrid secret must start with 32-byte Ed25519 seed");
    let falcon_secret = &secret_bytes[32..];
    let falcon_pk = &pubkey[ED25519_PUBKEY_LEN..];

    let sk = ed25519_dalek::SigningKey::from_bytes(&ed_secret);
    let ed_sig = sk.sign(message).to_bytes();
    let falcon_sig = sign_falcon512(falcon_secret, falcon_pk, message);

    let mut hybrid_sig = Vec::with_capacity(HYBRID_SIG_LEN);
    hybrid_sig.extend_from_slice(&ed_sig);
    hybrid_sig.extend_from_slice(&falcon_sig);
    hybrid_sig
}

/// Build a WALLET SIGNATURE STANDARD signing key (`stellereum::wallet_signing`,
/// docs/WALLET_SIGNING.md in the node repo) from this wallet's 32-byte seed.
///
/// The derivation mirrors [`PqKeyPair::from_seed`] EXACTLY (same BLAKE3
/// domain KDFs), so the standard signature comes from the wallet's OWN
/// identity: `key.address()` equals the wallet's address for every scheme
/// (`ed25519` direct, `falcon512`/`hybrid` via the zero-salt PQ derivation).
///
/// `mldsa44` is refused fail-closed (forgeable verifier — same rule as the
/// node side; a `WalletScheme` never names it, this arm is for the raw
/// [`PqScheme`] only).
pub fn wallet_standard_signing_key(
    seed: &[u8; 32],
    scheme: WalletScheme,
) -> Result<stellereum::wallet_signing::WalletSigningKey, String> {
    use stellereum::wallet_signing::WalletSigningKey;
    match scheme {
        WalletScheme::Ed25519 => Ok(WalletSigningKey::ed25519(*seed)),
        WalletScheme::Falcon512 => {
            let mut hasher = blake3::Hasher::new_derive_key("STELL_PQ_FALCON512_SEED_V4");
            hasher.update(seed);
            let falcon_sec = *hasher.finalize().as_bytes();
            Ok(WalletSigningKey::falcon_from_seed(&falcon_sec))
        }
        WalletScheme::Hybrid => {
            let mut ed_hasher = blake3::Hasher::new_derive_key("STELL_PQ_HYBRID_ED25519_V4");
            ed_hasher.update(seed);
            let ed_seed = *ed_hasher.finalize().as_bytes();
            let mut f_hasher = blake3::Hasher::new_derive_key("STELL_PQ_HYBRID_FALCON512_V4");
            f_hasher.update(seed);
            let falcon_sec = *f_hasher.finalize().as_bytes();
            Ok(WalletSigningKey::hybrid(ed_seed, &falcon_sec))
        }
    }
}

/// Generates a sample keypair for the specified scheme.
/// Secret key material is held in memory-scrubbed storage and dropped safely.
pub fn generate_sample_keypair(scheme: PqScheme) -> PqKeyPair {
    let mut rng = OsRng;
    match scheme {
        PqScheme::Ed25519 => {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let pubkey = signing_key.verifying_key().to_bytes().to_vec();
            seed.zeroize();
            PqKeyPair {
                scheme,
                public_key: pubkey,
                _secret_key: PqSecretKey {
                    bytes: signing_key.to_bytes().to_vec(),
                },
            }
        }
        PqScheme::Falcon512 => {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let falcon_kp =
                stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&seed);
            PqKeyPair {
                scheme,
                public_key: falcon_kp.public_key.clone(),
                _secret_key: PqSecretKey {
                    bytes: seed.to_vec(),
                },
            }
        }
        PqScheme::MlDsa44 => {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"STELL_PQ_MLDSA44_SAMPLE_PUBKEY");
            hasher.update(&seed);
            let mut pubkey = vec![0u8; MLDSA44_PUBKEY_LEN];
            let mut reader = hasher.finalize_xof();
            reader.fill(&mut pubkey);
            PqKeyPair {
                scheme,
                public_key: pubkey,
                _secret_key: PqSecretKey {
                    bytes: seed.to_vec(),
                },
            }
        }
        PqScheme::Hybrid => {
            let mut ed_seed = [0u8; 32];
            rng.fill_bytes(&mut ed_seed);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&ed_seed);
            let ed_pubkey = signing_key.verifying_key().to_bytes();
            ed_seed.zeroize();

            let mut pq_seed = [0u8; 32];
            rng.fill_bytes(&mut pq_seed);
            let falcon_kp =
                stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&pq_seed);

            let mut pubkey = Vec::with_capacity(HYBRID_PUBKEY_LEN);
            pubkey.extend_from_slice(&ed_pubkey);
            pubkey.extend_from_slice(&falcon_kp.public_key);

            let mut combined_secret = Vec::with_capacity(64);
            combined_secret.extend_from_slice(&signing_key.to_bytes());
            combined_secret.extend_from_slice(&pq_seed);

            PqKeyPair {
                scheme,
                public_key: pubkey,
                _secret_key: PqSecretKey {
                    bytes: combined_secret,
                },
            }
        }
    }
}

#[cfg(test)]
mod wallet_standard_tests {
    //! The `stell sign` command must produce the WALLET SIGNATURE STANDARD
    //! envelope (docs/WALLET_SIGNING.md in the node repo), and `stell verify`
    //! must check it. These tests pin the bridge between this wallet's own key
    //! derivation (`PqKeyPair::from_seed`) and the standard:
    //! `wallet_standard_signing_key` built from a wallet seed must report the
    //! SAME address as the wallet itself, for every scheme — otherwise `sign`
    //! would mint signatures the wallet's own address cannot own.

    use super::*;

    #[test]
    fn standard_signing_key_matches_wallet_address_for_all_schemes() {
        let seed = [0x5Au8; 32];
        for scheme in [
            WalletScheme::Ed25519,
            WalletScheme::Falcon512,
            WalletScheme::Hybrid,
        ] {
            // The wallet's own identity (what `new`/`restore` store).
            let (wallet_addr, expected_pubkey) = match scheme {
                WalletScheme::Ed25519 => {
                    let account = stellereum::wallet::WalletAccount::from_seed(&seed);
                    (account.address, account.address.to_vec())
                }
                WalletScheme::Falcon512 => {
                    let kp = PqKeyPair::from_seed(PqScheme::Falcon512, &seed);
                    (kp.derive_address(&DEFAULT_SALT), kp.public_key().to_vec())
                }
                WalletScheme::Hybrid => {
                    let kp = PqKeyPair::from_seed(PqScheme::Hybrid, &seed);
                    (kp.derive_address(&DEFAULT_SALT), kp.public_key().to_vec())
                }
            };
            // The standard key the `sign` command builds from the same seed.
            let key = wallet_standard_signing_key(&seed, scheme)
                .expect("standard key builds for every wallet scheme");
            assert_eq!(key.address(), wallet_addr, "scheme {scheme}");
            assert_eq!(key.pubkey_bytes(), expected_pubkey, "scheme {scheme}");
            // ... and it round-trips through the standard envelope.
            let sig = key.sign_message(5757, b"stell conformance").expect("signs");
            assert!(stellereum::wallet_signing::verify_message(
                &wallet_addr,
                5757,
                b"stell conformance",
                &sig
            ));
            assert!(!stellereum::wallet_signing::verify_message(
                &wallet_addr,
                5758,
                b"stell conformance",
                &sig
            ));
        }
    }

    #[test]
    fn standard_envelope_decodes_and_names_the_scheme() {
        let seed = [0x5Au8; 32];
        let key = wallet_standard_signing_key(&seed, WalletScheme::Falcon512)
            .expect("falcon standard key builds");
        let sig = key.sign_message(5757, b"envelope shape").expect("signs");
        let hex_sig = sig.to_hex();
        let back =
            stellereum::wallet_signing::WalletSignature::from_hex(&hex_sig).expect("decodes");
        assert_eq!(back.scheme, stellereum::post_quantum::PqScheme::Falcon512);
        assert_eq!(back.encode().len(), 1569);
    }
}
