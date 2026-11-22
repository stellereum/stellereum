//! Pure Rust Address Utilities for Stellereum Smart Contracts and Tooling
//!
//! Features:
//! - Standard Burn / Black Hole address constant `[0u8; 32]` (all zeros).
//! - Deterministic domain hash calculation for `.stl` domain names.
//! - Canonical protocol and system burn domain definitions.

/// Black Hole / System Burn Address (no private key exists).
/// Any assets or domain ownership transferred here are permanently destroyed.
pub const BURN_ADDRESS: [u8; 32] = [0u8; 32];

pub const BASE58_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Hash a domain name into a 28-bit domain ID using FNV-1a (deterministic, fits in packed i64).
pub const fn hash_domain(name: &str) -> i64 {
    let bytes = name.as_bytes();
    let mut hash: u64 = 0xcbf29ce484222325;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        i += 1;
    }
    // Mask to positive 28-bit integer (1..268,435,455) so packed i64 never overflows
    let val = (hash & 0x0FFFFFFF) as i64;
    if val == 0 {
        1
    } else {
        val
    }
}

/// Calculate optical hue shift (0..359) for an STL domain name or domain ID.
pub const fn calculate_domain_hue(domain_id: i64) -> i64 {
    (domain_id.abs() * 137) % 360
}

// -----------------------------------------------------------------------------
// Canonical Reserved Domain Definitions (Compile-Time Hashes)
// -----------------------------------------------------------------------------

// System Black Hole / Burn Domains (permanently locked to [0u8; 32])
pub const DOMAIN_BURN: i64 = hash_domain("burn.stl");
pub const DOMAIN_TRASH: i64 = hash_domain("trash.stl");

// Protocol Core & Ecosystem Domains (reserved for Treasury / Protocol Services)
pub const DOMAIN_VAULT: i64 = hash_domain("vault.stl");
pub const DOMAIN_STAKE: i64 = hash_domain("stake.stl");
pub const DOMAIN_BRIDGE: i64 = hash_domain("bridge.stl");
pub const DOMAIN_ORACLE: i64 = hash_domain("oracle.stl");
pub const DOMAIN_DNS: i64 = hash_domain("dns.stl");
pub const DOMAIN_STL: i64 = hash_domain("stl.stl");
pub const DOMAIN_DEX: i64 = hash_domain("dex.stl");
pub const DOMAIN_DAO: i64 = hash_domain("dao.stl");
pub const DOMAIN_MAIL: i64 = hash_domain("mail.stl");
pub const DOMAIN_INFMAIL: i64 = hash_domain("infmail.stl");
pub const DOMAIN_STELLEREUM: i64 = hash_domain("stellereum.stl");
pub const DOMAIN_STELL: i64 = hash_domain("stell.stl");

pub const SYSTEM_BURN_DOMAINS: [i64; 2] = [DOMAIN_BURN, DOMAIN_TRASH];

pub const PROTOCOL_RESERVED_DOMAINS: [i64; 12] = [
    DOMAIN_VAULT,
    DOMAIN_STAKE,
    DOMAIN_BRIDGE,
    DOMAIN_ORACLE,
    DOMAIN_DNS,
    DOMAIN_STL,
    DOMAIN_DEX,
    DOMAIN_DAO,
    DOMAIN_MAIL,
    DOMAIN_INFMAIL,
    DOMAIN_STELLEREUM,
    DOMAIN_STELL,
];

/// Returns true if domain is a permanent Black Hole / Burn destination
pub const fn is_system_burn(domain_id: i64) -> bool {
    domain_id == DOMAIN_BURN || domain_id == DOMAIN_TRASH
}

/// Returns true if domain is reserved for protocol services
pub const fn is_protocol_reserved(domain_id: i64) -> bool {
    let mut i = 0;
    while i < PROTOCOL_RESERVED_DOMAINS.len() {
        if PROTOCOL_RESERVED_DOMAINS[i] == domain_id {
            return true;
        }
        i += 1;
    }
    false
}

/// Returns true if domain cannot be auctioned by public users
pub const fn is_any_reserved(domain_id: i64) -> bool {
    is_system_burn(domain_id) || is_protocol_reserved(domain_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_burn_address_is_zero() {
        assert_eq!(BURN_ADDRESS, [0u8; 32]);
    }

    #[test]
    fn test_domain_hashing() {
        let id1 = hash_domain("star.stl");
        let id2 = hash_domain("wallet.stl");
        let id3 = hash_domain("burn.stl");
        assert_ne!(id1, id2);
        assert_ne!(id1, id3);
        assert!(id1 > 0);
        assert!(id2 > 0);
        assert!(id3 > 0);
    }

    #[test]
    fn test_reserved_domains_compile_time() {
        assert!(is_system_burn(DOMAIN_BURN));
        assert!(is_system_burn(DOMAIN_TRASH));
        assert!(!is_system_burn(DOMAIN_VAULT));

        assert!(is_protocol_reserved(DOMAIN_VAULT));
        assert!(is_protocol_reserved(DOMAIN_STAKE));
        assert!(is_protocol_reserved(DOMAIN_BRIDGE));
        assert!(is_protocol_reserved(DOMAIN_ORACLE));
        assert!(is_protocol_reserved(DOMAIN_DNS));
        assert!(is_protocol_reserved(DOMAIN_STL));
        assert!(is_protocol_reserved(DOMAIN_DEX));
        assert!(is_protocol_reserved(DOMAIN_DAO));
        assert!(is_protocol_reserved(DOMAIN_MAIL));
        assert!(is_protocol_reserved(DOMAIN_INFMAIL));
        assert!(is_protocol_reserved(DOMAIN_STELLEREUM));
        assert!(is_protocol_reserved(DOMAIN_STELL));

        assert!(is_any_reserved(DOMAIN_BURN));
        assert!(is_any_reserved(DOMAIN_STELL));

        // blackhole.stl is NOT reserved (user can auction it)
        let blackhole_id = hash_domain("blackhole.stl");
        assert!(!is_any_reserved(blackhole_id));
    }

    #[test]
    fn test_hue_calculation() {
        assert_eq!(calculate_domain_hue(1), 137);
        assert_eq!(calculate_domain_hue(2), 274);
        assert_eq!(calculate_domain_hue(3), 51);
    }
}
