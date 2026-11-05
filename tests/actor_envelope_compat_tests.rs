//! §1 ACTOR MAILBOX: envelope compatibility.
//!
//! `OpCode` is bincode-serialized into every transaction's signature preimage
//! and tx hash, so the ONLY safe way to add `SysCallActorSend` is to APPEND
//! it. These tests pin exactly that, three ways:
//!
//!  1. GOLDEN byte-compatibility: the pinned legacy tx / block bytes, hashes
//!     and signing messages still hold (the constants are copied verbatim
//!     from `tests/session_key_tests.rs`, which owns the original capture -
//!     keep them in sync with that file).
//!  2. Every pre-actor opcode keeps its discriminant (0..=33) and the new
//!     variant is 34: an insertion anywhere above would renumber what
//!     follows and invalidate already-signed payloads, and this test names
//!     every index so no insertion can hide.
//!  3. An actor payload's tx hash commits the BODY (so two sends that differ
//!     only in their program are different transactions, and tampering with
//!     the body after signing invalidates the signature), and a modelled
//!     pre-actor node FAILS CLOSED on the appended variant instead of
//!     misreading it.

use ed25519_dalek::SigningKey;
use stellereum::bridge::BridgeIntent;
use stellereum::oracle::PriceFeedUpdate;
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::svm::OpCode;
use stellereum::zkml::SessionKeyAuthorization;

// ============================================================================
// Golden vectors - copied from tests/session_key_tests.rs (which captured
// them from the PRE-session-key, pre-bridge, pre-privacy, pre-actor
// implementation). If any of these moves, legacy blocks no longer rehash to
// their voted hashes.
// ============================================================================

const GOLDEN_PUBKEY: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
const GOLDEN_SIGNING_MSG: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c090909090909090909090909090909090909090909090909090909090909090900000000000003e80000000000000032000000000000000300000001000000015041594c4f4144000000080000000000000000";
const GOLDEN_SIG: &str = "ec92a88d6c30df1625df08d1172e2baecf20964110ce727278849ee953418106c995e7ac322958b6ea6910abe8a7c55f709d5fe935ae09a53fa099b843dee806";
const GOLDEN_TX_BYTES: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c0909090909090909090909090909090909090909090909090909090909090909e8030000000000003200000000000000030000000000000001000000010000004000000000000000ec92a88d6c30df1625df08d1172e2baecf20964110ce727278849ee953418106c995e7ac322958b6ea6910abe8a7c55f709d5fe935ae09a53fa099b843dee8060000000000000000";
const GOLDEN_TX_HASH: &str = "5396c8cb4dbfe9f745a51980a892adf059ad6a10737e4ba1d9d2291b72c8fc85";
/// Chain-id bound since `STELLEREUM_BLOCK_V3` (the preimage carries the
/// chain id), so the block hash is the one under the default chain id 5757.
const GOLDEN_BLOCK_HASH: &str = "68e8c8dc7c0de7915e9d6eb620c1b25f80fb6216fa929a283a856ad2ab37d6d2";
const GOLDEN_BLOCK_BYTES: &str = "000000000100000000000000000000000000000000000000000000000000000000000000000000000000000002020202020202020202020202020202020202020202020202020202020202020100000000000000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c0909090909090909090909090909090909090909090909090909090909090909e8030000000000003200000000000000030000000000000001000000010000004000000000000000ec92a88d6c30df1625df08d1172e2baecf20964110ce727278849ee953418106c995e7ac322958b6ea6910abe8a7c55f709d5fe935ae09a53fa099b843dee8060000000000000000000000000000000000f1536500000000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c0100000000000000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c40000000000000003d12d67dfedc7232b0bef033e5182e4dfde39cb6255567a82e0eee1e76b4bd9c25be7ce4374cca6fd75128f79201c184069972b9b753a89f62b3cd887c4a470300";
/// `sign_with_payload(&sk7, [9u8;32], 5, 700, 8, 1, 2, [Push(42)])`
const GOLDEN_PAYLOAD_TX_HASH: &str =
    "1c0dd4788cffddce81eca80d10a3d054cc88b5f2b965e72609ef555ae3723958";

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("golden hex")
}

fn h32(s: &str) -> [u8; 32] {
    h(s).try_into().expect("golden 32-byte hex")
}

fn golden_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

// ===========================================================================
// 1. Legacy bytes, hashes and signing messages are unchanged
// ===========================================================================

#[test]
fn legacy_tx_and_block_encodings_are_unchanged() {
    let sk = golden_key();

    // The pinned legacy transaction still decodes, re-encodes byte-identically,
    // keeps its signing message, verifies, and hashes to the pinned value.
    let raw = h(GOLDEN_TX_BYTES);
    let tx: Transaction = bincode::deserialize(&raw).expect("legacy tx must still decode");
    assert_eq!(tx.from, h32(GOLDEN_PUBKEY));
    assert_eq!(tx.signature, h(GOLDEN_SIG));
    assert!(tx.payload.is_empty(), "the golden tx carries no payload");
    assert_eq!(
        bincode::serialize(&tx).unwrap(),
        raw,
        "re-encode must be byte-identical"
    );
    assert_eq!(
        hex::encode(tx.signing_message()),
        GOLDEN_SIGNING_MSG,
        "legacy signing message must be byte-identical"
    );
    assert!(tx.verify_signature(), "legacy signature must still verify");
    assert_eq!(
        hex::encode(tx.compute_tx_hash()),
        GOLDEN_TX_HASH,
        "legacy tx hash must be byte-identical"
    );

    // Signing with the old API still produces exactly those bytes.
    let fresh = Transaction::sign(&sk, [9u8; 32], 1000, 50, 3, 1, 1);
    assert_eq!(bincode::serialize(&fresh).unwrap(), raw);

    // A payload-carrying legacy transaction: the payload commitment is
    // untouched, so its hash is too.
    let ptx =
        Transaction::sign_with_payload(&sk, [9u8; 32], 5, 700, 8, 1, 2, vec![OpCode::Push(42)]);
    assert_eq!(hex::encode(ptx.compute_tx_hash()), GOLDEN_PAYLOAD_TX_HASH);

    // The pinned legacy block still decodes and rehashes to its voted hash.
    let raw_block = h(GOLDEN_BLOCK_BYTES);
    // The legacy body shape (the trailing commitment fields absent) is
    // tolerated on the STORE path only: the wire decodes strictly, so a
    // truncated message can never be reinterpreted as a different block.
    let block: Block =
        stellereum::sharding::with_legacy_block_tolerance(|| bincode::deserialize(&raw_block))
            .expect("legacy block must still decode");
    assert_eq!(block.height, 1);
    assert_eq!(block.shard_id, MASTERCHAIN_SHARD);
    assert_eq!(hex::encode(block.compute_hash()), GOLDEN_BLOCK_HASH);
    // The shard-head set (TON `shard_hashes`), the TRANSACTION-ORDER
    // commitment, the EPOCH-KEY commitment, the canonical downtime-evidence
    // slot (`last_qc`, W10.5) and the EPOCH-MMR root (V5 Tier-2) were APPENDED
    // to the block layout: the legacy bytes are the untouched PREFIX of the
    // encoding and the re-encoding adds exactly the empty shard-head set
    // (8 bytes), the all-zero order root (32 bytes), the all-zero epoch-key
    // commitment (32 bytes), the `None` downtime-evidence byte (1 byte) plus
    // the all-zero epoch-MMR root (32 bytes). The HASH — the thing the chain
    // agrees on — is unchanged: a legacy block commits to no order, to no
    // epoch key and to no epoch MMR, so none of them is mixed into its hash.
    let re = bincode::serialize(&block).unwrap();
    assert_eq!(
        &re[..raw_block.len()],
        &raw_block[..],
        "the legacy bytes must be the untouched prefix of the encoding"
    );
    assert_eq!(
        re.len(),
        raw_block.len() + 8 + 32 + 32 + 1 + 32,
        "only the empty shard-head set, the zero order root, the zero epoch-key commitment, the None last_qc byte and the zero epoch-MMR root are appended (W10.5 canonical downtime evidence; V5 Tier-2 MMR)"
    );
    assert_eq!(
        block.order_merkle_root, [0u8; 32],
        "a legacy block commits to no transaction order"
    );
    assert_eq!(
        block.mmr_epoch_root, [0u8; 32],
        "a legacy block commits to no epoch MMR root"
    );
}

// ===========================================================================
// 2. The appended discriminant: every existing opcode keeps its index
// ===========================================================================

/// One instance of EVERY `OpCode` variant, in enum order, with the
/// discriminant bincode assigns it. Variants 0..=33 predate the actor
/// mailbox; 34 is `SysCallActorSend`.
///
/// APPENDING kept every number below 34 fixed; INSERTING anywhere would have
/// shifted everything after the insertion point, re-signed nothing, and
/// silently changed every already-signed payload's bytes. Pinning each index
/// by name means no insertion - here, or anywhere in the first 34 - can hide.
fn every_opcode_and_its_discriminant() -> Vec<(OpCode, u32)> {
    let grant = SessionKeyAuthorization::sign_delegation(
        &SigningKey::from_bytes(&[7u8; 32]),
        [9u8; 32],
        1_500_000_000,
        1_000_000,
        u64::MAX,
        u64::MAX,
        5757,
    );
    vec![
        (OpCode::Nop, 0),
        (OpCode::Push(1), 1),
        (OpCode::Pop, 2),
        (OpCode::Add, 3),
        (OpCode::Sub, 4),
        (OpCode::Mul, 5),
        (OpCode::Div, 6),
        (OpCode::LoadBalance, 7),
        (
            OpCode::Transfer {
                recipient: [0; 32],
                amount: 1,
            },
            8,
        ),
        (
            OpCode::SysCallPlaceOrder {
                pair_id: 1,
                is_buy: true,
                price: 1,
                amount: 1,
            },
            9,
        ),
        (OpCode::SysCallCancelOrder { order_id: 1 }, 10),
        (OpCode::SysCallVerifyZkMl, 11),
        (OpCode::SysCallPatriciaLookup([0u8; 32]), 12),
        (
            OpCode::SysCallTokenTransfer {
                token_id: [0; 32],
                to: [0; 32],
                amount: 1,
            },
            13,
        ),
        (
            OpCode::SysCallTokenTransferFrom {
                token_id: [0; 32],
                from: [0; 32],
                to: [0; 32],
                amount: 1,
            },
            14,
        ),
        (
            OpCode::SysCallTokenMint {
                token_id: [0; 32],
                to: [0; 32],
                amount: 1,
            },
            15,
        ),
        (
            OpCode::SysCallTokenBurn {
                token_id: [0; 32],
                from: [0; 32],
                amount: 1,
            },
            16,
        ),
        (
            OpCode::SysCallTokenApprove {
                token_id: [0; 32],
                spender: [0; 32],
                amount: 1,
            },
            17,
        ),
        (
            OpCode::SysCallTokenBalanceOf {
                token_id: [0; 32],
                account: [0; 32],
            },
            18,
        ),
        (OpCode::SysCallDeployContract { code: vec![] }, 19),
        (
            OpCode::SysCallCallContract {
                contract: [0; 32],
                method: vec![],
                arg: 0,
            },
            20,
        ),
        (
            OpCode::SysCallStake {
                validator: [0; 32],
                amount: 1,
            },
            21,
        ),
        (
            OpCode::SysCallUnbond {
                validator: [0; 32],
                amount: 1,
            },
            22,
        ),
        (
            OpCode::SysCallDelegate {
                validator: [0; 32],
                amount: 1,
            },
            23,
        ),
        (OpCode::SysCallUndelegate { validator: [0; 32] }, 24),
        (OpCode::SysCallClaimRewards { validator: [0; 32] }, 25),
        (OpCode::Halt, 26),
        (
            OpCode::SysCallSubmitPriceFeed(Box::new(PriceFeedUpdate {
                asset: "STELL/USD".to_string(),
                price_micro_usd: 250_000,
                timestamp: 1_700_000_000,
                publisher_pubkey: [0; 32],
                signature: vec![],
            })),
            27,
        ),
        (
            OpCode::SysCallRevokeSession {
                session_pubkey: [0; 32],
            },
            28,
        ),
        (OpCode::SysCallPmmBuy { usdt_micro: 1 }, 29),
        (OpCode::SysCallPmmSell { stell_nano: 1 }, 30),
        (OpCode::SysCallPublishSessionGrant(Box::new(grant)), 31),
        (
            OpCode::SysCallBridge(Box::new(BridgeIntent::Release { req_id: 1 })),
            32,
        ),
        // PQ excision: the shielded transfer opcode (discriminant 33)
        // removed with Ristretto; 33 stays RESERVED so every pin below
        // is unchanged.
        (
            OpCode::SysCallActorSend {
                recipient: [0; 32],
                value: 7,
                body: vec![OpCode::Halt],
                bounce: true,
                gas_budget: 900,
            },
            34,
        ),
        (
            OpCode::SysCallVerifyZkMlReexec {
                model_id: [0; 32],
                proof: Box::new(stellereum::zkml::ZkMlProof {
                    model_hash: [0; 32],
                    public_inputs: vec![],
                    public_outputs: vec![],
                    proof_bytes: vec![],
                }),
            },
            35,
        ),
        (
            OpCode::SysCallRegisterZkMlModel {
                model_id: [0; 32],
                model: Box::new(stellereum::zkml::QuantizedLinearModel::new(vec![
                    stellereum::zkml::QuantizedLayer::new(2, 2, vec![2, -1, 1, 3], vec![1, -2]),
                ])),
            },
            36,
        ),
        (
            OpCode::SysCallRegisterZkMlSpec {
                model_id: [0; 32],
                spec: Box::new(stellereum::zkml_attestation::ModelSpec {
                    spec_hash: [0; 32],
                    spec_bytes: vec![],
                    setup_attestation: vec![],
                    n_public_inputs: 0,
                    in_dim: 0,
                    out_dim: 0,
                }),
            },
            37,
        ),
        (
            OpCode::SysCallVerifyZkMlAttestation {
                model_id: [0; 32],
                proof: Box::new(stellereum::zkml_attestation::AttestationProof {
                    model_hash: [0; 32],
                    spec_hash: [0; 32],
                    public_inputs: vec![],
                    public_outputs: vec![],
                    proof_bytes: vec![],
                }),
            },
            38,
        ),
        (
            OpCode::SysCallTokenCreate {
                name: "T".to_string(),
                symbol: "T".to_string(),
                decimals: 9,
                initial_supply: 0,
                max_supply: None,
            },
            39,
        ),
        // PQ excision: the three remaining shielded opcodes
        // (discriminants 40/41/42) removed with Ristretto; all RESERVED
        // so every pin below is unchanged.
        (
            OpCode::SysCallRotateValidatorKey {
                old_validator: [0; 32],
                new_validator: [1; 32],
            },
            43,
        ),
        (
            OpCode::SysCallBeginUndelegate {
                validator: [0; 32],
                amount: 1,
            },
            44,
        ),
        (
            OpCode::SysCallClaimDelegatorRewards { validator: [0; 32] },
            45,
        ),
        (
            OpCode::SysCallVerifyPqSignature {
                scheme_id: 1,
                pubkey: vec![],
                message: vec![],
                signature: vec![],
            },
            46,
        ),
    ]
}

#[test]
fn appended_discriminant_preserves_every_existing_encoding() {
    let cases = every_opcode_and_its_discriminant();
    assert_eq!(cases.len(), 43, "OpCode list must have exactly 43 entries");

    for (op, want) in &cases {
        let bytes = bincode::serialize(op).expect("opcode serializes");
        assert!(
            bytes.len() >= 4,
            "bincode encodes the discriminant as a leading u32: {op:?}"
        );
        let got = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        assert_eq!(
            got, *want,
            "discriminant of {op:?} moved: {got} != {want}. An OpCode was \
             INSERTED above it - every already-signed payload carrying it just \
             changed bytes"
        );
    }

    // And the whole-vector form the payload commitment actually hashes is
    // stable for a legacy payload too (a Vec prefixes its u64 length, then
    // the same indices).
    let legacy: Vec<OpCode> = vec![OpCode::Push(42), OpCode::Halt];
    let bytes = bincode::serialize(&legacy).unwrap();
    let count = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    assert_eq!(count, 2, "two opcodes");
    let first = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    assert_eq!(first, 1, "Push is still variant 1 inside a Vec");
}

// ===========================================================================
// 3. An actor tx hash commits the body
// ===========================================================================

#[test]
fn actor_tx_hash_commits_the_body() {
    let sk = SigningKey::from_bytes(&[3u8; 32]);
    let recipient = [0xABu8; 32];

    let mk = |body: Vec<OpCode>| {
        Transaction::sign_with_payload(
            &sk,
            recipient,
            0,
            50_000,
            0,
            1,
            1,
            vec![OpCode::SysCallActorSend {
                recipient,
                value: 1_000,
                body,
                bounce: true,
                gas_budget: 5_000,
            }],
        )
    };

    let a = mk(vec![OpCode::Push(1)]);
    let b = mk(vec![OpCode::Push(2)]);
    let a_again = mk(vec![OpCode::Push(1)]);

    // Deterministic: the same body hashes the same way every time ...
    assert_eq!(a.compute_tx_hash(), a_again.compute_tx_hash());
    // ... and a different body is a DIFFERENT transaction: the program is
    // committed into the signing message (and therefore the tx hash), so two
    // sends that differ only inside their body can never be confused on the
    // wire or in a block.
    assert_ne!(
        a.compute_tx_hash(),
        b.compute_tx_hash(),
        "the body must be committed: two different programs, two different hashes"
    );
    assert_ne!(a.signing_message(), b.signing_message());

    // Tampering with the body after signing invalidates the signature - the
    // payload is inside what the key signed, not a mutable annex.
    let mut tampered = a.clone();
    tampered.payload[0] = match &tampered.payload[0] {
        OpCode::SysCallActorSend {
            recipient,
            value,
            body: _,
            bounce,
            gas_budget,
        } => OpCode::SysCallActorSend {
            recipient: *recipient,
            value: *value,
            body: vec![OpCode::Push(99)],
            bounce: *bounce,
            gas_budget: *gas_budget,
        },
        other => panic!("unexpected payload opcode: {other:?}"),
    };
    assert!(
        !tampered.verify_signature(),
        "changing the body after signing must invalidate the signature"
    );
}

// ===========================================================================
// 4. A pre-actor decoder fails closed
// ===========================================================================

/// A modelled PRE-actor node: its `OpCode` enum ends at discriminant 33
/// (the shielded transfer opcode that lived there, removed since) -
/// 34 variants, discriminants 0..=33 - and
/// bincode matches the decoded `u32` index against them. An index it does not
/// know is a DECODE ERROR, so a payload starting with `SysCallActorSend`
/// cannot be decoded at all (fail closed), rather than being misread as some
/// older opcode.
///
/// Returns `true` when the modelled old node would refuse the payload.
fn pre_actor_decode_fails(payload: &[OpCode]) -> bool {
    const PRE_ACTOR_VARIANTS: u32 = 34; // discriminants 0..=33 existed then
    let bytes = bincode::serialize(payload).expect("payload serializes");
    if bytes.len() < 12 {
        return false; // empty vec: decodes on any node
    }
    let count = u64::from_le_bytes(bytes[..8].try_into().expect("vec length"));
    if count == 0 {
        return false;
    }
    let first = u32::from_le_bytes(bytes[8..12].try_into().expect("variant index"));
    first >= PRE_ACTOR_VARIANTS
}

#[test]
fn pre_actor_decoder_fails_closed_on_the_appended_variant() {
    let recipient = [0xABu8; 32];
    let actor_payload = vec![OpCode::SysCallActorSend {
        recipient,
        value: 1_000,
        body: vec![OpCode::Push(1)],
        bounce: true,
        gas_budget: 5_000,
    }];

    // The modelled old node cannot decode it - it fails closed ...
    assert!(
        pre_actor_decode_fails(&actor_payload),
        "a pre-actor node must REFUSE an actor payload, never misread it"
    );
    // ... while today's node decodes it perfectly.
    let round: Vec<OpCode> =
        bincode::deserialize(&bincode::serialize(&actor_payload).unwrap()).expect("decodes today");
    assert_eq!(round.len(), 1);

    // Every legacy payload still maps to a variant the old node knows, so
    // the append changed nothing for traffic that existed before it.
    for legacy in [
        vec![OpCode::Push(42)],
        vec![OpCode::Halt],
        vec![OpCode::Transfer {
            recipient,
            amount: 5,
        }],
        vec![OpCode::SysCallStake {
            validator: recipient,
            amount: 9,
        }],
        vec![],
    ] {
        assert!(
            !pre_actor_decode_fails(&legacy),
            "legacy payload must decode on a pre-actor node: {legacy:?}"
        );
    }
}
