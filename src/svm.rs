//! Stellereum Virtual Machine (SVM) and Micro-Gas Model
//! Micro-gas optimized for AI HFT bots:
//! Basic transfer: 280_000 nano-STELL (0.00028 STELL, micro-gas ~20x under TON)
//! Cancel order: 100 nano-STELL
//! Syscalls for fast Patricia trie traversal, Orderbook matching, and zkML verification.

use crate::cell::{CellHash, PatriciaTrie};
pub use crate::contract::{
    Contract, ContractCallContext, ContractError, ContractEvent, ContractOutcome, ContractRegistry,
    FUEL_BLAKE3_BASE, FUEL_BLAKE3_PER_BYTE, FUEL_BLOCK_HASH, FUEL_BLOCK_TIME, FUEL_CALLER,
    FUEL_ED25519_VERIFY, FUEL_EMIT, FUEL_RETURN_DATA_BASE, FUEL_RETURN_DATA_PER_BYTE,
    FUEL_SHA256_BASE, FUEL_SHA256_PER_BYTE, FUEL_SLOAD, FUEL_SSTORE, FUEL_VALUE,
};
use crate::orderbook::{ClobEvent, OrderSide, OrderType, OrderbookActor, TradeExecution};
pub use crate::token::{
    TokenEvent, TokenOp, TokenRegistry, GAS_TOKEN_APPROVE, GAS_TOKEN_BURN, GAS_TOKEN_CREATE,
    GAS_TOKEN_MINT, GAS_TOKEN_TRANSFER,
};
use crate::zkml::{SessionKeyAuthorization, ZkMlProof};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Micro-gas constants (1 STELL = 1_000_000_000 nano-STELL)
pub const NANO_STELL: u64 = 1;
/// Base fee of an empty native transfer: 280_000 nano-STELL (0.00028 STELL,
/// ~$0.00007 at the $0.25 genesis rate - roughly 20x cheaper than a typical
/// TON transfer fee, while paying validators real money: ~$1300/day network
/// wide at 211 TPS sustained, vs ~$2.6/day at the old 560).
/// Raised 500x from 560 (governance decision 2026-10-06): the old value made
/// spam essentially free and validator fee income negligible. Micro-gas still
/// holds (sub-cent fees); HFT/griefing costs 500x more to sustain.
/// This is a CONSENSUS CONSTANT: every validator must run a binary with this
/// exact value (redeploy in lockstep). Historical blocks are unaffected (gas
/// is priced at apply time), so no wipe or version bump is needed.
///
/// Token transfers are aligned with [`GAS_BASIC_TRANSFER`] (280,000 nano-STELL floor)
/// so that custom token transfers cannot be used for 500x cheaper spam attacks.
pub const GAS_BASIC_TRANSFER: u64 = 280_000;
const _: () = assert!(GAS_TOKEN_TRANSFER >= GAS_BASIC_TRANSFER);
pub const GAS_ORDER_CANCEL: u64 = 100; // Ultra cheap cancellation for HFT bots
pub const GAS_ORDER_PLACE: u64 = 1_200;
pub const GAS_ZKML_VERIFY: u64 = 5_000;
pub const GAS_PATRICIA_LOOKUP: u64 = 50;
/// Gas consumed by the token balance query.
///
/// Aligned with the native floor like every other token operation (audit
/// W6.6, item 4): the fee a transaction pays is its DECLARED `gas_limit`, so
/// a cheap table entry lets one paid transaction run thousands of registry
/// reads. ONE RULE: no token operation is cheaper than a native transfer.
pub const GAS_TOKEN_BALANCE: u64 = GAS_BASIC_TRANSFER;
const _: () = assert!(GAS_TOKEN_BALANCE >= GAS_BASIC_TRANSFER);
/// Base gas to deploy a WASM contract, plus a per-byte charge (`GAS_DEPLOY_BASE + bytes * GAS_PER_BYTE`).
pub const GAS_DEPLOY_BASE: u64 = crate::contract::GAS_DEPLOY_BASE;
pub const GAS_PER_BYTE: u64 = crate::contract::GAS_PER_BYTE;
pub const GAS_CONTRACT_DEPLOY_BASE: u64 = GAS_DEPLOY_BASE;
pub const GAS_CONTRACT_CODE_PER_BYTE: u64 = GAS_PER_BYTE;
/// Base gas to call a WASM contract (wasmi fuel is charged on top).
pub const GAS_CONTRACT_CALL: u64 = 1_000;
/// Extra gas charged per argument of a multi-argument contract call.
pub const GAS_CONTRACT_CALL_PER_ARG: u64 = 10;
/// Gas charged per byte of method name + calldata carried by a contract-call
/// opcode. Anti-DoS: both ride the signed payload (block space every node
/// stores) and cost per-byte work on every node (UTF-8 scan, export lookup,
/// calldata clone, `host.calldata` copy), so a fixed-price call would make a
/// megabyte method name cost the same as `sum3`. Same rate as the deploy
/// per-byte price and the PQ wire price: one byte price for one byte of wire.
pub const GAS_CONTRACT_CALL_PER_BYTE: u64 = 2;
/// Hard cap on a contract-call method name (bytes). Wasm export names are
/// short identifiers; anything larger is a wire-bloat probe. Fail-closed in
/// the dispatch arms below.
pub const MAX_CONTRACT_METHOD_LEN: usize = 256;
/// Hard cap on calldata bytes per contract call (matches
/// [`crate::contract::MAX_RETURN_DATA`]: a call cannot carry more blob than a
/// contract can return). Fail-closed in the dispatch arms below.
pub const MAX_CONTRACT_CALLDATA_BYTES: usize = 64 * 1024;

/// Variable half of `SysCallCallContract` / `SysCallCallContractArgs`: base +
/// per-arg + per byte of method name and calldata carried. Single definition
/// shared by the `opcode_gas` table and the execution arms (they must agree
/// bit-identically — pinned by `syscall_charges_match_the_priced_table`-style
/// tests).
#[inline(always)]
pub fn contract_call_gas(method_len: usize, args_len: usize, calldata_len: usize) -> u64 {
    GAS_CONTRACT_CALL
        .saturating_add((args_len as u64).saturating_mul(GAS_CONTRACT_CALL_PER_ARG))
        .saturating_add(
            ((method_len.saturating_add(calldata_len)) as u64)
                .saturating_mul(GAS_CONTRACT_CALL_PER_BYTE),
        )
}
/// Gas to bond or delegate stake.
pub const GAS_STAKE_BOND: u64 = 2_000;
/// Gas to start unbonding / withdraw delegations.
pub const GAS_STAKE_UNBOND: u64 = 800;
/// Gas to claim staking rewards.
pub const GAS_STAKE_CLAIM: u64 = 600;
/// Gas charged per PRICE LEVEL an order crosses during matching.
/// Anti-DoS: matching work scales with levels crossed, so gas must too.
pub const GAS_PER_MATCH_LEVEL: u64 = 40;
/// Hard cap on price levels a single order may cross in one call.
pub const MAX_MATCH_LEVELS: usize = 64;
/// Gas to commit a signed price feed: one ed25519 verify plus the ordered
/// map writes. Priced like the other signature-shaped syscalls so a feed flood
/// cannot be cheaper than the block space it burns.
pub const GAS_SUBMIT_PRICE_FEED: u64 = 1_500;
/// Gas to run a PMM buy: the bonding-curve solve plus a wUSDT burn.
pub const GAS_PMM_BUY: u64 = 1_800;
/// Gas to run a PMM sell: the curve solve plus a wUSDT mint (the mirror of a
/// buy; same work, same price).
pub const GAS_PMM_SELL: u64 = 1_800;
/// Gas to publish a master-signed session grant: one ed25519 verify over the
/// grant message, priced with the other signature-shaped syscalls.
pub const GAS_PUBLISH_SESSION_GRANT: u64 = 1_500;
/// Gas to validate a bridge intent. Deliberately cheap: the VM only checks the
/// intent's shape, while `execute_payload` settles its native leg (see
/// `OpCode::SysCallBridge`).
pub const GAS_BRIDGE_INTENT: u64 = 600;
/// Gas to revoke a session key. Rare, master-only, and consensus-visible
/// (it moves the committed registry), so it is priced like the other
/// state-writing admin syscalls rather than like arithmetic.
pub const GAS_SESSION_REVOKE: u64 = 1_000;
/// Gas to apply a §9 confidential transfer: a handful of Ristretto
/// decompressions plus the fee-point multiplication, the spent-set insert and
/// the two (or one, for a self-transfer) balance rewrites. Priced with the
/// other state-writing syscalls - the work is group arithmetic plus ordered
/// map writes, and a flood of them must not be cheaper than the block space
/// it burns.
pub const GAS_CONFIDENTIAL_TRANSFER: u64 = 2_625;
/// Gas BASE for the enforced confidential transfer (V2, audit 2026-10-06 F-A):
/// the table prices per commitment + per proof bit on top (see
/// `confidential_transfer2_gas`), since one 64-bit proof costs ~64
/// bit-verifies and counts are uncapped. 1.75x multiplier applied for privacy compute defense.
pub const GAS_CONFIDENTIAL_TRANSFER2: u64 = 3_500;
/// Per commitment / per proof bit inside a V2 transfer (1.75x scaled).
pub const GAS_CONFIDENTIAL_T2_PER_COMMITMENT: u64 = 1_750;
pub const GAS_CONFIDENTIAL_T2_PER_BIT: u64 = 44;

/// Full dispatch charge for a V2 transfer. Single definition shared by the
/// `opcode_gas` table and the execution arm (they must agree bit-identically —
/// pinned by `syscall_charges_match_the_priced_table`).
pub fn confidential_transfer2_gas(
    input_ranges: &[crate::crypto_privacy::RangeProof],
    output_ranges: &[crate::crypto_privacy::RangeProof],
) -> u64 {
    let n = (input_ranges.len() + output_ranges.len()) as u64;
    let bits: u64 = input_ranges
        .iter()
        .chain(output_ranges.iter())
        .map(|p| p.bits as u64)
        .sum();
    GAS_CONFIDENTIAL_TRANSFER2
        .saturating_add(n.saturating_mul(GAS_CONFIDENTIAL_T2_PER_COMMITMENT))
        .saturating_add(bits.saturating_mul(GAS_CONFIDENTIAL_T2_PER_BIT))
}
/// Gas for a shield entry: one Pedersen recomputation (opening check) plus
/// the ownership-map insert. 1.75x scaled.
pub const GAS_CONFIDENTIAL_SHIELD: u64 = 3_500;
/// Base gas for an unshield exit: per-input opening recomputation is charged
/// dynamically in `opcode_gas` (1.75x scaled).
pub const GAS_CONFIDENTIAL_UNSHIELD: u64 = 3_500;
/// Consensus caps on shielded IO counts (audit: blocks troubles — wire-DoS
/// asymmetry): one tx may carry at most this many range-proved commitments /
/// unshield inputs. A 16-proof 64-bit transfer is ~330KB (fits 1MB tx cap
/// with headroom); 64 unshield inputs are ~4.6KB. Beyond this, split across
/// txs. Fail-closed in the handlers below.
pub const MAX_CONFIDENTIAL_IO_PER_TX: usize = 16;
pub const MAX_UNSHIELD_INPUTS_PER_TX: usize = 64;
/// Hard cap on viewing payloads per `stell_shieldedBalance` scan (audit F1:
/// unbounded array = unauth CPU DoS: hex parse + X25519 DH + KDF + Pedersen
/// commit per entry). Read-only scan, so the cap is generous (4x unshield);
/// larger histories paginate client-side. Fail-closed in the handler.
pub const MAX_SHIELDED_SCAN_PAYLOADS: usize = 256;
/// Per-input cost inside an unshield exit (one Pedersen recomputation, 1.75x scaled).
pub const GAS_CONFIDENTIAL_UNSHIELD_PER_INPUT: u64 = 525;
/// Gas to enqueue an actor message (`OpCode::SysCallActorSend`): the opcode
/// validation plus the inbox bookkeeping `execute_payload` performs when it
/// settles the send. Priced with the other state-writing syscalls. The
/// DELIVERY half is charged separately as [`GAS_ACTOR_DELIVER`] (see the
/// handler), so a message flood costs block gas on the sending side twice -
/// once for the enqueue, once for the delivery it forces.
pub const GAS_ACTOR_SEND: u64 = 900;
/// Gas the sender prepays for DELIVERING one actor message: the deterministic
/// per-message overhead of the block's mailbox pass (inbox pop, undo snapshot,
/// trie write), independent of the body it may run. Charged to the sending
/// transaction's gas (so it shows up in the fee / the session budget) BEFORE
/// the body's own fuel, which is the sender's separately chosen `gas_budget`.
/// Deliberately NOT part of `opcode_gas`: it varies per execution context, so
/// the handler charges it on top of the fixed table entry.
pub const GAS_ACTOR_DELIVER: u64 = 800;

/// §2 zkML. Micro-gas for the SOUND verify opcode, `SysCallVerifyZkMlReexec`.
///
/// The fixed half of the price: the Fiat-Shamir re-hash of the proof
/// transcript plus the work of LOOKING the model up in the committed registry.
/// The two variable halves are priced on top of it:
///  * the PROOF bytes carried on the wire, in `opcode_gas`
///    ([`GAS_ZKML_PROOF_PER_BYTE`]) - the proof rides inside the signed
///    payload, so the sender pays for the block space it burns;
///  * the MODEL re-execution, charged inside the handler
///    ([`GAS_ZKML_REEXEC_PER_PARAM`]) - `opcode_gas` cannot see the registry,
///    and the re-execution cost is exactly the model's parameter count.
///
/// Deliberately priced like `GAS_ZKML_VERIFY` (5_000): same verification shape,
/// but this one actually runs the model, so the per-parameter charge on top is
/// what keeps "verify a registered model" from being cheaper per unit of work
/// than "claim you verified one".
pub const GAS_ZKML_VERIFY_IN: u64 = 5_000;
/// Micro-gas per byte of proof carried by `SysCallVerifyZkMlReexec`
/// (`ZkMlProof::wire_len`). Anti-DoS: a proof flood must cost at least the
/// block space it occupies, and `opcode_gas` is the table the dispatch loop
/// (and the mailbox pass pricing a program without running it) charges from.
pub const GAS_ZKML_PROOF_PER_BYTE: u64 = 2;
/// Micro-gas per registered-model parameter the verifier RE-EXECUTES.
///
/// Charged inside the handler (like [`GAS_PER_MATCH_LEVEL`] and
/// [`GAS_ACTOR_DELIVER`], which are also not in the fixed table), because the
/// model lives in the committed registry and `opcode_gas` only ever sees the
/// opcode. Bounded by [`crate::zkml::MAX_ZKML_MODEL_PARAMS`], so the charge
/// cannot run away; an out-of-gas here reverts the transaction like any other.
pub const GAS_ZKML_REEXEC_PER_PARAM: u64 = 1;
/// Fixed half of `SysCallRegisterZkMlModel`: the validation pass
/// (`QuantizedLinearModel::validate`) plus the ordered map write.
pub const GAS_ZKML_REGISTER: u64 = 1_000;
/// Micro-gas per parameter written into the committed registry by
/// `SysCallRegisterZkMlModel`. Registration is the only way the registry
/// grows, so pricing it per parameter is what stops a model flood from being
/// cheaper than the state it forces every node to store and hash.
pub const GAS_ZKML_REGISTER_PER_PARAM: u64 = 4;

/// Fixed micro-gas for the stack/arithmetic hot path. These are `pub` so the
/// dispatch loop in [`Svm::execute_inner`] charges from the SAME constants as
/// [`opcode_gas`] (single dispatch: one match per opcode, not two) - changing
/// a value here changes both call sites together, so the table cannot drift.
pub const GAS_NOP: u64 = 1;
pub const GAS_PUSH: u64 = 5;
pub const GAS_POP: u64 = 2;
pub const GAS_ADD_SUB: u64 = 3;
pub const GAS_MUL_DIV: u64 = 10;
pub const GAS_LOAD_BALANCE: u64 = 20;
pub const GAS_HALT: u64 = 0;

/// Variable half of `SysCallDeployContract`: base + per byte of code carried (`GAS_DEPLOY_BASE + bytes * GAS_PER_BYTE`).
#[inline(always)]
pub fn contract_deploy_gas(code_len: usize) -> u64 {
    crate::contract::contract_deploy_gas(code_len)
}

/// Variable half of `SysCallVerifyZkMlReexec`: base + per byte of proof carried.
#[inline(always)]
pub fn zkml_verify_in_gas(proof_wire_len: usize) -> u64 {
    GAS_ZKML_VERIFY_IN
        .saturating_add((proof_wire_len as u64).saturating_mul(GAS_ZKML_PROOF_PER_BYTE))
}

/// Variable half of `SysCallRegisterZkMlModel`: base + per parameter written.
#[inline(always)]
pub fn zkml_register_gas(model_params: usize) -> u64 {
    GAS_ZKML_REGISTER
        .saturating_add((model_params as u64).saturating_mul(GAS_ZKML_REGISTER_PER_PARAM))
}

/// §2 zkML, the ATTESTATION verify opcode (`SysCallVerifyZkMlAttestation`).
///
/// ⚠️ HONESTY (audit W8.3 / production blocker A5): the old name of this
/// constant said "Groth16 verification over BLS12-381 (three pairings plus
/// the verifier's MSM)". **None of that is what happens.** The attestation
/// verifier RE-EXECUTES the quantized model and compares the outputs and the
/// BLAKE3 trace root — there are no pairings, no MSM, no curve at all.
///
/// The fixed half of the price is therefore the fixed cost of the trace
/// bookkeeping around that re-execution. Priced an order of magnitude above
/// the re-execution verify base (5_000) because it ALSO checks the registered
/// spec binding (two hash matches + the shape check) that the plain
/// re-execution path does not do. The two variable halves are priced on top:
///  * the PUBLIC INPUTS, in this table
///    ([`GAS_ATTESTATION_PER_PUBLIC_INPUT`]) - the verifier's per-input work
///    grows with them, and `opcode_gas` sees the proof, so everything is
///    visible here;
///  * the PROOF bytes carried on the wire ([`GAS_ZKML_PROOF_PER_BYTE`], the
///    same block-space price as the re-execution proof).
///
/// The MODEL-SIZED half of the work is charged inside the handler
/// ([`GAS_ZKML_REEXEC_PER_PARAM`]), exactly like the re-execution path,
/// because `opcode_gas` cannot see the registry. Before audit W8.3 that
/// charge was MISSING here, so the "attestation" opcode was priced BELOW the
/// re-execution opcode while doing the same CPU work.
pub const GAS_ATTESTATION_VERIFY_BASE: u64 = 30_000;
/// Micro-gas per public input of an attestation verify: the verifier's
/// per-input work (the re-execution's activations and the trace leaves)
/// grows with this.
pub const GAS_ATTESTATION_PER_PUBLIC_INPUT: u64 = 200;
/// Fixed half of `SysCallRegisterZkMlSpec`: the spec parse + shape/hash
/// checks plus the ordered map write.
pub const GAS_ZKML_SPEC_REGISTER_BASE: u64 = 2_000;
/// Micro-gas per spec byte written into committed state (spec bytes plus
/// attestation). Same rate as model parameters: both are state every node
/// stores and hashes.
pub const GAS_ZKML_SPEC_PER_BYTE: u64 = 4;

/// Variable half of `SysCallVerifyZkMlAttestation`: base + per public input +
/// per proof wire byte. Fully visible to `opcode_gas` (the proof carries
/// its inputs), so the handler charges the model-sized half on top.
#[inline(always)]
pub fn attestation_verify_gas(n_public_inputs: usize, proof_wire_len: usize) -> u64 {
    GAS_ATTESTATION_VERIFY_BASE
        .saturating_add((n_public_inputs as u64).saturating_mul(GAS_ATTESTATION_PER_PUBLIC_INPUT))
        .saturating_add((proof_wire_len as u64).saturating_mul(GAS_ZKML_PROOF_PER_BYTE))
}

/// Variable half of `SysCallRegisterZkMlSpec`: base + per spec byte stored.
#[inline(always)]
pub fn spec_register_gas(spec: &crate::zkml_attestation::ModelSpec) -> u64 {
    GAS_ZKML_SPEC_REGISTER_BASE.saturating_add(
        (spec
            .spec_bytes
            .len()
            .saturating_add(spec.setup_attestation.len()) as u64)
            .saturating_mul(GAS_ZKML_SPEC_PER_BYTE),
    )
}

/// Base gas for post-quantum / hybrid signature verification (`OpCode::SysCallVerifyPqSignature`).
pub const GAS_PQ_VERIFY_BASE: u64 = 1_500;
/// Micro-gas per byte carried by `SysCallVerifyPqSignature` (pubkey, message, and signature bytes).
pub const GAS_PQ_VERIFY_PER_BYTE: u64 = 2;

/// Gas for `SysCallVerifyPqSignature`: base + per byte of pubkey, message, and signature carried.
#[inline(always)]
pub fn pq_verify_gas(pubkey_len: usize, message_len: usize, signature_len: usize) -> u64 {
    let wire_bytes = (pubkey_len as u64)
        .saturating_add(message_len as u64)
        .saturating_add(signature_len as u64);
    GAS_PQ_VERIFY_BASE.saturating_add(wire_bytes.saturating_mul(GAS_PQ_VERIFY_PER_BYTE))
}

/// Base gas for an equivocation report (`OpCode::SysCallReportEquivocation`):
/// two signature verifications plus ledger-membership and dedup-key work.
pub const GAS_EQUIVOCATION_REPORT_BASE: u64 = 2_500;
/// Micro-gas per evidence wire byte carried by `SysCallReportEquivocation`.
pub const GAS_EQUIVOCATION_REPORT_PER_BYTE: u64 = 2;

/// Gas for `SysCallReportEquivocation`: base + per evidence wire byte.
#[inline(always)]
pub fn equivocation_report_gas(wire_len: usize) -> u64 {
    GAS_EQUIVOCATION_REPORT_BASE
        .saturating_add((wire_len as u64).saturating_mul(GAS_EQUIVOCATION_REPORT_PER_BYTE))
}

/// The gas ONE opcode costs, as charged by the dispatch loop in
/// [`Svm::execute_inner`].
///
/// This is the whole micro-gas table, extracted so the mailbox pass and any
/// other out-of-VM caller can price a program without running it - a delivered
/// actor body is gas-metered exactly like a payload, against the same table.
/// APPENDING a variant means adding its arm here; the compiler forces it.
///
/// The dispatch loop does NOT call this per opcode (that was a second full
/// match over 35+ variants on the hot path); it charges the same constants
/// inline, in the same match that executes the opcode. The values are
/// identical by construction - every arm below and every dispatch arm reads
/// the same `GAS_*` constant or `*_gas` helper.
pub fn opcode_gas(op: &OpCode) -> u64 {
    match op {
        OpCode::Nop => GAS_NOP,
        OpCode::Push(_) => GAS_PUSH,
        OpCode::Pop => GAS_POP,
        OpCode::Add | OpCode::Sub => GAS_ADD_SUB,
        OpCode::Mul | OpCode::Div => GAS_MUL_DIV,
        OpCode::LoadBalance => GAS_LOAD_BALANCE,
        OpCode::Transfer { .. } => GAS_BASIC_TRANSFER,
        OpCode::SysCallPlaceOrder { .. } => GAS_ORDER_PLACE,
        OpCode::SysCallCancelOrder { .. } => GAS_ORDER_CANCEL,
        OpCode::SysCallVerifyZkMl => GAS_ZKML_VERIFY,
        OpCode::SysCallPatriciaLookup(_) => GAS_PATRICIA_LOOKUP,
        OpCode::SysCallTokenTransfer { .. } => GAS_TOKEN_TRANSFER,
        OpCode::SysCallTokenTransferFrom { .. } => GAS_TOKEN_TRANSFER,
        OpCode::SysCallTokenMint { .. } => GAS_TOKEN_MINT,
        OpCode::SysCallTokenBurn { .. } => GAS_TOKEN_BURN,
        OpCode::SysCallTokenApprove { .. } => GAS_TOKEN_APPROVE,
        OpCode::SysCallTokenCreate { .. } => GAS_TOKEN_CREATE,
        OpCode::SysCallConfidentialTransfer2 {
            input_ranges,
            output_ranges,
            ..
        } => confidential_transfer2_gas(input_ranges, output_ranges),
        OpCode::SysCallConfidentialShield { .. } => GAS_CONFIDENTIAL_SHIELD,
        OpCode::SysCallConfidentialUnshield { inputs } => GAS_CONFIDENTIAL_UNSHIELD.saturating_add(
            (inputs.len() as u64).saturating_mul(GAS_CONFIDENTIAL_UNSHIELD_PER_INPUT),
        ),
        OpCode::SysCallTokenBalanceOf { .. } => GAS_TOKEN_BALANCE,
        OpCode::SysCallDeployContract { code } => contract_deploy_gas(code.len()),
        OpCode::SysCallCallContract { method, .. } => {
            contract_call_gas(method.len(), 1, 0)
        }
        OpCode::SysCallCallContractArgs {
            method,
            args,
            calldata,
            ..
        } => contract_call_gas(method.len(), args.len(), calldata.len()),
        OpCode::SysCallStake { .. } | OpCode::SysCallDelegate { .. } => GAS_STAKE_BOND,
        OpCode::SysCallUnbond { .. } | OpCode::SysCallUndelegate { .. } => GAS_STAKE_UNBOND,
        OpCode::SysCallBeginUndelegate { .. } => GAS_STAKE_UNBOND,
        OpCode::SysCallRotateValidatorKey { .. } => GAS_STAKE_UNBOND,
        OpCode::SysCallClaimRewards { .. } => GAS_STAKE_CLAIM,
        OpCode::SysCallClaimDelegatorRewards { .. } => GAS_STAKE_CLAIM,
        OpCode::SysCallWithdrawSelfBond { .. } => GAS_STAKE_UNBOND,
        OpCode::SysCallSubmitPriceFeed(_) => GAS_SUBMIT_PRICE_FEED,
        OpCode::SysCallRevokeSession { .. } => GAS_SESSION_REVOKE,
        OpCode::SysCallPmmBuy { .. } => GAS_PMM_BUY,
        OpCode::SysCallPmmSell { .. } => GAS_PMM_SELL,
        OpCode::SysCallPublishSessionGrant(_) => GAS_PUBLISH_SESSION_GRANT,
        OpCode::SysCallBridge(_) => GAS_BRIDGE_INTENT,
        OpCode::SysCallConfidentialTransfer { .. } => GAS_CONFIDENTIAL_TRANSFER,
        OpCode::SysCallActorSend { .. } => GAS_ACTOR_SEND,
        // §2: the proof is part of the payload, so its BYTES are charged here
        // (the model half is charged in the handler - `opcode_gas` cannot see
        // the registry). Registration is priced per parameter written.
        OpCode::SysCallVerifyZkMlReexec { proof, .. } => zkml_verify_in_gas(proof.wire_len()),
        OpCode::SysCallRegisterZkMlModel { model, .. } => zkml_register_gas(model.param_count()),
        // §2 succinct halves: fully priced here (everything is visible on
        // the proof/key the opcode carries - no registry-sized remainder
        // for the handler, unlike the re-execution verify).
        OpCode::SysCallRegisterZkMlSpec { spec, .. } => spec_register_gas(spec),
        OpCode::SysCallVerifyZkMlAttestation { proof, .. } => attestation_verify_gas(
            proof
                .public_inputs
                .len()
                .saturating_add(proof.public_outputs.len()),
            proof.wire_len(),
        ),
        OpCode::SysCallVerifyPqSignature {
            pubkey,
            message,
            signature,
            ..
        } => pq_verify_gas(pubkey.len(), message.len(), signature.len()),
        OpCode::SysCallReportEquivocation { evidence } => {
            equivocation_report_gas(evidence.wire_len())
        }
        // The PQ report does the SAME work as the Ed25519 one (two signature
        // verifications, ledger membership and dedup-key work) and carries
        // the SAME kind of envelope, so it is priced from the SAME table:
        // one gas table for one job, so the two reports can never drift
        // apart into "the expensive one is cheaper".
        OpCode::SysCallReportPqEquivocation { evidence } => {
            equivocation_report_gas(evidence.wire_len())
        }
        // The proposal report does the same job as the vote reports (two
        // proposer-signature verifications over two full blocks, ledger
        // membership and dedup-key work) and is priced from the same table.
        // The per-byte term is what prices the two embedded blocks: a
        // reporter pays for every byte of evidence it makes every node
        // re-verify.
        OpCode::SysCallReportProposalEquivocation { evidence } => {
            equivocation_report_gas(evidence.wire_len())
        }
        // Same bond work as `SysCallStake` (floor check, ledger bond,
        // pool move): same price, no discount for naming a commission.
        OpCode::SysCallStakeWithCommission { .. } => GAS_STAKE_BOND,
        OpCode::Halt => GAS_HALT,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum OpCode {
    Nop,
    Push(u64),
    Pop,
    Add,
    Sub,
    Mul,
    Div,
    // Storage & Account
    LoadBalance,
    Transfer {
        recipient: [u8; 32],
        amount: u64,
    },
    // Orderbook Syscalls
    SysCallPlaceOrder {
        pair_id: u32,
        is_buy: bool,
        price: u64,
        amount: u64,
    },
    SysCallCancelOrder {
        order_id: u64,
    },
    // AI zkML Syscall
    //
    // LEGACY. Structural-only (`ZkMlProof::verify_inference`, explicitly NOT
    // sound - it never checks the linear layers) AND hard-refused on the block
    // path: it reads `VmContext.zkml_proof`, which no transport ever supplies,
    // and the handler reverts unconditionally so wiring that field up cannot
    // resurrect the unsound check. Kept unchanged for its pinned discriminant
    // (11). The reachable, sound §2 opcode is `SysCallVerifyZkMlReexec` (below),
    // which carries the proof in the payload and re-executes the registered
    // model.
    SysCallVerifyZkMl,
    // Patricia Tree Traversal
    SysCallPatriciaLookup(CellHash),
    // Fungible Token Syscalls (STS standard)
    SysCallTokenTransfer {
        token_id: [u8; 32],
        to: [u8; 32],
        amount: u64,
    },
    SysCallTokenTransferFrom {
        token_id: [u8; 32],
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
    },
    SysCallTokenMint {
        token_id: [u8; 32],
        to: [u8; 32],
        amount: u64,
    },
    SysCallTokenBurn {
        token_id: [u8; 32],
        from: [u8; 32],
        amount: u64,
    },
    SysCallTokenApprove {
        token_id: [u8; 32],
        spender: [u8; 32],
        amount: u64,
    },
    SysCallTokenBalanceOf {
        token_id: [u8; 32],
        account: [u8; 32],
    },
    // WASM smart-contract syscalls (validated, sandboxed, fuel-metered)
    SysCallDeployContract {
        code: Vec<u8>,
    },
    SysCallCallContract {
        contract: [u8; 32],
        method: Vec<u8>,
        arg: i64,
    },
    // Staking (P0-1). These are what make the validator set reachable: bonds
    // are applied through blocks, so every node derives the same validator set,
    // instead of trusting whatever one node was told over RPC.
    /// Bond (or add to the bond of) a validator. The amount leaves the sender.
    SysCallStake {
        validator: [u8; 32],
        amount: u64,
    },
    /// Start unbonding from a validator; returns to the sender after cooldown.
    SysCallUnbond {
        validator: [u8; 32],
        amount: u64,
    },
    /// Delegate stake to a validator.
    SysCallDelegate {
        validator: [u8; 32],
        amount: u64,
    },
    /// Withdraw matured delegations.
    SysCallUndelegate {
        validator: [u8; 32],
    },
    /// Claim accrued rewards for a validator the sender is bonded to.
    SysCallClaimRewards {
        validator: [u8; 32],
    },
    Halt,
    // APPENDED, never inserted above: `OpCode` is bincode-serialized into
    // every transaction's signature preimage and tx hash, so adding a variant
    // anywhere before an existing one would renumber its discriminant and
    // invalidate already-signed transactions (and every pinned tx hash).
    // The price feed itself is boxed: it is a signed, attacker-supplied struct
    // and keeping the opcode variant small keeps enum-wide work proportional.
    /// Commit a signed oracle price feed into consensus state. Verified and
    /// committed atomically against `ctx.timestamp` (the BLOCK timestamp); any
    /// rejection reverts the whole transaction.
    SysCallSubmitPriceFeed(Box<crate::oracle::PriceFeedUpdate>),
    // APPEND, never insert above: see the comment on `SysCallSubmitPriceFeed`.
    // This variant was added in session-keys phase 2 with the SAME rule -
    // `OpCode` is bincode-serialized into every transaction's signature
    // preimage and tx hash, so appending is what keeps every already-signed
    // payload (and every pinned tx/block hash) byte-identical, while an old
    // node's decoder fails closed on these bytes instead of misreading them.
    /// Revoke a registered session key. The revocation is TERMINAL and lives
    /// in the committed session-key registry: from the block this lands in,
    /// every admission path, the proposer filter and execution itself refuse
    /// transactions under that key. Callable only by the delegator
    /// (`ctx.sender`, i.e. `tx.from`, must equal the key's registered master).
    SysCallRevokeSession {
        session_pubkey: [u8; 32],
    },
    // APPEND, never insert above: same bincode-discriminant rule as every
    // variant above (see the comment on `SysCallSubmitPriceFeed`). The three
    // variants below make the passport's remaining domains reachable from a
    // block instead of only from a direct engine call.
    //
    // The PMM syscalls. The curve and the wUSDT leg are applied inside the VM
    // against its clone-committed registries; the NATIVE leg (minting STELL on
    // a buy, burning it on a sell) has no VM channel, so it is emitted as a
    // `pmm::PmmEvent` and settled once by `execute_payload` through the
    // engine's account map + trie - both apply paths therefore move the same
    // coins.
    /// Buy STELL from the PMM with exactly `usdt_micro` wUSDT (6-decimals).
    SysCallPmmBuy {
        usdt_micro: u64,
    },
    /// Sell exactly `stell_nano` STELL back to the PMM for wUSDT.
    SysCallPmmSell {
        stell_nano: u64,
    },
    /// Publish a master-signed session-key grant on chain.
    ///
    /// The grant itself rides inside every session transaction's signature
    /// envelope, so this is not needed to USE a grant - it is how a grant
    /// becomes a committed, receipt-provable record instead of a printout. The
    /// master's signature over the grant must verify and the master must be
    /// the sender: nobody can publish someone else's grant, and nobody can
    /// publish a grant they altered.
    SysCallPublishSessionGrant(Box<crate::zkml::SessionKeyAuthorization>),
    /// Teleport bridge intent (deposit / withdrawal request / attestation /
    /// release).
    ///
    /// The VM validates the intent's shape; `execute_payload` then settles its
    /// native leg the same way it settles a PMM swap: a deposit credits the
    /// recipient, a withdrawal debits the sender into `bridge::BRIDGE_ESCROW`
    /// and parks a committed queue entry. Both are account/trie writes plus
    /// committed `bridge::BridgeState` fields, so they are deterministic and
    /// part of the state root. The POLICY half - relayer/validator quorum over
    /// `Attest` bundles, the source-tx replay set, the withdrawal queue, the
    /// time-lock and the hourly rate limit - is enforced there too, against
    /// the committed domain and the BLOCK timestamp; see `bridge.rs`.
    SysCallBridge(Box<crate::bridge::BridgeIntent>),
    // APPEND, never insert above: same bincode-discriminant rule as every
    // variant above (see the comment on `SysCallSubmitPriceFeed`). Appending
    // is what keeps every already-signed payload and every pinned tx hash
    // byte-identical while an old node's decoder fails closed on these bytes.
    /// Apply a §9 confidential (shielded) value transfer.
    ///
    /// The handler is the live front door to the committed engine: it calls
    /// `ConfidentialTransfer::verify_balance_conservation`, then
    /// `ConfidentialState::apply_transfer`, which rejects a repeated input and
    /// an input already in the spent set (double-spend) and only then rewrites
    /// the two shielded balances, the spent set and the fee total. Every
    /// rejection reverts the whole transaction.
    ///
    /// The SENDER is `ctx.sender` - the transaction's authenticated signer -
    /// and never a field of the opcode: input ownership is not proven here
    /// (that is an A5 range/balance-proof concern, and this opcode does not
    /// carry proofs yet), so the signature is the only thing tying a spend to
    /// an account. `recipient` is the shielded account being credited.
    ///
    /// The ledger itself is NOT in the VM: `execute_payload` clones the engine's
    /// `ConfidentialState`, hands that working copy in through
    /// [`Svm::execute_with_confidential_and_sends`] and commits it back only if
    /// the whole transaction applies (clone-commit, exactly like the staking
    /// ledger). A direct [`Svm::execute`] caller has no ledger to offer, so the
    /// syscall reverts the way a token syscall does without a registry.
    SysCallConfidentialTransfer {
        recipient: [u8; 32],
        transfer: Box<crate::crypto_privacy::ConfidentialTransfer>,
    },
    // APPEND, never insert above: same bincode-discriminant rule as every
    // variant above (see the comment on `SysCallSubmitPriceFeed`). This is
    // §1 of the actor mailbox: it enqueues an asynchronous message into the
    // RECIPIENT's inbox instead of moving value synchronously, and the block's
    // mailbox pass delivers it after the transactions step.
    //
    // `body` is a PROGRAM, not opaque bytes, so a delivered message reuses the
    // micro-gas table (`opcode_gas`), the clone-commit discipline and the
    // bounce semantics of a normal payload - it is executed by the same VM,
    // with the `gas_budget` the sender prepaid here as its fuel.
    //
    // v1 rule (enforced by the handler): `bounce` MUST be true, so a failed
    // delivery returns the value to the sender instead of destroying it.
    // `gas_budget` is prepaid on top of [`GAS_ACTOR_DELIVER`] within the
    // transaction's declared `gas_limit` (the handler charges both), which is
    // what bounds the work this message can force on every node later.
    SysCallActorSend {
        recipient: [u8; 32],
        value: u64,
        body: Vec<OpCode>,
        bounce: bool,
        gas_budget: u64,
    },
    // APPEND, never insert above: same bincode-discriminant rule as every
    // variant above (see the comment on `SysCallSubmitPriceFeed`). §2 of the
    // passport, appended as TWO opcodes (35 then 36) so both halves of
    // "consensus-verifiable inference" - the committed model registry and the
    // proof checked against it - are reachable from a block.
    //
    // WHY THE PROOF RIDES INSIDE THE OPCODE: `Transaction.payload` is already
    // hashed into the signing message and the tx hash, so the proof bytes are
    // signed and committed by construction, and an OLD node fails closed on
    // the new discriminant instead of misreading it. No `Transaction`/`Block`
    // field was added (bincode 1.3 is non-self-describing: a new struct field
    // would stop every persisted block from decoding).
    //
    // The two gas halves are the micro-gas table (`opcode_gas`: verify base +
    // proof bytes, register base + parameters) plus, for the verify, the
    // in-handler re-execution charge - see the constants at the top of this
    // file.
    /// §2 zkML, the SOUND variant: verify an inference proof against a model
    /// that is REGISTERED on chain under `model_id`.
    ///
    /// The handler fetches the model from the committed registry
    /// ([`crate::zkml::ZkMlModelRegistry`]), hash-matches it against
    /// `proof.model_hash`, and calls
    /// [`crate::zkml::ZkMlProof::verify_inference_against`] - which RE-EXECUTES
    /// the model on the proof's public inputs and compares outputs and every
    /// traced activation. A failed check reverts the whole transaction, like
    /// every other refusal opcode here.
    ///
    /// **"Sound" means re-execution, NOT a zk-SNARK.** There is no circuit, no
    /// trusted setup and no succinctness: every verifying node runs the full
    /// forward pass, so verification costs what the model costs and the verifier
    /// must hold the model (that is what the registry is for). What that does
    /// buy - and what the structural check it replaces did NOT - is that a
    /// forged proof with invented activations and lying outputs is rejected:
    /// `verify_inference()` alone is fooled (regression
    /// `forged_proof_passes_structural_but_fails_sound_check`), and the old
    /// `OpCode::SysCallVerifyZkMl` called exactly that and was unreachable on
    /// the block path anyway (`VmContext.zkml_proof` is never supplied).
    ///
    /// REMAINING GAP, deliberately out of scope this wave: a real succinct
    /// proof system (a SNARK/STARK circuit over the quantized forward pass)
    /// so verifiers could check a huge model without running it. Until then
    /// [`crate::zkml::MAX_ZKML_MODEL_PARAMS`] bounds what one registration can
    /// make every node re-execute.
    SysCallVerifyZkMlReexec {
        model_id: [u8; 32],
        proof: Box<crate::zkml::ZkMlProof>,
    },
    // APPEND, never insert above: same bincode-discriminant rule as every
    // variant above (see the comment on `SysCallSubmitPriceFeed`).
    /// §2 zkML: register `model` under `model_id` in the committed model
    /// registry, which is what makes a later `SysCallVerifyZkMlReexec` a
    /// CONSENSUS statement instead of a per-node opinion.
    ///
    /// Permissionless and APPEND-ONLY (first writer wins): an already
    /// registered id cannot be re-registered, so the weights a proof is
    /// checked against can never be swapped after the fact. The model is
    /// validated (`QuantizedLinearModel::validate`) and bounded
    /// (`MAX_ZKML_MODEL_PARAMS`) BEFORE it joins the registry, so a malformed
    /// or unbounded model can never reach the re-execution path. The registry
    /// is clone-committed: a later revert, out-of-gas or failed settlement
    /// discards the registration along with everything else the payload did,
    /// and the registry is folded into the state root conditionally (empty
    /// registry = zero digest bytes, `COMMITMENT_VERSION` untouched).
    SysCallRegisterZkMlModel {
        model_id: [u8; 32],
        model: Box<crate::zkml::QuantizedLinearModel>,
    },
    // APPEND, never insert above: same bincode-discriminant rule as every
    // variant above (see the comment on `SysCallSubmitPriceFeed`).
    // §2 zkML, the SPEC half: two opcodes (37 then 38) so a proof over the
    // quantized forward pass can be checked on chain against a REGISTERED
    // specification of that model.
    //
    // ⚠️ HONESTY (audit W8.3 / production blocker A5): the older name of this
    // pair said "Groth16" and "SUCCINCT". Neither was true, and the code was
    // changed to match reality: the registered "verifying key" was never a
    // pairing-based key (it is the model's constrained format plus a shape
    // plus a free-form setup LABEL), and the "succinct" verifier re-executed
    // the whole model, so it was neither succinct nor cheaper than the
    // re-execution path. The opcodes are now named for what they do.
    //
    // WHY TWO OPCODES: the spec is per-model state (it binds the exact
    // weights - see `crate::zkml_attestation`), so it must be committed before
    // any proof can name it. Registration reuses the model registry's
    // append-only discipline (first writer wins, never overwritten);
    // verification mirrors `SysCallVerifyZkMlReexec`'s handler shape
    // (lookup → hash match → charge → check, failure reverts).
    //
    // WHEN TO USE WHICH VERIFY: BOTH re-execute the model. Use
    // `SysCallVerifyZkMlReexec` when the model is registered but no spec is;
    // use `SysCallVerifyZkMlAttestation` when you also want the proof bound
    // to a registered spec hash and a registered I/O shape. Both revert the
    // whole transaction on failure. NEITHER is a zero-knowledge proof.
    /// §2 zkML: attach a VERIFICATION SPEC to an ALREADY-REGISTERED model.
    ///
    /// ⚠️ HONESTY (audit W8.3 / production blocker A5): what this registers is
    /// **NOT a Groth16 verifying key**. It is the model's *constrained format*
    /// (the serialized weights/biases/shape the verifier must reproduce) plus
    /// the operator's I/O shape and a free-form `setup_attestation` LABEL.
    /// There is no circuit, no proving key, no toxic waste and no ceremony:
    /// the "setup" is a string the registrant chooses, and the only thing the
    /// chain does with it is refuse the documented test-only prefix.
    ///
    /// Calls `ZkMlModelRegistry::register_spec`: the id must exist, no spec may
    /// be present yet, the model must satisfy the constrained format (i8
    /// weights / u16 inputs / bounded accumulator - legacy unbounded models are
    /// refused here but keep their re-execution path), and the spec must
    /// parse, hash to `spec_hash` and pin this model's I/O shape.
    SysCallRegisterZkMlSpec {
        model_id: [u8; 32],
        spec: Box<crate::zkml_attestation::ModelSpec>,
    },
    // APPEND, never insert above: same bincode-discriminant rule as every
    // variant above (see the comment on `SysCallSubmitPriceFeed`).
    /// §2 zkML: verify an INFERENCE ATTESTATION against the spec registered
    /// on chain under `model_id`.
    ///
    /// ⚠️ HONESTY (audit W8.3 / production blocker A5): **this is NOT a
    /// SNARK, NOT a STARK, and NOT zero-knowledge.** The verifier
    /// RE-EXECUTES the whole quantized forward pass from the registered spec
    /// and compares the outputs and the Merkle trace root — the same work
    /// [`crate::zkml::ZkMlProof::verify_inference_against`] does on the
    /// re-execution path. There is no succinctness (verification costs what
    /// the model costs), no hiding (the inputs and outputs are in the clear),
    /// and no trusted setup.
    ///
    /// What it DOES give over the re-execution path is a registry-layer
    /// binding that the plain re-execution path does not have: the proof must
    /// name BOTH the registered model's hash and the registered spec's hash,
    /// and the public I/O shape must match the registered spec. Both are
    /// checked before any work is done.
    ///
    /// The handler: fetches the record from the committed registry, requires a
    /// registered spec, hash-matches `proof.model_hash` (against the
    /// registered model) and `proof.spec_hash` (against the registered spec),
    /// shape-matches the public I/O, and calls
    /// [`crate::zkml_attestation::verify_attestation`]. A failed check
    /// reverts the whole transaction, like every other refusal opcode here.
    ///
    /// The machine-readable statement of what this opcode is and is not lives
    /// in [`crate::zkml::zkml_capabilities`] and is served over RPC as
    /// `stell_zkmlCapabilities`.
    SysCallVerifyZkMlAttestation {
        model_id: [u8; 32],
        proof: Box<crate::zkml_attestation::AttestationProof>,
    },
    // APPEND, never insert above: same bincode-discriminant rule as every
    // variant above (see the comment on `SysCallSubmitPriceFeed`).
    /// Create a new fungible token. Permissionless: anyone may create any
    /// number of tokens; the id commits (creator, name, symbol, registry
    /// nonce) so squatting a KNOWN id is impossible (the nonce is chain
    /// state, not caller-chosen) while re-creating the same (name, symbol)
    /// yields a DISTINCT token, never a overwrite.
    ///
    /// The caller becomes the minter and is credited the full
    /// `initial_supply` (a zero supply creates an empty mintable token).
    /// `max_supply`, when set, caps all future mints including this one.
    /// Invalid metadata (empty/oversize name/symbol, decimals > 18,
    /// supply above cap) reverts the whole transaction, like every other
    /// refusal opcode here.
    SysCallTokenCreate {
        name: String,
        symbol: String,
        decimals: u8,
        initial_supply: u64,
        max_supply: Option<u64>,
    },
    // APPEND, never insert above: same bincode-discriminant rule as every
    // variant above (see the comment on `SysCallSubmitPriceFeed`).
    // ENFORCED confidential transfer (audit 2026-10-06, F-A fix): the V1
    // opcode above checked only the group equation, so wrapped/negative
    // values and anyone's commitments inflated the pool. V2 carries a range
    // proof per commitment (verified BEFORE anything mutates) and the state
    // machine requires every input to be recorded as owned by the sender
    // (see `ConfidentialState.owned`). The V1 variant is DISABLED (its
    // handler reverts) — payloads using it must migrate to V2.
    SysCallConfidentialTransfer2 {
        recipient: [u8; 32],
        transfer: Box<crate::crypto_privacy::ConfidentialTransfer>,
        input_ranges: Vec<crate::crypto_privacy::RangeProof>,
        output_ranges: Vec<crate::crypto_privacy::RangeProof>,
    },
    // APPEND, never insert above: same bincode-discriminant rule.
    /// Shield entry: move native STELL into the shielded pool. The commitment
    /// must open EXACTLY to `amount` (recomputed in the handler — a range
    /// proof cannot bind a value, only an opening can), and the output is
    /// recorded as owned by the sender. The native debit (sender ->
    /// [`SHIELD_ESCROW`][crate::crypto_privacy::SHIELD_ESCROW]) settles in
    /// the engine on the SUCCESS arm via the transfers channel, so a failed
    /// debit reverts the recording with everything else.
    SysCallConfidentialShield {
        commitment: [u8; 32],
        amount: u64,
        blinding: [u8; 32],
    },
    // APPEND, never insert above: same bincode-discriminant rule.
    /// Unshield exit: retire owned inputs by revealing their openings and
    /// release the matching native value from
    /// [`SHIELD_ESCROW`][crate::crypto_privacy::SHIELD_ESCROW]. Privacy ends
    /// at exit by design (amounts are public here, like transparent deposits
    /// into shielded pools elsewhere). The native credit settles in the
    /// engine via the payouts channel on the SUCCESS arm; escrow
    /// insufficiency reverts the retirement with everything else.
    SysCallConfidentialUnshield {
        inputs: Vec<crate::crypto_privacy::UnshieldInput>,
    },
    // APPEND, never insert above: same bincode-discriminant rule.
    /// Rotate a validator's consensus key (foreign-validator operations):
    /// move the entire staking record from `old_validator` to
    /// `new_validator` atomically. Only the old key itself may authorize
    /// (`ctx.sender` must equal `old_validator`); the new key must not
    /// already be a validator (no merging). Slashing/downtime history
    /// carries over (no laundering by rekeying). Moves no coins.
    SysCallRotateValidatorKey {
        old_validator: [u8; 32],
        new_validator: [u8; 32],
    },
    // APPEND, never insert above: same bincode-discriminant rule.
    /// Begin unbonding the caller's delegation with a validator (E1 fix).
    /// Moves `amount` of the sender's delegated position into a maturing
    /// unbonding entry (releasable after cooldown via `SysCallUndelegate`).
    /// The old `SysCallUndelegate` tried to do this job with swapped lookup
    /// args and no amount, bricking delegator exits AND double-paying on any
    /// naive fix — hence the split: begin here, withdraw there, each
    /// consuming exactly what it touches.
    SysCallBeginUndelegate {
        validator: [u8; 32],
        amount: u64,
    },
    // APPEND, never insert above: same bincode-discriminant rule as every
    // variant above (see the comment on `SysCallSubmitPriceFeed`). Appending
    // is what keeps every already-signed payload and every pinned tx hash
    // byte-identical while an old node's decoder fails closed on these bytes.
    /// Claim accrued rewards for the sender's delegation with `validator`
    /// (E8: the ledger's `claim_delegator_rewards` had no opcode reaching it,
    /// so delegator rewards were unclaimable on chain while the validator's
    /// own `SysCallClaimRewards` existed).
    ///
    /// Pays out of the rewards pool via `ctx.payouts` (E2: never out of
    /// bonded principal), exactly like the
    /// `SysCallUndelegate` withdraw arm: the consumed amount leaves the ledger
    /// (removed, not zeroed-in-place) and moves once. Nothing claimable (or
    /// no staking ledger wired in) reverts with a clear reason instead of a
    /// silent no-op.
    SysCallClaimDelegatorRewards {
        validator: [u8; 32],
    },
    // APPEND, never insert above: same bincode-discriminant rule.
    /// Verify a post-quantum or hybrid signature (Falcon-512, ML-DSA-44, Hybrid).
    /// Discriminant 46 (appended, never inserted above).
    SysCallVerifyPqSignature {
        scheme_id: u8,
        pubkey: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
    },
    // APPEND, never insert above: same bincode-discriminant rule as every
    // variant above (see the comment on `SysCallSubmitPriceFeed`). Appending
    // is what keeps every already-signed payload and every pinned tx hash
    // byte-identical while an old node's decoder fails closed on these bytes.
    /// Withdraw matured SELF-BOND for `validator` (M1: the ledger's
    /// `withdraw` had no opcode reaching it, so unbonded self-bond sat in
    /// `withdrawable` forever while the delegator-side twin
    /// (`SysCallUndelegate`) existed).
    ///
    /// Pays out of the staking pool via `ctx.payouts` (never minted),
    /// exactly like the `SysCallUndelegate` withdraw arm: the consumed
    /// amount leaves the ledger (removed, not zeroed-in-place) and moves
    /// once. Only the validator itself may call (`ctx.sender` must equal
    /// `validator`). UNBONDING-PERIOD MATURED ONLY: `withdraw` reads the
    /// `withdrawable` map, which `process_unbonding` fills only once
    /// `release_at` passes — immature funds revert here (fail-closed)
    /// instead of paying early. Nothing withdrawable reverts with a clear
    /// reason instead of a silent no-op.
    SysCallWithdrawSelfBond {
        validator: [u8; 32],
    },
    // APPEND, never insert above: same bincode-discriminant rule as every
    // variant above (see the comment on `SysCallSubmitPriceFeed`). Appending
    // is what keeps every already-signed payload and every pinned tx hash
    // byte-identical while an old node's decoder fails closed on these bytes
    // (it rejects the whole block) instead of misreading them.
    //
    // SCOPE NOTE: this variant is the block-carriage half of the
    // equivocation-slash wiring (audit O1/F4), added here because the
    // evidence envelope must ride the block BODY — `Block` is
    // bincode-frozen (no new field without a migration break) and the
    // QC-sentinel alternative was rejected. It is a PURE CARRIER: the
    // handler below verifies the envelope and reverts on invalid evidence
    // (fail-closed, reporter wastes gas), but moves NO coins and touches
    // NO ledger state. The slash itself fires once per block at
    // `InMemoryStateEngine::apply_block_transition` (step 5b), which scans
    // the decided block for this opcode, re-verifies every envelope from
    // block bytes, dedupes per offense in the staking ledger, burns 5% and
    // debits STAKING_POOL — so every route (finalize/adopt/walk/replay/
    // reorg) derives one verdict from one block and cannot fork.
    /// Report consensus equivocation (double-sign) for deterministic
    /// in-block slashing. Permissionless: ANY funded account may report
    /// (pays gas like any transaction); the evidence names the OFFENDER,
    /// never the reporter, so no authorization check applies.
    ///
    /// The envelope carries BOTH conflicting votes fully, so every node
    /// re-verifies from block bytes alone (no gossip, no external data).
    /// An invalid envelope (bad shape, forged signature, unknown voter,
    /// same target, oversize) reverts the transaction with a clear reason
    /// instead of succeeding silently; valid-but-duplicate evidence
    /// succeeds here and burns 0 at the block step via ledger dedup.
    SysCallReportEquivocation {
        evidence: Box<crate::consensus::EquivocationEvidence>,
    },
    // APPEND, never insert above: same bincode-discriminant rule as every
    // variant above (see the comment on `SysCallSubmitPriceFeed`). Appending
    // is what keeps every already-signed payload and every pinned tx hash
    // byte-identical while an old node's decoder fails closed on these bytes
    // (it rejects the whole block) instead of misreading them.
    //
    // SCOPE NOTE: this variant is the POST-QUANTUM arm of the
    // equivocation-slash wiring (audit O1/F4). Where the Ed25519 opcode
    // above is a PURE CARRIER (the block step does the slash), this one
    // SLASHES IN THE VM: the handler calls
    // `StakingLedger::slash_pq_equivocation` on the clone-committed ledger
    // and hands the burned amount to the engine, which debits STAKING_POOL
    // by exactly that amount inside the same undo-protected native
    // settlement as every other movement. The reason is the PQ-specific
    // key resolution: the signature is verified against the accused
    // validator's REGISTERED post-quantum key (the ledger's
    // `validator_pq_keys`), so the verdict depends on committed ledger
    // state that only the ledger itself can resolve.
    /// Report POST-QUANTUM equivocation (a PQ double-sign) for on-chain
    /// slashing. Permissionless: ANY funded account may report (pays gas
    /// like any transaction); the evidence names the OFFENDER, never the
    /// reporter, so no authorization check applies.
    ///
    /// The envelope carries BOTH conflicting votes in compact form (the
    /// height, the round, the vote kind, the two targets and the two
    /// signatures), so every node re-verifies from block bytes alone. Both
    /// signatures are checked against the accused validator's REGISTERED
    /// post-quantum key (Falcon-512 / hybrid), falling back to Ed25519 with
    /// the validator id as the public key when no PQ key is registered.
    ///
    /// Fail-closed: an invalid envelope (same target, forged signature,
    /// unknown voter, oversize) REVERTS the transaction with a clear reason
    /// instead of succeeding silently — the reporter wastes gas and NOTHING
    /// else moves. Valid-but-duplicate evidence succeeds and burns 0 (the
    /// per-offense dedup key is consumed on first processing, so the same
    /// offense burns exactly once per chain).
    SysCallReportPqEquivocation {
        evidence: Box<crate::staking::CompactPqEquivocationEvidence>,
    },
    // APPEND, never insert above: same bincode-discriminant rule as every
    // variant above (see the comment on `SysCallSubmitPriceFeed`). Appending
    // is what keeps every already-signed payload and every pinned tx hash
    // byte-identical while an old node's decoder fails closed on these bytes.
    //
    /// Call a WASM contract method with SEVERAL arguments.
    ///
    /// `SysCallCallContract` carries a single `i64` parameter, which forced
    /// every multi-parameter method to pack its arguments by hand
    /// (`from * 100_000_000 + to * 100_000 + amount`). This variant carries
    /// the arguments as an ordered list instead, so the contract's own ABI
    /// manifest defines the parameter order and no client has to guess it.
    ///
    /// The dispatch is by exact arity: the contract decides how many
    /// parameters a method takes and the caller must supply exactly that
    /// many.
    SysCallCallContractArgs {
        contract: [u8; 32],
        method: Vec<u8>,
        args: Vec<i64>,
        /// The canonical ABI encoding of the arguments, handed to the contract
        /// through `host.calldata` so blob parameters (addresses, bytes,
        /// strings) are readable from the contract's memory. Empty for a call
        /// that carries no blob.
        calldata: Vec<u8>,
    },
    // APPEND, never insert above: same bincode-discriminant rule as every
    // variant above (see the comment on `SysCallSubmitPriceFeed`). Appending
    // is what keeps every already-signed payload and every pinned tx hash
    // byte-identical while an old node's decoder fails closed on these bytes.
    //
    // SCOPE NOTE: this variant is the block-carriage half of the
    // proposal-equivocation slash wiring (P3-EQ-ESCAPE variant 2). Like the
    // Ed25519 vote report it is a PURE CARRIER: the handler below verifies
    // the envelope and reverts on invalid evidence (fail-closed, reporter
    // wastes gas), but moves NO coins and touches NO ledger state. The slash
    // itself fires once per block at `InMemoryStateEngine::apply_block_transition`,
    // which scans the decided block for this opcode, re-verifies every
    // envelope from block bytes, dedupes per offense in the staking ledger,
    // burns 5% and debits STAKING_POOL — so every route (finalize/adopt/
    // walk/replay/reorg) derives one verdict from one block and cannot fork.
    /// Report PROPOSAL equivocation (double-propose) for deterministic
    /// in-block slashing. Permissionless: ANY funded account may report
    /// (pays gas like any transaction); the evidence names the OFFENDER,
    /// never the reporter, so no authorization check applies.
    ///
    /// The envelope carries BOTH conflicting blocks fully, so every node
    /// re-verifies from block bytes alone (no gossip, no external data).
    /// An invalid envelope (bad shape, forged proposer signature, unknown
    /// proposer, same body twice, oversize) reverts the transaction with a
    /// clear reason instead of succeeding silently; valid-but-duplicate
    /// evidence succeeds here and burns 0 at the block step via ledger dedup.
    SysCallReportProposalEquivocation {
        evidence: Box<crate::consensus::ProposalEquivocationEvidence>,
    },
    // APPEND, never insert above: same bincode-discriminant rule as every
    // variant above (see the comment on `SysCallSubmitPriceFeed`).
    //
    /// Bond (or top up) with an EXPLICIT commission at registration time.
    /// Same floor, funding and pool discipline as [`OpCode::SysCallStake`]:
    /// the amount must be positive, covered by the sender's balance, and at
    /// or above the governed minimum; the bonded value moves into
    /// STAKING_POOL. The difference is the commission: a NEW validator bonds
    /// with `commission_bps` (validated `<= 10_000`, else the transaction
    /// reverts) instead of the governance default, while a top-up to an
    /// EXISTING validator keeps the commission it registered with —
    /// commission is IMMUTABLE after bonding (the ledger exposes no setter,
    /// and `add_bond` never touches it). A wallet that wants the default
    /// keeps using `SysCallStake`; a wallet that wants to compete on fees
    /// mints this variant.
    SysCallStakeWithCommission {
        validator: [u8; 32],
        amount: u64,
        commission_bps: u64,
    },
}

/// One actor send the VM accepted, handed to the ENGINE through
/// [`Svm::execute_with_confidential_and_sends`].
///
/// The VM has no account map, so it can only validate a send (bounce rule,
/// prepaid gas, affordability against its balance mirror) and record it; the
/// engine debits the sender and enqueues the message when the transaction
/// commits (`InMemoryStateEngine::settle_actor_sends`), and the mailbox pass
/// settles the sends a DELIVERED body produced the same way. Collected through
/// an explicit sink rather than a `VmContext` field so every existing
/// `VmContext` literal (engine + tests) stays source-compatible.
#[derive(Clone, Debug)]
pub struct ActorSendRequest {
    pub recipient: [u8; 32],
    pub value: u64,
    pub body: Vec<OpCode>,
    pub bounce: bool,
    pub gas_budget: u64,
}

#[derive(Clone, Debug, Default)]
pub struct VmState {
    pub stack: Vec<u64>,
    pub gas_remaining: u64,
    pub gas_consumed: u64,
    pub registers: [u64; 8],
    pub memory: HashMap<u32, Vec<u8>>,
    pub halted: bool,
}

pub struct VmContext<'a> {
    pub sender: [u8; 32],
    pub balance: u64,
    pub orderbooks: Option<&'a mut HashMap<u32, OrderbookActor>>,
    pub patricia_trie: Option<&'a PatriciaTrie>,
    pub session_auth: Option<&'a mut SessionKeyAuthorization>,
    /// On-chain session-key registry, wired ONLY for payloads that can touch
    /// it (`execute_payload` clones it in when the payload carries a
    /// `SysCallRevokeSession`). The engine commits the working copy back only
    /// after the whole transaction succeeds, so a revoke - like every other
    /// payload effect - dies with a revert, an out-of-gas, or a failed
    /// settlement instead of revoking anything on a transaction that did not
    /// apply. `None` = direct `Svm::execute` callers: the syscall then reverts.
    pub session_keys: Option<&'a mut crate::zkml::SessionKeyRegistry>,
    /// The proof for the LEGACY `OpCode::SysCallVerifyZkMl` (structural check
    /// only, and NOT sound - see that opcode's docs).
    ///
    /// Deliberately kept, and deliberately never supplied: no transport fills
    /// it (`execute_payload` passes `None`) and the legacy handler reverts
    /// unconditionally anyway, so the structural-only check cannot be reached
    /// from any opcode. The reachable, sound §2 path is
    /// `OpCode::SysCallVerifyZkMlReexec`, which CARRIES its proof in the payload
    /// and fetches its model from the committed registry - the registry rides
    /// into the VM as an `execute_inner` parameter (like the shielded ledger
    /// and the actor-send sink), not as a context field, so every existing
    /// `VmContext` literal stays source-compatible.
    pub zkml_proof: Option<&'a ZkMlProof>,
    pub timestamp: u64,
    pub trades: Vec<TradeExecution>,
    pub transfers: Vec<([u8; 32], u64)>,
    /// On-chain fungible token registry (STS standard). Mutations are atomic:
    /// they are committed back only if the whole VM execution succeeds.
    pub token_registry: Option<&'a mut TokenRegistry>,
    pub token_events: Vec<TokenEvent>,
    /// On-chain WASM contract registry. Mutations are atomic (clone-commit):
    /// a later revert or out-of-gas discards deploys/pauses from this call.
    pub contracts: Option<&'a mut crate::contract::ContractRegistry>,
    /// On-chain staking ledger. Atomic (clone-commit) like the other domains: a
    /// bond is discarded if the rest of the transaction reverts, so a partially
    /// applied stake can never join the validator set.
    pub staking: Option<&'a mut crate::staking::StakingLedger>,
    /// The committed Primary Market Maker plus the read-only inputs a PMM
    /// syscall needs (`None` = no PMM wired in: `SysCallPmmBuy`/`SysCallPmmSell`
    /// revert, the way the token syscalls do without a registry).
    ///
    /// `state` is clone-committed by the VM exactly like the staking ledger,
    /// so a later revert discards the curve advance along with the wUSDT
    /// movements - a half-applied swap can never reach the engine. `events`
    /// carries the NATIVE leg out for `execute_payload` to settle: the VM has
    /// no account map, so minting/burning STELL is the engine's job.
    pub pmm: Option<crate::pmm::PmmVmContext<'a>>,
    /// Minimum bond a SysCallStake accepts, resolved from governance before
    /// execution. A passed `SetMinValidatorBond` must actually gate new bonds, or
    /// the committed parameter is decorative.
    pub min_validator_bond: u64,
    /// Commission for a newly created validator bond, resolved from governance.
    pub default_commission_bps: u64,
    /// Value movements that are NOT paid for by the transaction sender:
    /// `(payer, beneficiary, amount)`. Used to pay staking rewards out of the
    /// rewards pool, where the sender has no stake in the debit.
    pub payouts: Vec<([u8; 32], [u8; 32], u64)>,
    /// Committed oracle state (trusted publishers, feeds, breaker latch).
    ///
    /// Unlike the other domains the VM writes this IN PLACE, because a gate
    /// that fires has to survive its own transaction: `execute_payload`
    /// restores the pre-payload snapshot when the payload fails, keeping only
    /// a tripped breaker latch (see `restore_oracle_after_failure`). A feed
    /// therefore never survives a revert, while the alarm always does.
    ///
    /// `None` = no oracle wired in (direct `Svm::execute` callers): the submit
    /// syscall then reverts and the order gates are skipped.
    pub oracle: Option<&'a mut crate::oracle::OracleState>,
}

#[derive(Debug)]
pub enum VmExecutionResult {
    Success {
        gas_used: u64,
        return_value: Option<u64>,
        new_balance: u64,
        trades: Vec<TradeExecution>,
        transfers: Vec<([u8; 32], u64)>,
        token_events: Vec<TokenEvent>,
        /// What the order syscalls did (placement + fills, cancellation), in
        /// program order. The engine settles escrow and moves the value for
        /// these in `execute_payload`, on both apply paths. The book itself is
        /// already committed by the VM's clone-commit; without this hand-off
        /// the fills moved nothing and the escrow lifecycle was unreachable.
        clob_events: Vec<ClobEvent>,
        /// (payer, beneficiary, amount) movements funded by someone else
        payouts: Vec<([u8; 32], [u8; 32], u64)>,
        /// Native coins BURNED by the payload, as `(account, amount)`: the
        /// amount LEAVES that account and is destroyed (it is credited to
        /// nobody). Today the only producer is the post-quantum
        /// equivocation slash (`OpCode::SysCallReportPqEquivocation`), which
        /// burns the slashed stake out of the staking pool.
        ///
        /// The VM has no account map, so it cannot move coins itself: it
        /// REPORTS the burn and the engine settles it inside the same
        /// undo-protected native commit as every other movement (a refused
        /// transaction then burns nothing, and the ledger-side slash is
        /// rolled back with the rest of the payload).
        burns: Vec<([u8; 32], u64)>,
        /// Outbound messages emitted by contracts during execution via host.send_message
        outbound_messages: Vec<crate::contract::ContractMessage>,
        /// Contract events emitted by host.emit during execution
        events: Vec<crate::contract::ContractEvent>,
    },
    OutOfGas,
    Reverted(String),
}

impl VmExecutionResult {
    pub fn events(&self) -> &[crate::contract::ContractEvent] {
        match self {
            VmExecutionResult::Success { events, .. } => events,
            _ => &[],
        }
    }
}

/// Clone-on-first-use for the VM's clone-commit working copies.
///
/// The block path wires every domain registry into each payload's context, so
/// an EAGER working copy would clone all five registries per transaction even
/// when the payload never touches them (a transfer pays for a token-registry,
/// orderbook, contract, staking AND curve clone it never uses - the
/// `registry_wired_overhead` bench shows ~270ns/call for a 1-token registry
/// alone, scaling with registry size). Instead each domain arm calls this on
/// first touch: `None` source (direct `Svm::execute` callers) leaves the slot
/// `None` and the arm fails closed exactly as before; a present source is
/// cloned once, and the commit step at the end only writes back slots that
/// were actually created - an untouched domain is never written back, which
/// is trivially identical to writing back an unmodified clone.
#[inline(always)]
fn ensure_working<T: Clone>(slot: &mut Option<T>, src: Option<&T>) {
    if slot.is_none() {
        if let Some(s) = src {
            *slot = Some(s.clone());
        }
    }
}

pub struct Svm;

impl Svm {
    /// Execute `instructions` against every domain wired into `ctx`.
    ///
    /// The shielded ledger is deliberately NOT one of them: this entry point
    /// passes `None`, so a payload carrying `SysCallConfidentialTransfer`
    /// reverts with "confidential state not available" - the same fail-closed
    /// shape as a token syscall with no registry. Block application uses
    /// [`Svm::execute_with_confidential_and_sends`], which hands the engine's
    /// working copy of the `ConfidentialState` (and the actor-send sink) in.
    pub fn execute(
        instructions: &[OpCode],
        gas_limit: u64,
        ctx: &mut VmContext,
    ) -> VmExecutionResult {
        Self::execute_inner(instructions, gas_limit, ctx, None, None, None, None)
    }

    /// The same VM, plus the shielded ledger `SysCallConfidentialTransfer`
    /// applies against.
    ///
    /// `confidential` is a working COPY owned by the caller
    /// (`InMemoryStateEngine::execute_payload` clones the committed state in,
    /// exactly like the session registry): the handler mutates that copy in
    /// place, and the caller writes it back only if the whole transaction -
    /// including every settlement step after the VM returns - applied. A
    /// revert, an out-of-gas or a failed settlement therefore discards the
    /// transfer along with everything else the payload did.
    pub fn execute_with_confidential(
        instructions: &[OpCode],
        gas_limit: u64,
        ctx: &mut VmContext,
        confidential: Option<&mut crate::crypto_privacy::ConfidentialState>,
    ) -> VmExecutionResult {
        Self::execute_inner(instructions, gas_limit, ctx, confidential, None, None, None)
    }

    /// The block-path VM: the shielded ledger, the actor-send sink AND the §2
    /// zkML model registry.
    ///
    /// `sends` collects every `SysCallActorSend` this run EXECUTED, in
    /// program order, so the engine settles exactly those - not every send
    /// opcode in the byte slice (opcodes after a `Halt` never ran). A run
    /// with no sink wired fails closed on `SysCallActorSend`, the same way a
    /// token syscall fails without a registry: `Svm::execute` callers have no
    /// engine to enqueue into, so accepting the send there would be a silent
    /// no-op on a message somebody paid for.
    ///
    /// `zkml_models` is the committed §2 model registry, wired ONLY for
    /// payloads that carry a zkML opcode (`execute_payload` clones it in when
    /// the payload has `SysCallVerifyZkMlReexec` or `SysCallRegisterZkMlModel`,
    /// and writes it back only on a fully applied transaction). A run with no
    /// registry wired fails closed on BOTH opcodes - the same shape as a token
    /// syscall with no registry - which is why an actor body delivered by the
    /// mailbox pass (no registries in scope, by design) can never register or
    /// verify a model.
    pub fn execute_with_confidential_and_sends(
        instructions: &[OpCode],
        gas_limit: u64,
        ctx: &mut VmContext,
        confidential: Option<&mut crate::crypto_privacy::ConfidentialState>,
        sends: &mut Vec<ActorSendRequest>,
        zkml_models: Option<&mut crate::zkml::ZkMlModelRegistry>,
    ) -> VmExecutionResult {
        Self::execute_inner(
            instructions,
            gas_limit,
            ctx,
            confidential,
            Some(sends),
            zkml_models,
            None,
        )
    }

    /// The block-path VM with a range-proof pre-verification cache: the same
    /// execution as [`Svm::execute_with_confidential_and_sends`], except the
    /// `SysCallConfidentialTransfer2` handler may skip re-verifying range
    /// proofs for bundles the engine's parallel pre-pass already verified.
    ///
    /// `range_preverify` maps
    /// [`crate::crypto_privacy::confidential_transfer2_preverify_digest`] to
    /// the pre-pass verdict for that exact bundle. The cache covers ONLY the
    /// stateless proof check — ownership, spent-set, conservation and fee
    /// handling below run unconditionally, and a cache miss runs the full
    /// check exactly as the surgery-free path does. `None` (and every other
    /// entry point above, which passes `None`) is the single-transaction
    /// path: it never consults a cache.
    pub fn execute_with_confidential_and_sends_with_preverify(
        instructions: &[OpCode],
        gas_limit: u64,
        ctx: &mut VmContext,
        confidential: Option<&mut crate::crypto_privacy::ConfidentialState>,
        sends: &mut Vec<ActorSendRequest>,
        zkml_models: Option<&mut crate::zkml::ZkMlModelRegistry>,
        range_preverify: Option<&HashMap<[u8; 32], bool>>,
    ) -> VmExecutionResult {
        Self::execute_inner(
            instructions,
            gas_limit,
            ctx,
            confidential,
            Some(sends),
            zkml_models,
            range_preverify,
        )
    }

    fn execute_inner(
        instructions: &[OpCode],
        gas_limit: u64,
        ctx: &mut VmContext,
        mut confidential: Option<&mut crate::crypto_privacy::ConfidentialState>,
        mut sends: Option<&mut Vec<ActorSendRequest>>,
        mut zkml_models: Option<&mut crate::zkml::ZkMlModelRegistry>,
        range_preverify: Option<&HashMap<[u8; 32], bool>>,
    ) -> VmExecutionResult {
        // The operand stack starts WITHOUT an allocation: the hot benchmark
        // path (and most real payloads) may never push, and `Vec::new` only
        // allocates on the first push. Push-heavy programs pay one extra
        // doubling step at most versus a pre-sized buffer.
        let mut state = VmState {
            stack: Vec::new(),
            gas_remaining: gas_limit,
            gas_consumed: 0,
            registers: [0; 8],
            memory: HashMap::new(),
            halted: false,
        };

        let mut current_balance = ctx.balance;

        // Outbound messages emitted by contracts during call execution via host.send_message
        let mut outbound_messages: Vec<crate::contract::ContractMessage> = Vec::new();

        // Contract events emitted by host.emit during execution.
        let mut contract_events: Vec<crate::contract::ContractEvent> = Vec::new();

        // What the order syscalls did, in program order. Emitted only on
        // overall success (the engine never sees them for a reverted payload).
        let mut clob_events: Vec<ClobEvent> = Vec::new();

        // Atomic token state: cloned on FIRST token touch (see
        // `ensure_working`), committed back only on overall success. A later
        // revert or out-of-gas discards all token mutations (all-or-nothing).
        // Payloads that never touch tokens never pay the clone.
        let mut working_tokens: Option<TokenRegistry> = None;

        // Atomic orderbook state: same lazy clone-commit discipline. Without
        // this, a placed/cancelled order survived a later revert (leak); the
        // laziness only skips the clone for payloads with no order ops.
        let mut working_books: Option<HashMap<u32, OrderbookActor>> = None;

        // Atomic contract state: deploys/pauses are discarded on revert.
        let mut working_contracts: Option<crate::contract::ContractRegistry> = None;

        // Atomic staking state: a bond is discarded if the transaction reverts.
        let mut working_staking: Option<crate::staking::StakingLedger> = None;

        // Native coins burned by the payload (`(account, amount)`), reported
        // to the engine: the VM has no account map, so it cannot move coins
        // itself. Today only the PQ equivocation slash burns (out of the
        // staking pool).
        let mut burns: Vec<([u8; 32], u64)> = Vec::new();

        // Atomic PMM state: a curve advance is discarded if the transaction
        // reverts. Only the curve is cloned - the quote token id, the treasury
        // and the governed buffer are read-only inputs for this call.
        let mut working_pmm: Option<crate::pmm::PrimaryMarketMaker> = None;

        // Single dispatch: gas is charged INSIDE the match arm that executes
        // the opcode, from the same GAS_* constants / *_gas helpers that
        // `opcode_gas` reads. The old shape called `opcode_gas(op)` first -
        // a second full match over 35+ variants per opcode - which profiling
        // showed costing ~2/3 of the cached per-op time ([E] 1.57ns of 2.43ns).
        //
        // `gas_consumed` is NOT accumulated per opcode: every charge below
        // only decrements `gas_remaining`, and the consumed total is derived
        // once at success (`gas_limit - gas_remaining`). The two stay in lock
        // step because no other write touches either counter, so the reported
        // `gas_used` is bit-identical; `OutOfGas`/`Reverted` carry no gas.
        macro_rules! charge {
            ($cost:expr) => {{
                let cost: u64 = $cost;
                if state.gas_remaining < cost {
                    return VmExecutionResult::OutOfGas;
                }
                state.gas_remaining -= cost;
            }};
        }

        for op in instructions {
            if state.halted {
                break;
            }

            match op {
                OpCode::Nop => {
                    charge!(GAS_NOP);
                }
                OpCode::Push(val) => {
                    charge!(GAS_PUSH);
                    state.stack.push(*val);
                }
                OpCode::Pop => {
                    charge!(GAS_POP);
                    state.stack.pop();
                }
                OpCode::Add => {
                    charge!(GAS_ADD_SUB);
                    let b = state.stack.pop().unwrap_or(0);
                    let a = state.stack.pop().unwrap_or(0);
                    state.stack.push(a.saturating_add(b));
                }
                OpCode::Sub => {
                    charge!(GAS_ADD_SUB);
                    let b = state.stack.pop().unwrap_or(0);
                    let a = state.stack.pop().unwrap_or(0);
                    state.stack.push(a.saturating_sub(b));
                }
                OpCode::Mul => {
                    charge!(GAS_MUL_DIV);
                    let b = state.stack.pop().unwrap_or(0);
                    let a = state.stack.pop().unwrap_or(0);
                    state.stack.push(a.saturating_mul(b));
                }
                OpCode::Div => {
                    charge!(GAS_MUL_DIV);
                    let b = state.stack.pop().unwrap_or(1);
                    let a = state.stack.pop().unwrap_or(0);
                    if b == 0 {
                        state.stack.push(0);
                    } else {
                        state.stack.push(a / b);
                    }
                }
                OpCode::LoadBalance => {
                    charge!(GAS_LOAD_BALANCE);
                    state.stack.push(current_balance);
                }
                OpCode::Transfer { recipient, amount } => {
                    charge!(GAS_BASIC_TRANSFER);
                    if *amount > current_balance {
                        return VmExecutionResult::Reverted("Insufficient balance".to_string());
                    }
                    current_balance -= *amount;
                    ctx.transfers.push((*recipient, *amount));
                }
                OpCode::SysCallPlaceOrder {
                    pair_id,
                    is_buy,
                    price,
                    amount,
                } => {
                    charge!(GAS_ORDER_PLACE);
                    // Priority gates, checked BEFORE the order is accepted:
                    // breaker latch, USDT peg and deviation of the limit price
                    // from the committed oracle price. `gate_order` is the
                    // very same call `place_order_settled` makes, so the SVM
                    // and non-SVM entry points cannot disagree about what
                    // trading is allowed. A violation reverts the whole tx
                    // WITHOUT latching (E3: orders never trip the breaker).
                    if let Some(oracle) = ctx.oracle.as_deref() {
                        if let Err(e) = oracle.gate_order(*pair_id, *price) {
                            return VmExecutionResult::Reverted(e);
                        }
                    }
                    let side = if *is_buy {
                        OrderSide::Buy
                    } else {
                        OrderSide::Sell
                    };
                    let order_cost = if *is_buy {
                        let prod = (*price as u128) * (*amount as u128);
                        (prod / 1_000_000u128).min(u64::MAX as u128) as u64
                    } else {
                        *amount
                    };

                    if order_cost > current_balance {
                        return VmExecutionResult::Reverted(
                            "Insufficient balance for order".to_string(),
                        );
                    }

                    // First order op clones the book map; payloads without order
                    // ops never pay for it (see `ensure_working`).
                    ensure_working(&mut working_books, ctx.orderbooks.as_deref());
                    if let Some(books) = working_books.as_mut() {
                        let book = books
                            .entry(*pair_id)
                            .or_insert_with(|| OrderbookActor::new(*pair_id, 1000));
                        let (placed_order, trade_events) = book.submit_order_bounded(
                            ctx.sender,
                            side.clone(),
                            OrderType::Limit,
                            *price,
                            *amount,
                            ctx.timestamp,
                            MAX_MATCH_LEVELS,
                        );
                        // Charge gas per price level crossed (anti-griefing).
                        // If the extra gas cannot be paid, revert the whole call.
                        let level_gas = (trade_events.len() as u64).min(MAX_MATCH_LEVELS as u64)
                            * GAS_PER_MATCH_LEVEL;
                        if state.gas_remaining < level_gas {
                            return VmExecutionResult::OutOfGas;
                        }
                        state.gas_remaining -= level_gas;
                        // VM-local mirror of the escrow lock the engine will
                        // perform for this order (the lock can never exceed
                        // `order_cost`, so this stays conservative for any
                        // later opcode in the same payload).
                        current_balance -= order_cost;
                        ctx.trades.extend(trade_events.iter().cloned());
                        clob_events.push(ClobEvent::Place {
                            pair_id: *pair_id,
                            order_id: placed_order.order_id,
                            trader: ctx.sender,
                            side,
                            order_type: OrderType::Limit,
                            price: *price,
                            amount: *amount,
                            filled: placed_order.filled,
                            trades: trade_events,
                        });
                        state.stack.push(placed_order.order_id);
                    } else {
                        current_balance -= order_cost;
                        state.stack.push(1); // Default order id
                    }
                }
                OpCode::SysCallCancelOrder { order_id } => {
                    charge!(GAS_ORDER_CANCEL);
                    // Only the order's own trader may cancel it, and the refund
                    // goes to that trader, not the caller.
                    //
                    // Without the ownership check any third party could cancel any
                    // resting order for a trivial gas cost while the escrow record
                    // stayed in place. The victim could then never release it: the
                    // release path looks the order up in the book, the order is
                    // already gone, and the release silently does nothing. That
                    // stranded the full escrowed balance permanently.
                    //
                    // The equivalent check in the engine's own cancel path is at
                    // `state_engine.rs` "Only the order owner may cancel".
                    let mut cancelled: Option<u32> = None;
                    ensure_working(&mut working_books, ctx.orderbooks.as_deref());
                    if let Some(books) = working_books.as_mut() {
                        for (pair, book) in books.iter_mut() {
                            // Locate the trader without removing anything: the
                            // cancel below is the only thing that should mutate.
                            let owner = book
                                .bids
                                .values()
                                .chain(book.asks.values())
                                .flatten()
                                .find(|o| o.order_id == *order_id)
                                .map(|o| (o.trader, matches!(o.side, OrderSide::Sell)));
                            match owner {
                                None => continue,
                                Some((t, _)) if t != ctx.sender => {
                                    return VmExecutionResult::Reverted(
                                        "only the order owner may cancel it".to_string(),
                                    )
                                }
                                Some(_) => {}
                            }
                            if let Some(order) = book.cancel_order(*order_id) {
                                // The real refund is issued by the engine when it
                                // processes the Cancel event below (native for a
                                // sell, native-or-wUSDT for a buy - the VM cannot
                                // see the escrow map to know which). Mirror it in
                                // the VM-local balance only for the side whose
                                // asset is unambiguous: a sell refunds base STELL.
                                // For a buy the quote asset is unknown here, so
                                // staying un-credited is the conservative choice
                                // (it can only make a later opcode revert, never
                                // overdraw).
                                if matches!(order.side, OrderSide::Sell) {
                                    let refund = order.amount.saturating_sub(order.filled);
                                    current_balance = current_balance.saturating_add(refund);
                                }
                                cancelled = Some(*pair);
                                break;
                            }
                        }
                    }
                    if let Some(pair) = cancelled {
                        clob_events.push(ClobEvent::Cancel {
                            pair_id: pair,
                            order_id: *order_id,
                            trader: ctx.sender,
                        });
                    }
                    state.stack.push(if cancelled.is_some() { 1 } else { 0 });
                }
                OpCode::SysCallVerifyZkMl => {
                    charge!(GAS_ZKML_VERIFY);
                    // LEGACY, structural-only and therefore UNSOUND. It reads
                    // `ctx.zkml_proof`, which no transport ever supplies (the
                    // engine passes `None`), so it has always reverted here -
                    // but "always reverts because the field happens to be None"
                    // is not a property anybody should be able to weaken by
                    // wiring the field up. The unsound check is removed from
                    // the reachable surface entirely: the only zkML verification
                    // this VM can perform is `SysCallVerifyZkMlReexec`, which
                    // re-executes the registered model.
                    return VmExecutionResult::Reverted(
                        "legacy SysCallVerifyZkMl is structural-only (not sound) and has no \
                         transport: use SysCallVerifyZkMlReexec with a registered model"
                            .to_string(),
                    );
                }
                OpCode::SysCallPatriciaLookup(hash) => {
                    charge!(GAS_PATRICIA_LOOKUP);
                    let found = if let Some(trie) = ctx.patricia_trie {
                        trie.boc.get_cell(hash).is_some()
                    } else {
                        true
                    };
                    state.stack.push(if found { 1 } else { 0 });
                }
                OpCode::SysCallTokenTransfer {
                    token_id,
                    to,
                    amount,
                } => {
                    charge!(GAS_TOKEN_TRANSFER);
                    ensure_working(&mut working_tokens, ctx.token_registry.as_deref());
                    let Some(reg) = working_tokens.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Token registry not available".to_string(),
                        );
                    };
                    match reg.execute(
                        token_id,
                        ctx.sender,
                        TokenOp::Transfer {
                            to: *to,
                            amount: *amount,
                        },
                    ) {
                        Ok(ev) => {
                            ctx.token_events.push(ev);
                            state.stack.push(1);
                        }
                        Err(e) => {
                            return VmExecutionResult::Reverted(format!(
                                "token transfer failed: {e}"
                            ))
                        }
                    }
                }
                OpCode::SysCallTokenTransferFrom {
                    token_id,
                    from,
                    to,
                    amount,
                } => {
                    charge!(GAS_TOKEN_TRANSFER);
                    ensure_working(&mut working_tokens, ctx.token_registry.as_deref());
                    let Some(reg) = working_tokens.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Token registry not available".to_string(),
                        );
                    };
                    match reg.execute(
                        token_id,
                        ctx.sender,
                        TokenOp::TransferFrom {
                            from: *from,
                            to: *to,
                            amount: *amount,
                        },
                    ) {
                        Ok(ev) => {
                            ctx.token_events.push(ev);
                            state.stack.push(1);
                        }
                        Err(e) => {
                            return VmExecutionResult::Reverted(format!(
                                "token transferFrom failed: {e}"
                            ))
                        }
                    }
                }
                OpCode::SysCallTokenMint {
                    token_id,
                    to,
                    amount,
                } => {
                    charge!(GAS_TOKEN_MINT);
                    ensure_working(&mut working_tokens, ctx.token_registry.as_deref());
                    let Some(reg) = working_tokens.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Token registry not available".to_string(),
                        );
                    };
                    match reg.execute(
                        token_id,
                        ctx.sender,
                        TokenOp::Mint {
                            to: *to,
                            amount: *amount,
                        },
                    ) {
                        Ok(ev) => {
                            ctx.token_events.push(ev);
                            state.stack.push(1);
                        }
                        Err(e) => {
                            return VmExecutionResult::Reverted(format!("token mint failed: {e}"))
                        }
                    }
                }
                OpCode::SysCallTokenBurn {
                    token_id,
                    from,
                    amount,
                } => {
                    charge!(GAS_TOKEN_BURN);
                    ensure_working(&mut working_tokens, ctx.token_registry.as_deref());
                    let Some(reg) = working_tokens.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Token registry not available".to_string(),
                        );
                    };
                    match reg.execute(
                        token_id,
                        ctx.sender,
                        TokenOp::Burn {
                            from: *from,
                            amount: *amount,
                        },
                    ) {
                        Ok(ev) => {
                            ctx.token_events.push(ev);
                            state.stack.push(1);
                        }
                        Err(e) => {
                            return VmExecutionResult::Reverted(format!("token burn failed: {e}"))
                        }
                    }
                }
                OpCode::SysCallTokenApprove {
                    token_id,
                    spender,
                    amount,
                } => {
                    charge!(GAS_TOKEN_APPROVE);
                    ensure_working(&mut working_tokens, ctx.token_registry.as_deref());
                    let Some(reg) = working_tokens.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Token registry not available".to_string(),
                        );
                    };
                    match reg.execute(
                        token_id,
                        ctx.sender,
                        TokenOp::Approve {
                            spender: *spender,
                            amount: *amount,
                        },
                    ) {
                        Ok(ev) => {
                            ctx.token_events.push(ev);
                            state.stack.push(1);
                        }
                        Err(e) => {
                            return VmExecutionResult::Reverted(format!(
                                "token approve failed: {e}"
                            ))
                        }
                    }
                }
                OpCode::SysCallTokenCreate {
                    name,
                    symbol,
                    decimals,
                    initial_supply,
                    max_supply,
                } => {
                    charge!(GAS_TOKEN_CREATE);
                    ensure_working(&mut working_tokens, ctx.token_registry.as_deref());
                    let Some(reg) = working_tokens.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Token registry not available".to_string(),
                        );
                    };
                    // `create_token` sets minter = caller and credits it the
                    // full initial supply; any metadata violation reverts.
                    let meta = crate::token::TokenMetadata {
                        name: name.clone(),
                        symbol: symbol.clone(),
                        decimals: *decimals,
                        total_supply: *initial_supply,
                        max_supply: *max_supply,
                        minter: [0u8; 32],
                        paused: false,
                        description: String::new(),
                    };
                    match reg.create_token(ctx.sender, meta, *initial_supply) {
                        Ok(id) => {
                            if *initial_supply > 0 {
                                ctx.token_events.push(TokenEvent::Mint {
                                    token_id: id,
                                    to: ctx.sender,
                                    amount: *initial_supply,
                                    new_total: *initial_supply,
                                });
                            }
                            state.stack.push(1);
                        }
                        Err(e) => {
                            return VmExecutionResult::Reverted(format!("token create failed: {e}"))
                        }
                    }
                }
                OpCode::SysCallTokenBalanceOf { token_id, account } => {
                    charge!(GAS_TOKEN_BALANCE);
                    let bal = if let Some(reg) = working_tokens.as_ref() {
                        reg.balance_of(token_id, account)
                    } else if let Some(reg) = ctx.token_registry.as_ref() {
                        reg.balance_of(token_id, account)
                    } else {
                        return VmExecutionResult::Reverted(
                            "Token registry not available".to_string(),
                        );
                    };
                    state.stack.push(bal);
                }
                OpCode::SysCallDeployContract { code } => {
                    charge!(contract_deploy_gas(code.len()));
                    ensure_working(&mut working_contracts, ctx.contracts.as_deref());
                    let Some(reg) = working_contracts.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Contract registry not available".to_string(),
                        );
                    };
                    match reg.deploy(ctx.sender, code.clone(), ctx.timestamp) {
                        Ok(_addr) => state.stack.push(1),
                        Err(e) => {
                            return VmExecutionResult::Reverted(format!(
                                "contract deploy failed: {e}"
                            ))
                        }
                    }
                }
                OpCode::SysCallCallContract {
                    contract,
                    method,
                    arg,
                } => {
                    // Wire caps BEFORE any clone/commit: an unbounded method
                    // name would otherwise force every node through a UTF-8
                    // scan + export lookup for fixed gas. Same fail-closed
                    // shape as the confidential IO caps above.
                    if method.len() > MAX_CONTRACT_METHOD_LEN {
                        return VmExecutionResult::Reverted(format!(
                            "contract call rejected: method name exceeds {MAX_CONTRACT_METHOD_LEN} bytes"
                        ));
                    }
                    charge!(contract_call_gas(method.len(), 1, 0));
                    ensure_working(&mut working_contracts, ctx.contracts.as_deref());
                    let Some(reg) = working_contracts.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Contract registry not available".to_string(),
                        );
                    };
                    let method = match std::str::from_utf8(method) {
                        Ok(m) => m,
                        Err(_) => {
                            return VmExecutionResult::Reverted(
                                "invalid contract method name".to_string(),
                            )
                        }
                    };
                    // The remaining gas bounds the wasmi fuel, so a contract can
                    // never consume more compute than the caller paid for.
                    let call_ctx = crate::contract::ContractCallContext {
                        caller: ctx.sender,
                        value: 0,
                        block_time: ctx.timestamp,
                        block_hash: [0u8; 32],
                    };
                    match reg.call_with_context(
                        contract,
                        method,
                        *arg,
                        state.gas_remaining,
                        &call_ctx,
                    ) {
                        Ok(outcome) => {
                            if state.gas_remaining < outcome.fuel_used {
                                return VmExecutionResult::OutOfGas;
                            }
                            state.gas_remaining -= outcome.fuel_used;
                            state.stack.push(outcome.result as u64);
                            outbound_messages.extend(outcome.outbound_messages);
                            contract_events.extend(outcome.events);
                        }
                        Err(crate::contract::ContractError::OutOfFuel) => {
                            return VmExecutionResult::OutOfGas
                        }
                        Err(e) => {
                            return VmExecutionResult::Reverted(format!(
                                "contract call failed: {e}"
                            ))
                        }
                    }
                }
                OpCode::SysCallCallContractArgs {
                    contract,
                    method,
                    args,
                    calldata,
                } => {
                    // Wire caps BEFORE the registry clone below: an oversized
                    // method/calldata/args vector would otherwise force a full
                    // registry clone plus a UTF-8 scan for fixed gas. The
                    // contract layer re-checks arity; this early reject just
                    // avoids paying the clone for a call that cannot succeed.
                    if method.len() > MAX_CONTRACT_METHOD_LEN {
                        return VmExecutionResult::Reverted(format!(
                            "contract call rejected: method name exceeds {MAX_CONTRACT_METHOD_LEN} bytes"
                        ));
                    }
                    if calldata.len() > MAX_CONTRACT_CALLDATA_BYTES {
                        return VmExecutionResult::Reverted(format!(
                            "contract call rejected: calldata exceeds {MAX_CONTRACT_CALLDATA_BYTES} bytes"
                        ));
                    }
                    if args.len() > crate::contract::MAX_CONTRACT_CALL_ARGS {
                        return VmExecutionResult::Reverted(format!(
                            "contract call rejected: too many arguments (max {})",
                            crate::contract::MAX_CONTRACT_CALL_ARGS
                        ));
                    }
                    charge!(contract_call_gas(method.len(), args.len(), calldata.len()));
                    ensure_working(&mut working_contracts, ctx.contracts.as_deref());
                    let Some(reg) = working_contracts.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Contract registry not available".to_string(),
                        );
                    };
                    let method = match std::str::from_utf8(method) {
                        Ok(m) => m,
                        Err(_) => {
                            return VmExecutionResult::Reverted(
                                "invalid contract method name".to_string(),
                            )
                        }
                    };
                    // The remaining gas bounds the wasmi fuel, so a contract can
                    // never consume more compute than the caller paid for.
                    let call_ctx = crate::contract::ContractCallContext {
                        caller: ctx.sender,
                        value: 0,
                        block_time: ctx.timestamp,
                        block_hash: [0u8; 32],
                    };
                    match reg.call_with_context_args_calldata(
                        contract,
                        method,
                        args,
                        calldata,
                        state.gas_remaining,
                        &call_ctx,
                    ) {
                        Ok(outcome) => {
                            if state.gas_remaining < outcome.fuel_used {
                                return VmExecutionResult::OutOfGas;
                            }
                            state.gas_remaining -= outcome.fuel_used;
                            state.stack.push(outcome.result as u64);
                            outbound_messages.extend(outcome.outbound_messages);
                            contract_events.extend(outcome.events);
                        }
                        Err(crate::contract::ContractError::OutOfFuel) => {
                            return VmExecutionResult::OutOfGas
                        }
                        Err(e) => {
                            return VmExecutionResult::Reverted(format!(
                                "contract call failed: {e}"
                            ))
                        }
                    }
                }
                OpCode::SysCallStake { validator, amount } => {
                    charge!(GAS_STAKE_BOND);
                    ensure_working(&mut working_staking, ctx.staking.as_deref());
                    let Some(ledger) = working_staking.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Staking ledger not available".to_string(),
                        );
                    };
                    // The bond must be paid for out of the sender's real balance,
                    // otherwise anyone could claim validator power for free.
                    if *amount == 0 {
                        return VmExecutionResult::Reverted(
                            "stake amount must be positive".to_string(),
                        );
                    }
                    if *amount > current_balance {
                        return VmExecutionResult::Reverted(
                            "Insufficient balance to stake".to_string(),
                        );
                    }
                    // The bond IS the registration: an address that has never
                    // bonded becomes a validator here, and an existing one just
                    // tops up. That is what makes the validator set reachable
                    // without a permissioned off-chain list.
                    //
                    // Both the floor and the commission come from governance (resolved
                    // into the context before execution): a passed SetMinValidatorBond
                    // gates entry, and a passed SetDefaultCommissionBps prices new
                    // validators. The ledger's own hardcoded floor stays as the
                    // absolute minimum underneath.
                    if *amount < ctx.min_validator_bond {
                        return VmExecutionResult::Reverted(
                            "stake below the governed minimum".to_string(),
                        );
                    }
                    let applied = if ledger.validators.contains_key(validator) {
                        ledger.add_bond(*validator, *amount)
                    } else {
                        ledger.bond(*validator, *amount, ctx.default_commission_bps)
                    };
                    if let Err(e) = applied {
                        return VmExecutionResult::Reverted(format!("stake failed: {e}"));
                    }
                    current_balance -= *amount;
                    // Move the value into the staking pool so it is real, and so
                    // slashing has something to burn.
                    ctx.transfers.push((crate::staking::STAKING_POOL, *amount));
                    state.stack.push(1);
                }
                OpCode::SysCallStakeWithCommission {
                    validator,
                    amount,
                    commission_bps,
                } => {
                    charge!(GAS_STAKE_BOND);
                    ensure_working(&mut working_staking, ctx.staking.as_deref());
                    let Some(ledger) = working_staking.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Staking ledger not available".to_string(),
                        );
                    };
                    // Same funding discipline as `SysCallStake`: free power
                    // is never minted, and the governed floor gates entry.
                    if *amount == 0 {
                        return VmExecutionResult::Reverted(
                            "stake amount must be positive".to_string(),
                        );
                    }
                    if *amount > current_balance {
                        return VmExecutionResult::Reverted(
                            "Insufficient balance to stake".to_string(),
                        );
                    }
                    if *commission_bps > crate::staking::BPS_DENOMINATOR {
                        return VmExecutionResult::Reverted(format!(
                            "commission must be <= {} bps",
                            crate::staking::BPS_DENOMINATOR
                        ));
                    }
                    if *amount < ctx.min_validator_bond {
                        return VmExecutionResult::Reverted(
                            "stake below the governed minimum".to_string(),
                        );
                    }
                    // IMMUTABILITY: a new validator bonds with the
                    // transaction-supplied commission; an existing one tops
                    // up through `add_bond`, which never touches the
                    // registered commission. There is no path — here or
                    // anywhere in the ledger — that changes a validator's
                    // commission after bonding.
                    let applied = if ledger.validators.contains_key(validator) {
                        ledger.add_bond(*validator, *amount)
                    } else {
                        ledger.bond(*validator, *amount, *commission_bps)
                    };
                    if let Err(e) = applied {
                        return VmExecutionResult::Reverted(format!("stake failed: {e}"));
                    }
                    current_balance -= *amount;
                    ctx.transfers.push((crate::staking::STAKING_POOL, *amount));
                    state.stack.push(1);
                }
                OpCode::SysCallUnbond { validator, amount } => {
                    charge!(GAS_STAKE_UNBOND);
                    // Only the validator may unbond its own stake. Without this,
                    // anyone can loop this opcode against a victim's id and drive
                    // `self_bond` to zero, which drops them out of the validator
                    // set (`to_validator_set` requires the minimum bond) - a
                    // 50,000 STELL validator ejected for a few hundred gas.
                    if ctx.sender != *validator {
                        return VmExecutionResult::Reverted(
                            "only the validator may unbond its own stake".to_string(),
                        );
                    }
                    ensure_working(&mut working_staking, ctx.staking.as_deref());
                    let Some(ledger) = working_staking.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Staking ledger not available".to_string(),
                        );
                    };
                    if let Err(e) = ledger.unbond(*validator, *amount, ctx.timestamp) {
                        return VmExecutionResult::Reverted(format!("unbond failed: {e}"));
                    }
                    state.stack.push(1);
                }
                OpCode::SysCallRotateValidatorKey {
                    old_validator,
                    new_validator,
                } => {
                    charge!(GAS_STAKE_UNBOND);
                    // Only the old key itself may rotate away from itself.
                    // Without this, anyone could exile a victim's record to
                    // a dead key (same grief class as the unbond rule above).
                    if ctx.sender != *old_validator {
                        return VmExecutionResult::Reverted(
                            "only the old validator key may rotate itself".to_string(),
                        );
                    }
                    if *old_validator == [0u8; 32] || *new_validator == [0u8; 32] {
                        return VmExecutionResult::Reverted(
                            "rotation needs two real keys".to_string(),
                        );
                    }
                    ensure_working(&mut working_staking, ctx.staking.as_deref());
                    let Some(ledger) = working_staking.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Staking ledger not available".to_string(),
                        );
                    };
                    if let Err(e) = ledger.rotate_key(*old_validator, *new_validator) {
                        return VmExecutionResult::Reverted(format!("rotate failed: {e}"));
                    }
                    state.stack.push(1);
                }
                OpCode::SysCallDelegate { validator, amount } => {
                    charge!(GAS_STAKE_BOND);
                    ensure_working(&mut working_staking, ctx.staking.as_deref());
                    let Some(ledger) = working_staking.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Staking ledger not available".to_string(),
                        );
                    };
                    if *amount == 0 {
                        return VmExecutionResult::Reverted(
                            "delegate amount must be positive".to_string(),
                        );
                    }
                    if *amount > current_balance {
                        return VmExecutionResult::Reverted(
                            "Insufficient balance to delegate".to_string(),
                        );
                    }
                    if let Err(e) = ledger.delegate(ctx.sender, *validator, *amount) {
                        return VmExecutionResult::Reverted(format!("delegate failed: {e}"));
                    }
                    current_balance -= *amount;
                    ctx.transfers.push((crate::staking::STAKING_POOL, *amount));
                    state.stack.push(1);
                }
                OpCode::SysCallUndelegate { validator } => {
                    charge!(GAS_STAKE_UNBOND);
                    ensure_working(&mut working_staking, ctx.staking.as_deref());
                    let Some(ledger) = working_staking.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Staking ledger not available".to_string(),
                        );
                    };
                    // Withdraw MATURED delegation (E1 fix): consume the
                    // withdrawable entry and pay it out, exactly once. The
                    // old code called `undelegate()` (begin unbonding) with
                    // swapped lookup args AND paid without consuming — bricking
                    // exits and multi-paying on any naive fix. Beginning an
                    // unbonding is `SysCallBeginUndelegate` now; this opcode
                    // only releases what already matured.
                    match ledger.withdraw_delegator(ctx.sender, *validator) {
                        Ok(amount) => {
                            ctx.payouts
                                .push((crate::staking::STAKING_POOL, ctx.sender, amount));
                            state.stack.push(amount);
                        }
                        // Nothing matured (or never delegated): revert with a
                        // clear reason instead of a silent no-op — the caller
                        // must wait out the cooldown, not retry blindly.
                        Err(e) => {
                            return VmExecutionResult::Reverted(format!(
                                "withdraw matured delegation failed: {e}"
                            ));
                        }
                    }
                }
                OpCode::SysCallBeginUndelegate { validator, amount } => {
                    charge!(GAS_STAKE_UNBOND);
                    ensure_working(&mut working_staking, ctx.staking.as_deref());
                    let Some(ledger) = working_staking.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Staking ledger not available".to_string(),
                        );
                    };
                    // Anyone may begin unbonding ONLY their own position:
                    // `undelegate` keys by (validator, caller-as-delegator),
                    // so a stranger's call touches nobody else's funds (it
                    // fails on insufficient delegation unless they delegated
                    // themselves). Amount-explicit (unlike the old undelegate
                    // path): partial exits work, dust remainders stay staked.
                    if *amount == 0 {
                        return VmExecutionResult::Reverted(
                            "begin unbond amount must be positive".to_string(),
                        );
                    }
                    if let Err(e) =
                        ledger.undelegate(ctx.sender, *validator, *amount, ctx.timestamp)
                    {
                        return VmExecutionResult::Reverted(format!("begin unbonding failed: {e}"));
                    }
                    state.stack.push(*amount);
                }
                OpCode::SysCallClaimRewards { validator } => {
                    charge!(GAS_STAKE_CLAIM);
                    // The opcode's own documentation says "a validator the sender
                    // is bonded to", but no such check existed: the payout
                    // beneficiary is `ctx.sender`, so any account could name any
                    // validator and take its accrued rewards. The pool paid out of
                    // the victim's bonded principal and the victim's counter was
                    // zeroed, so the loss was unrecoverable.
                    if ctx.sender != *validator {
                        return VmExecutionResult::Reverted(
                            "only the validator may claim its own rewards".to_string(),
                        );
                    }
                    ensure_working(&mut working_staking, ctx.staking.as_deref());
                    let Some(ledger) = working_staking.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Staking ledger not available".to_string(),
                        );
                    };
                    let amount = match ledger.claim_validator_rewards(*validator) {
                        Ok(a) => a,
                        Err(e) => return VmExecutionResult::Reverted(format!("claim failed: {e}")),
                    };
                    // Rewards are backed by the minted rewards pool, never by
                    // bonded principal: pay them out of REWARDS_POOL (funded by
                    // the block-reward mint, capped by REWARDS_EMISSION_CAP).
                    if amount > 0 {
                        // Paid out of the rewards pool, not out of the sender
                        // and never out of the staking (principal) pool.
                        ctx.payouts
                            .push((crate::staking::REWARDS_POOL, ctx.sender, amount));
                    }
                    state.stack.push(amount);
                }
                OpCode::SysCallClaimDelegatorRewards { validator } => {
                    charge!(GAS_STAKE_CLAIM);
                    ensure_working(&mut working_staking, ctx.staking.as_deref());
                    let Some(ledger) = working_staking.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Staking ledger not available".to_string(),
                        );
                    };
                    // Withdraw accrued DELEGATOR rewards (E8): consume the
                    // sender's claimable amount for this validator and pay it
                    // out of the REWARDS pool (E2: never out of bonded
                    // principal), exactly once — the
                    // `SysCallUndelegate`-withdraw shape (remove-then-pay, the
                    // ledger removes the entry on read). Nothing claimable
                    // reverts with a clear reason instead of a silent no-op.
                    let amount = ledger.claim_delegator_rewards(ctx.sender, *validator);
                    if amount == 0 {
                        return VmExecutionResult::Reverted(
                            "no delegator rewards to claim for this validator".to_string(),
                        );
                    }
                    ctx.payouts
                        .push((crate::staking::REWARDS_POOL, ctx.sender, amount));
                    state.stack.push(amount);
                }
                OpCode::SysCallWithdrawSelfBond { validator } => {
                    charge!(GAS_STAKE_UNBOND);
                    // Only the validator may withdraw its own matured
                    // self-bond. Without this, anyone could name a victim's
                    // id and take its unbonded principal (same grief class
                    // as the `SysCallUnbond` sender rule above: the payout
                    // beneficiary is `ctx.sender`, so the id must match it).
                    if ctx.sender != *validator {
                        return VmExecutionResult::Reverted(
                            "only the validator may withdraw its own self-bond".to_string(),
                        );
                    }
                    ensure_working(&mut working_staking, ctx.staking.as_deref());
                    let Some(ledger) = working_staking.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Staking ledger not available".to_string(),
                        );
                    };
                    // Withdraw MATURED self-bond (M1): consume the
                    // withdrawable entry and pay it out of STAKING_POOL,
                    // exactly once — the `SysCallUndelegate`-withdraw shape
                    // (remove-then-pay, the ledger removes the entry on
                    // read). UNBONDING-PERIOD MATURED ONLY: `withdraw`
                    // reads the `withdrawable` map, which
                    // `process_unbonding` fills only once `release_at`
                    // passes, so immature funds revert here (fail-closed)
                    // instead of paying early. Nothing withdrawable
                    // reverts with a clear reason instead of a silent no-op.
                    match ledger.withdraw(*validator) {
                        Ok(amount) => {
                            ctx.payouts
                                .push((crate::staking::STAKING_POOL, ctx.sender, amount));
                            state.stack.push(amount);
                        }
                        Err(e) => {
                            return VmExecutionResult::Reverted(format!(
                                "withdraw matured self-bond failed: {e}"
                            ));
                        }
                    }
                }
                OpCode::Halt => {
                    charge!(GAS_HALT);
                    state.halted = true;
                    break;
                }
                OpCode::SysCallSubmitPriceFeed(feed) => {
                    charge!(GAS_SUBMIT_PRICE_FEED);
                    // DETERMINISM: `ctx.timestamp` is the BLOCK timestamp
                    // (`block.timestamp`, plumbed by `execute_payload`), never
                    // this node's wall clock - every node applying the block
                    // passes the same number, so freshness, monotonicity and
                    // the peg/deviation gates below agree network-wide.
                    //
                    // Every check lives in `commit_feed`, which the read-time
                    // path (`OracleSafetyEngine::resolve_price`) shares, so a
                    // commit and a read can never apply different rules.
                    // Any rejection reverts the whole transaction: no partial
                    // price, no half-committed oracle.
                    let Some(oracle) = ctx.oracle.as_deref_mut() else {
                        return VmExecutionResult::Reverted(
                            "oracle state not available".to_string(),
                        );
                    };
                    match oracle.commit_feed(feed, ctx.timestamp) {
                        Ok(price) => state.stack.push(price),
                        Err(e) => {
                            return VmExecutionResult::Reverted(format!("price feed rejected: {e}"))
                        }
                    }
                }
                OpCode::SysCallRevokeSession { session_pubkey } => {
                    charge!(GAS_SESSION_REVOKE);
                    // Snapshot the sender BEFORE borrowing the registry: it is
                    // `tx.from`, and for a session-keyed transaction the
                    // envelope has already proved `master_address == tx.from`,
                    // so "the delegator" is exactly whoever signed this payload.
                    let sender = ctx.sender;
                    let Some(registry) = ctx.session_keys.as_deref_mut() else {
                        return VmExecutionResult::Reverted(
                            "session-key registry not available".to_string(),
                        );
                    };
                    match registry.entries.get_mut(session_pubkey) {
                        None => {
                            // Fail closed. A key that was never registered has
                            // no master to authenticate a revocation against,
                            // so this is where the trade-off lands: a grant
                            // that has never been used cannot be revoked on
                            // chain either - but neither can anyone else
                            // pre-tombstone a victim's unused key by guessing
                            // its public key (registration itself requires the
                            // SESSION private key, revocation would not).
                            return VmExecutionResult::Reverted(
                                "unknown session key: nothing to revoke".to_string(),
                            );
                        }
                        Some(rec) if rec.master != sender => {
                            return VmExecutionResult::Reverted(
                                "only the delegator may revoke its session key".to_string(),
                            );
                        }
                        Some(rec) => {
                            // Terminal: `revoked` is never written back to
                            // `false` anywhere, and the registry is committed
                            // into the state root, so this survives restarts,
                            // restores and reorgs of the revoking block.
                            rec.revoked = true;
                            state.stack.push(1);
                        }
                    }
                }
                OpCode::SysCallPmmBuy { usdt_micro } => {
                    charge!(GAS_PMM_BUY);
                    // The wUSDT half of the swap runs here, in the working
                    // token registry (clone-committed, so a later revert takes
                    // the burn with it). The curve is advanced on the working
                    // PMM clone for the same reason. The NATIVE half has no VM
                    // channel - there is no account map in here - so it is
                    // emitted as an event and settled by the engine while the
                    // transaction is still all-or-nothing.
                    let Some(usdt_id) = ctx.pmm.as_ref().and_then(|p| p.usdt_token) else {
                        return VmExecutionResult::Reverted(
                            "PMM USDT token not initialised".to_string(),
                        );
                    };
                    ensure_working(&mut working_pmm, ctx.pmm.as_ref().map(|p| &*p.state));
                    let Some(working) = working_pmm.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "PMM not available in this VM context".to_string(),
                        );
                    };
                    let receipt = match working.buy_with_buffer(
                        *usdt_micro,
                        ctx.pmm
                            .as_ref()
                            .map(|p| p.redemption_buffer_bps)
                            .unwrap_or(crate::pmm::PMM_REDEMPTION_BUFFER_BPS),
                    ) {
                        Ok(r) => r,
                        Err(e) => return VmExecutionResult::Reverted(format!("PMM buy: {e}")),
                    };
                    // Burn the buyer's wUSDT. Checked before the curve commit
                    // matters only in the sense that a revert discards both.
                    ensure_working(&mut working_tokens, ctx.token_registry.as_deref());
                    let Some(reg) = working_tokens.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Token registry not available".to_string(),
                        );
                    };
                    if reg.balance_of(&usdt_id, &ctx.sender) < *usdt_micro {
                        return VmExecutionResult::Reverted(
                            "Insufficient wUSDT balance for PMM buy".to_string(),
                        );
                    }
                    match reg.execute(
                        &usdt_id,
                        ctx.sender,
                        TokenOp::Burn {
                            from: ctx.sender,
                            amount: *usdt_micro,
                        },
                    ) {
                        Ok(ev) => ctx.token_events.push(ev),
                        Err(e) => {
                            return VmExecutionResult::Reverted(format!("wUSDT debit failed: {e}"))
                        }
                    }
                    // Mirror the mint into the local balance so a later opcode
                    // in the same payload can spend it, exactly like the VM
                    // mirrors an escrow lock. The engine credits the real
                    // account when it settles the event below.
                    current_balance = current_balance.saturating_add(receipt.stell_minted);
                    if let Some(p) = ctx.pmm.as_mut() {
                        p.events.push(crate::pmm::PmmEvent::Buy {
                            buyer: ctx.sender,
                            usdt_micro: *usdt_micro,
                            stell_minted: receipt.stell_minted,
                        });
                    }
                    state.stack.push(receipt.stell_minted);
                }
                OpCode::SysCallPmmSell { stell_nano } => {
                    charge!(GAS_PMM_SELL);
                    let Some(usdt_id) = ctx.pmm.as_ref().and_then(|p| p.usdt_token) else {
                        return VmExecutionResult::Reverted(
                            "PMM USDT token not initialised".to_string(),
                        );
                    };
                    let treasury = ctx.pmm.as_ref().map(|p| p.treasury).unwrap_or([0u8; 32]);
                    // The seller pays native STELL out of the same running
                    // balance every other opcode is checked against, so a
                    // payload cannot sell coins it then also transfers.
                    if *stell_nano > current_balance {
                        return VmExecutionResult::Reverted(
                            "Insufficient native balance for PMM sell".to_string(),
                        );
                    }
                    ensure_working(&mut working_pmm, ctx.pmm.as_ref().map(|p| &*p.state));
                    let Some(working) = working_pmm.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "PMM not available in this VM context".to_string(),
                        );
                    };
                    let receipt = match working.sell_stell(*stell_nano) {
                        Ok(r) => r,
                        Err(e) => return VmExecutionResult::Reverted(format!("PMM sell: {e}")),
                    };
                    // Mint the wUSDT payout. Only the treasury (the token's
                    // minter, fixed at pmm_init_usdt) may mint, so a PMM that
                    // was never initialised cannot pay out.
                    ensure_working(&mut working_tokens, ctx.token_registry.as_deref());
                    let Some(reg) = working_tokens.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Token registry not available".to_string(),
                        );
                    };
                    match reg.execute(
                        &usdt_id,
                        treasury,
                        TokenOp::Mint {
                            to: ctx.sender,
                            amount: receipt.usdt_paid,
                        },
                    ) {
                        Ok(ev) => ctx.token_events.push(ev),
                        Err(e) => {
                            return VmExecutionResult::Reverted(format!("wUSDT payout failed: {e}"))
                        }
                    }
                    current_balance -= *stell_nano;
                    if let Some(p) = ctx.pmm.as_mut() {
                        p.events.push(crate::pmm::PmmEvent::Sell {
                            seller: ctx.sender,
                            stell_nano: *stell_nano,
                            usdt_paid: receipt.usdt_paid,
                        });
                    }
                    state.stack.push(receipt.usdt_paid);
                }
                OpCode::SysCallPublishSessionGrant(grant) => {
                    charge!(GAS_PUBLISH_SESSION_GRANT);
                    // Publishing a grant is a pure announcement: it writes no
                    // state (the registry the policy reads is populated by the
                    // session transactions themselves), so the only questions
                    // are "is it really the master's" and "is it really ours
                    // to publish". Both must hold, or anyone could republish
                    // or forge announcements under someone else's address.
                    //
                    // NOTE: `verify_signature` only - NOT `verify_at`, because
                    // that would read the local wall clock and every node
                    // applying the block would reach a different verdict.
                    if grant.master_address != ctx.sender {
                        return VmExecutionResult::Reverted(
                            "only the master may publish its own session grant".to_string(),
                        );
                    }
                    if !grant.verify_signature() {
                        return VmExecutionResult::Reverted(
                            "session grant signature does not verify".to_string(),
                        );
                    }
                    state.stack.push(1);
                }
                OpCode::SysCallBridge(intent) => {
                    charge!(GAS_BRIDGE_INTENT);
                    // Validate here, settle the NATIVE leg in the engine.
                    //
                    // The VM has no account map, so it cannot credit a deposit
                    // or escrow a withdrawal itself; `execute_payload` reads the
                    // `SysCallBridge` intents straight off the payload and moves
                    // the coins (mint to recipient / debit sender into
                    // `bridge::BRIDGE_ESCROW`) with the same all-or-nothing
                    // settlement the PMM native leg uses. An invalid intent
                    // reverts the whole transaction before any coin moves.
                    //
                    // The bridge's QUORUM, replay set and rate limit are NOT
                    // enforced yet - see `bridge.rs` for exactly what remains.
                    if let Err(e) = intent.validate() {
                        return VmExecutionResult::Reverted(e);
                    }
                    state.stack.push(1);
                }
                OpCode::SysCallConfidentialTransfer { .. } => {
                    // DISABLED (audit 2026-10-06, F-A): the V1 equation-only
                    // check admits wrapped/negative values and anyone's
                    // commitments. Use SysCallConfidentialTransfer2.
                    return VmExecutionResult::Reverted(
                        "confidential transfer V1 is disabled: resubmit as SysCallConfidentialTransfer2 with range proofs"
                            .to_string(),
                    );
                }
                OpCode::SysCallConfidentialTransfer2 {
                    recipient,
                    transfer,
                    input_ranges,
                    output_ranges,
                } => {
                    // Recipient sanity (audit follow-up): protocol-owned
                    // accounts (escrow, pools) can sign for nothing, so outputs
                    // to them freeze forever. Burn-by-design stays possible
                    // via an explicit dead address, not via the vault.
                    if *recipient == crate::crypto_privacy::SHIELD_ESCROW
                        || *recipient == crate::staking::STAKING_POOL
                        || *recipient == crate::bridge::BRIDGE_ESCROW
                    {
                        return VmExecutionResult::Reverted(
                            "confidential transfer rejected: recipient is a protocol account"
                                .to_string(),
                        );
                    }
                    // IO-count cap (audit: blocks troubles): uncapped proofs
                    // let one hostile tx eat ~5% of proposal wire for <1% of
                    // block gas. Fail closed before charging/paying anything.
                    if input_ranges.len() + output_ranges.len() > MAX_CONFIDENTIAL_IO_PER_TX {
                        return VmExecutionResult::Reverted(format!(
                            "confidential transfer rejected: too many proofs (max {MAX_CONFIDENTIAL_IO_PER_TX})"
                        ));
                    }
                    // Same dynamic charge as the table (see
                    // `confidential_transfer2_gas`): flat would underprice
                    // big proofs and break table/dispatch agreement.
                    charge!(confidential_transfer2_gas(input_ranges, output_ranges));
                    // Range proofs FIRST (before any state read): every
                    // committed value is proven in [0, 2^bits), closing the
                    // wrapped/negative-value inflation hole.
                    //
                    // Block-path fast path: the engine's parallel pre-pass
                    // (`InMemoryStateEngine::apply_block_parallel_fees`) already
                    // verified this EXACT bundle's stateless proof check across
                    // cores. A hit reuses that verdict instead of re-verifying;
                    // it covers ONLY the range proofs — the ownership,
                    // spent-set, conservation and fee checks in
                    // `apply_transfer` below run unconditionally either way.
                    // A miss (always, on the single-transaction path, which
                    // never carries a cache) runs the full check as before. A
                    // hit is bit-identical to recomputing: verification is a
                    // pure function of the bundled bytes, so the same digest
                    // always verifies the same way on every node.
                    let ranges_ok = match range_preverify.and_then(|m| {
                        m.get(
                            &crate::crypto_privacy::confidential_transfer2_preverify_digest(
                                transfer,
                                input_ranges,
                                output_ranges,
                            ),
                        )
                        .copied()
                    }) {
                        Some(preverified) => preverified,
                        None => transfer.verify_balanced_with_ranges(input_ranges, output_ranges),
                    };
                    if !ranges_ok {
                        return VmExecutionResult::Reverted(
                            "confidential transfer rejected: range proofs failed \
                             (bad count, bad proof, or unbalanced)"
                                .to_string(),
                        );
                    }
                    let Some(shielded) = confidential.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "confidential state not available".to_string(),
                        );
                    };
                    // `apply_transfer_with_ranges` enforces everything atomically:
                    // range proofs + valid points, no intra-tx repeats, sender
                    // OWNS every input, no double-spend, conservation, fee
                    // overflow — then rewrites balances, spent set, ownership
                    // map and fee total. Single entry point (C1): the preverify
                    // above is a fast-path only; this call re-verifies, so no
                    // caller can ever reach equation-only `apply_transfer`.
                    let sender = ctx.sender;
                    if let Err(e) = shielded.apply_transfer_with_ranges(
                        &sender,
                        recipient,
                        transfer,
                        input_ranges,
                        output_ranges,
                    ) {
                        return VmExecutionResult::Reverted(format!(
                            "confidential transfer rejected: {e}"
                        ));
                    }
                    state.stack.push(1);
                }
                OpCode::SysCallConfidentialShield {
                    commitment,
                    amount,
                    blinding,
                } => {
                    charge!(GAS_CONFIDENTIAL_SHIELD);
                    if *amount == 0 {
                        return VmExecutionResult::Reverted(
                            "shield amount must be greater than zero".to_string(),
                        );
                    }
                    // The opening MUST recompute exactly: a range proof cannot
                    // bind a value, only an opening can. Wrong blinding (or a
                    // commitment to a different value) reverts here, before
                    // any native coin moves.
                    if !crate::crypto_privacy::ConfidentialState::verify_opening(
                        commitment, *amount, blinding,
                    ) {
                        return VmExecutionResult::Reverted(
                            "shield rejected: opening does not match commitment".to_string(),
                        );
                    }
                    let Some(shielded) = confidential.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "confidential state not available".to_string(),
                        );
                    };
                    if shielded.is_spent(commitment) {
                        return VmExecutionResult::Reverted(
                            "shield rejected: commitment already spent".to_string(),
                        );
                    }
                    // No double-funding (audit follow-up): re-shielding a LIVE
                    // commitment double-debits native for one spendable entry
                    // and skews escrow-vs-outstanding forever. Same opening
                    // twice is a user error, not a second coin.
                    if shielded.is_owned(commitment) {
                        return VmExecutionResult::Reverted(
                            "shield rejected: commitment already shielded".to_string(),
                        );
                    }
                    shielded.note_shielded_output(&ctx.sender, *commitment);
                    // Native leg via the transfers channel (sender debited,
                    // SHIELD_ESCROW credited, atomically with everything else
                    // in commit_native). A sender that cannot cover `amount`
                    // fails there and the recording above dies with the tx.
                    ctx.transfers
                        .push((crate::crypto_privacy::SHIELD_ESCROW, *amount));
                    state.stack.push(1);
                }
                OpCode::SysCallConfidentialUnshield { inputs } => {
                    charge!(GAS_CONFIDENTIAL_UNSHIELD.saturating_add(
                        (inputs.len() as u64).saturating_mul(GAS_CONFIDENTIAL_UNSHIELD_PER_INPUT)
                    ));
                    if inputs.is_empty() {
                        return VmExecutionResult::Reverted(
                            "unshield needs at least one input".to_string(),
                        );
                    }
                    // IO-count cap (audit: blocks troubles): see Transfer2.
                    if inputs.len() > MAX_UNSHIELD_INPUTS_PER_TX {
                        return VmExecutionResult::Reverted(format!(
                            "unshield rejected: too many inputs (max {MAX_UNSHIELD_INPUTS_PER_TX})"
                        ));
                    }
                    let Some(shielded) = confidential.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "confidential state not available".to_string(),
                        );
                    };
                    // Verifies openings + ownership + unspent, retires the
                    // inputs, returns the releasable total. Privacy ends at
                    // exit by design (amounts are public from here on).
                    let total = match shielded.retire_for_unshield(&ctx.sender, inputs) {
                        Ok(t) => t,
                        Err(e) => {
                            return VmExecutionResult::Reverted(format!("unshield rejected: {e}"))
                        }
                    };
                    if total == 0 {
                        return VmExecutionResult::Reverted(
                            "unshield total must be greater than zero".to_string(),
                        );
                    }
                    // Native leg via payouts (SHIELD_ESCROW pays the sender;
                    // escrow insufficiency fails the whole tx in commit_native).
                    ctx.payouts
                        .push((crate::crypto_privacy::SHIELD_ESCROW, ctx.sender, total));
                    state.stack.push(total);
                }
                OpCode::SysCallActorSend {
                    recipient,
                    value,
                    body,
                    bounce,
                    gas_budget,
                } => {
                    charge!(GAS_ACTOR_SEND);
                    // §1 ACTOR MAILBOX. The VM only validates and records; the
                    // engine moves the coins when the transaction commits (or,
                    // for a delivered body, when the mailbox pass settles it).
                    //
                    // v1: a send MUST be bounceable. Without that rule a
                    // message to a missing recipient (or one whose body
                    // reverts) would destroy the value it carried, and value
                    // destruction is exactly what bounce exists to prevent -
                    // so the whole transaction reverts instead of the send
                    // being accepted with `bounce = false`.
                    if !bounce {
                        return VmExecutionResult::Reverted(
                            "actor send must enable bounce (v1 forbids value-destroying sends)"
                                .to_string(),
                        );
                    }
                    // Fail closed when no engine sink is wired (a direct
                    // `Svm::execute` caller): accepting the send would drop a
                    // message somebody prepaid for. Same shape as a token
                    // syscall with no registry.
                    let Some(sink) = sends.as_deref_mut() else {
                        return VmExecutionResult::Reverted(
                            "actor send not available: no engine sink wired".to_string(),
                        );
                    };
                    // PREPAY: the per-message delivery overhead plus the
                    // body's fuel, charged HERE so it fits inside the
                    // transaction's declared gas_limit - a sender can never
                    // force delivery work it did not pay for up front, and a
                    // session grant's budget covers it like any other gas.
                    let prepay = GAS_ACTOR_DELIVER.saturating_add(*gas_budget);
                    if state.gas_remaining < prepay {
                        return VmExecutionResult::OutOfGas;
                    }
                    state.gas_remaining -= prepay;
                    // Intra-payload affordability against the balance mirror,
                    // so several sends in one payload cannot together spend
                    // more than the sender holds. The engine re-checks under
                    // its own lock when it settles them.
                    if current_balance < *value {
                        return VmExecutionResult::Reverted(
                            "insufficient balance for actor send".to_string(),
                        );
                    }
                    current_balance -= *value;
                    sink.push(ActorSendRequest {
                        recipient: *recipient,
                        value: *value,
                        body: body.clone(),
                        bounce: *bounce,
                        gas_budget: *gas_budget,
                    });
                }
                OpCode::SysCallVerifyZkMlReexec { model_id, proof } => {
                    charge!(zkml_verify_in_gas(proof.wire_len()));
                    // §2 SOUND verify: the proof rides in the payload, the model
                    // rides in the committed registry. Fail closed with no
                    // registry wired (direct `Svm::execute`, or a delivered
                    // actor body which wires no registries by design) - the
                    // same shape as a token syscall with no registry.
                    let Some(reg) = zkml_models.as_deref_mut() else {
                        return VmExecutionResult::Reverted(
                            "zkML model registry not available".to_string(),
                        );
                    };
                    let Some(rec) = reg.get(model_id) else {
                        return VmExecutionResult::Reverted(
                            "unknown zkML model: register it first".to_string(),
                        );
                    };
                    if rec.model_hash != proof.model_hash {
                        return VmExecutionResult::Reverted(
                            "zkML proof model hash does not match the registered model".to_string(),
                        );
                    }
                    // In-handler re-execution charge: linear in the REGISTERED
                    // model's parameters (the work every verifier actually
                    // does). `opcode_gas` already charged the fixed half plus
                    // the proof bytes; this is the model half it cannot see.
                    let reexec =
                        (rec.model.param_count() as u64).saturating_mul(GAS_ZKML_REEXEC_PER_PARAM);
                    if state.gas_remaining < reexec {
                        return VmExecutionResult::OutOfGas;
                    }
                    state.gas_remaining -= reexec;
                    // SOUND check = re-execution, NOT a zero-knowledge proof
                    // (see the opcode docs). The structural-only
                    // `verify_inference()` is
                    // deliberately NOT called here: it is fooled by forged
                    // traces and the legacy opcode that called it is hard-
                    // refused above.
                    if !proof.verify_inference_against(&rec.model) {
                        return VmExecutionResult::Reverted(
                            "zkML verification failed: proof does not match the registered model"
                                .to_string(),
                        );
                    }
                    state.stack.push(1);
                }
                OpCode::SysCallRegisterZkMlModel { model_id, model } => {
                    charge!(zkml_register_gas(model.param_count()));
                    // §2 registry write: permissionless, append-only, validated
                    // and bounded before it joins committed state. Fail closed
                    // with no registry wired, like every other registry write.
                    let Some(reg) = zkml_models.as_deref_mut() else {
                        return VmExecutionResult::Reverted(
                            "zkML model registry not available".to_string(),
                        );
                    };
                    match reg.register(*model_id, (**model).clone()) {
                        Ok(_) => state.stack.push(1),
                        Err(e) => {
                            return VmExecutionResult::Reverted(format!(
                                "zkML model registration rejected: {e}"
                            ))
                        }
                    }
                }
                OpCode::SysCallRegisterZkMlSpec { model_id, spec } => {
                    charge!(spec_register_gas(spec));
                    // Test-setup refusal (audit F2, HIGH): test-only setups
                    // (deterministic, waste-derivable) must never anchor any
                    // chain. The check is DETERMINISTIC — it reads only the
                    // attestation bytes carried in the opcode itself — so every
                    // node reaches the same verdict and consensus cannot split
                    // over it.
                    //
                    // HONESTY (audit W8.3): there is NO ceremony behind this
                    // label. `setup_attestation` is a free-form operator
                    // string; the chain only refuses the documented test-only
                    // prefix. It is NOT a Groth16 setup, and it does NOT make
                    // the proof zero-knowledge (see `crate::zkml::zkml_capabilities`).
                    const TEST_PREFIX: &[u8] = b"TEST-ONLY-DETERMINISTIC-SETUP";
                    if spec.setup_attestation.starts_with(TEST_PREFIX) {
                        return VmExecutionResult::Reverted(
                            "zkML model spec setup attestation is test-only (waste-derivable, not for production)"
                                .to_string(),
                        );
                    }
                    // §2 spec registration: permissionless, append-only, gated
                    // on the constrained format. Fail closed with no registry
                    // wired, like any other registry write.
                    let Some(reg) = zkml_models.as_deref_mut() else {
                        return VmExecutionResult::Reverted(
                            "zkML model registry not available".to_string(),
                        );
                    };
                    match reg.register_spec(*model_id, (**spec).clone()) {
                        Ok(_) => state.stack.push(1),
                        Err(e) => {
                            return VmExecutionResult::Reverted(format!(
                                "zkML model spec registration rejected: {e}"
                            ))
                        }
                    }
                }
                OpCode::SysCallVerifyZkMlAttestation { model_id, proof } => {
                    charge!(attestation_verify_gas(
                        proof
                            .public_inputs
                            .len()
                            .saturating_add(proof.public_outputs.len()),
                        proof.wire_len()
                    ));
                    // §2 ATTESTATION verify: the proof rides in the payload, the
                    // model AND its registered spec ride in the committed
                    // registry. Fail closed with no registry wired (direct
                    // `Svm::execute`, or a delivered actor body which wires
                    // no registries by design) - the same shape as a token
                    // syscall with no registry.
                    let Some(reg) = zkml_models.as_deref_mut() else {
                        return VmExecutionResult::Reverted(
                            "zkML model registry not available".to_string(),
                        );
                    };
                    let Some(rec) = reg.get(model_id) else {
                        return VmExecutionResult::Reverted(
                            "unknown zkML model: register it first".to_string(),
                        );
                    };
                    // Registry-layer binding: the proof must name BOTH the
                    // registered model hash and the registered spec hash.
                    // Either mismatch reverts before any work is done.
                    if rec.model_hash != proof.model_hash {
                        return VmExecutionResult::Reverted(
                            "zkML attestation model hash does not match the registered model"
                                .to_string(),
                        );
                    }
                    let Some(spec) = rec.spec.as_ref() else {
                        return VmExecutionResult::Reverted(
                            "no model spec registered for this model: use \
                             SysCallVerifyZkMlReexec or register a spec first"
                                .to_string(),
                        );
                    };
                    if spec.spec_hash != proof.spec_hash {
                        return VmExecutionResult::Reverted(
                            "zkML attestation spec hash does not match the registered spec"
                                .to_string(),
                        );
                    }
                    if proof.public_inputs.len() as u64 != spec.in_dim
                        || proof.public_outputs.len() as u64 != spec.out_dim
                    {
                        return VmExecutionResult::Reverted(
                            "zkML attestation I/O shape does not match the registered spec"
                                .to_string(),
                        );
                    }
                    // Cheap fail-fast with a clear error: the circuit's input
                    // gadget only admits u16. (A larger value would fail the
                    // pairing check anyway; this names the reason.)
                    if proof
                        .public_inputs
                        .iter()
                        .any(|x| *x > crate::zkml_attestation::ATTEST_MAX_INPUT)
                    {
                        return VmExecutionResult::Reverted(
                            "zkML attestation input outside u16 (constrained format)".to_string(),
                        );
                    }
                    // The ATTESTATION check RE-EXECUTES the model from the
                    // registered spec and compares the outputs and the Merkle
                    // trace root. It is NOT a pairing check and NOT a
                    // succinct proof (audit W8.3) — so it costs what the
                    // model costs, and the gas table must price it that way.
                    //
                    // RE-EXECUTION CHARGE (audit W8.3, was MISSING): the
                    // re-execution path charges the registered model's
                    // parameter count inside the handler
                    // ([`GAS_ZKML_REEXEC_PER_PARAM`]) because `opcode_gas`
                    // cannot see the registry. The attestation path does the
                    // SAME work, so it must pay the SAME price: without this
                    // the "attestation" opcode was priced BELOW the
                    // re-execution opcode while doing the same CPU work, so a
                    // proof flood was cheaper than the block space it burned.
                    let reexec =
                        (rec.model.param_count() as u64).saturating_mul(GAS_ZKML_REEXEC_PER_PARAM);
                    if state.gas_remaining < reexec {
                        return VmExecutionResult::OutOfGas;
                    }
                    state.gas_remaining -= reexec;
                    if !crate::zkml_attestation::verify_attestation(&spec.spec_bytes, proof) {
                        return VmExecutionResult::Reverted(
                            "zkML attestation verification failed: the proof does not \
                             reproduce the registered model's outputs"
                                .to_string(),
                        );
                    }
                    state.stack.push(1);
                }
                OpCode::SysCallVerifyPqSignature {
                    scheme_id,
                    pubkey,
                    message,
                    signature,
                } => {
                    charge!(pq_verify_gas(pubkey.len(), message.len(), signature.len()));
                    let valid = match crate::post_quantum::PqScheme::from_id(*scheme_id) {
                        Ok(scheme) => crate::post_quantum::verify_pq_signature(
                            scheme, pubkey, message, signature,
                        ),
                        Err(_) => false,
                    };
                    state.stack.push(if valid { 1 } else { 0 });
                }
                OpCode::SysCallReportEquivocation { evidence } => {
                    charge!(equivocation_report_gas(evidence.wire_len()));
                    // PURE CARRIER (audit O1/F4 wiring — see the `OpCode`
                    // docs above): verify-only. Moves NO coins and touches
                    // NO ledger state. The slash itself fires once per block
                    // at `InMemoryStateEngine::apply_block_transition` (step
                    // 5b), which scans the decided block for this opcode and
                    // re-verifies every envelope from block bytes — so this
                    // arm's verdict only prices the reporter's transaction
                    // (success burns gas normally, revert wastes it), never
                    // the slash. Any exec/scan skew (e.g. a membership that
                    // changes in a later transaction of the same block) is
                    // harmless: both sides are deterministic functions of
                    // block content, and the scan is authoritative.
                    //
                    // Fail-closed: an envelope that does not verify (bad
                    // shape, forged signature, unknown voter, oversize)
                    // REVERTS the transaction instead of succeeding
                    // silently. Membership reads the wired staking ledger;
                    // with no ledger wired (direct `Svm::execute` callers)
                    // there is nothing to check membership against, so the
                    // report reverts like every other staking-gated syscall.
                    let verified = match ctx.staking.as_deref() {
                        Some(ledger) => {
                            crate::consensus::verify_equivocation_evidence(evidence, &|v| {
                                ledger.validators.contains_key(v)
                            })
                        }
                        None => false,
                    };
                    if !verified {
                        return VmExecutionResult::Reverted(
                            "equivocation evidence rejected: envelope does not verify".to_string(),
                        );
                    }
                    state.stack.push(1);
                }
                OpCode::SysCallReportPqEquivocation { evidence } => {
                    charge!(equivocation_report_gas(evidence.wire_len()));
                    // THE PQ ARM (audit O1/F4 wiring): unlike the Ed25519
                    // report above this one SLASHES HERE, because the verdict
                    // depends on the accused validator's REGISTERED
                    // post-quantum key - the ledger's `validator_pq_keys` -
                    // which only the ledger itself can resolve.
                    //
                    // Fail-closed throughout:
                    //  * OVERSIZE: a bigger envelope is a DoS probe, not
                    //    evidence (the cap is generous: a real Falcon pair is
                    //    ~1.4 KB).
                    //  * SAME TARGET: two votes for the same target are not
                    //    an equivocation, so the report is refused instead of
                    //    silently succeeding with a 0 burn.
                    //  * NO LEDGER: with no staking ledger wired (direct
                    //    `Svm::execute` callers) there is nothing to check
                    //    membership against, so the report reverts like every
                    //    other staking-gated syscall.
                    //  * BAD SIGNATURE / UNKNOWN VOTER: `slash_pq_equivocation`
                    //    returns `Err` and the transaction REVERTS - the
                    //    reporter wastes gas and nothing else moves.
                    if evidence.wire_len() > crate::staking::MAX_PQ_EQUIVOCATION_EVIDENCE_BYTES {
                        return VmExecutionResult::Reverted(format!(
                            "PQ equivocation evidence rejected: envelope exceeds {} bytes",
                            crate::staking::MAX_PQ_EQUIVOCATION_EVIDENCE_BYTES
                        ));
                    }
                    if evidence.block_hash_a == evidence.block_hash_b {
                        return VmExecutionResult::Reverted(
                            "PQ equivocation evidence rejected: the two votes share one target"
                                .to_string(),
                        );
                    }
                    // Clone-commit, exactly like every other staking opcode:
                    // a later revert / out-of-gas / failed settlement discards
                    // the slash along with everything else the payload did.
                    ensure_working(&mut working_staking, ctx.staking.as_deref());
                    let Some(ledger) = working_staking.as_mut() else {
                        return VmExecutionResult::Reverted(
                            "Staking ledger not available".to_string(),
                        );
                    };
                    // The slash itself: fail-closed verification (conflicting
                    // targets, membership, BOTH signatures under the voter's
                    // registered PQ key), per-offense dedup, then the burn.
                    //
                    // The MICRO-COMMITTEE arm (100% burn + eviction) is NOT
                    // reachable from here, deliberately: it leaves stranded
                    // `delegator_rewards`/`withdrawable`/`unbonding` rows
                    // whose UX must be specified first, and the committee mode
                    // must be derived from COMMITTED state - never chosen by
                    // the reporter. The standard 5% arm already makes PQ
                    // equivocation PUNISHABLE, which is the point of the
                    // opcode.
                    let burned = match ledger.slash_pq_equivocation(evidence, false) {
                        Ok(b) => b,
                        Err(e) => {
                            return VmExecutionResult::Reverted(format!(
                                "PQ equivocation evidence rejected: {e}"
                            ))
                        }
                    };
                    if burned > 0 {
                        // The coins are real: the burn leaves the STAKING_POOL.
                        // The VM has no account map, so it REPORTS the burn
                        // and the engine settles it inside the native commit
                        // (which debits the pool and rolls the whole thing
                        // back if the transaction is refused).
                        burns.push((crate::staking::STAKING_POOL, burned));
                    }
                    state.stack.push(burned);
                }
                OpCode::SysCallReportProposalEquivocation { evidence } => {
                    charge!(equivocation_report_gas(evidence.wire_len()));
                    // PURE CARRIER (P3-EQ-ESCAPE wiring — see the `OpCode`
                    // docs above): verify-only. Moves NO coins and touches
                    // NO ledger state. The slash itself fires once per block
                    // at `InMemoryStateEngine::apply_block_transition`, which
                    // scans the decided block for this opcode and re-verifies
                    // every envelope from block bytes — so this arm's verdict
                    // only prices the reporter's transaction (success burns
                    // gas normally, revert wastes it), never the slash. Any
                    // exec/scan skew is harmless: both sides are deterministic
                    // functions of block content, and the scan is authoritative.
                    //
                    // Fail-closed: an envelope that does not verify (bad
                    // shape, forged proposer signature, unknown proposer,
                    // same body twice, oversize) REVERTS the transaction
                    // instead of succeeding silently. Membership reads the
                    // wired staking ledger; with no ledger wired (direct
                    // `Svm::execute` callers) there is nothing to check
                    // membership against, so the report reverts like every
                    // other staking-gated syscall.
                    let verified = match ctx.staking.as_deref() {
                        Some(ledger) => crate::consensus::verify_proposal_equivocation_evidence(
                            evidence,
                            &|v| ledger.validators.contains_key(v),
                        ),
                        None => false,
                    };
                    if !verified {
                        return VmExecutionResult::Reverted(
                            "proposal equivocation evidence rejected: envelope does not verify"
                                .to_string(),
                        );
                    }
                    state.stack.push(1);
                }
            }
        }

        // The per-opcode adds are gone (see the dispatch loop): the consumed
        // total is exactly what is left of the limit. Bit-identical to the
        // old accumulation because every charge above only decrements
        // `gas_remaining` after the same `< cost` check.
        state.gas_consumed = gas_limit - state.gas_remaining;

        // Verify session key gas spend authorization if present
        if let Some(auth) = ctx.session_auth.as_mut() {
            if let Err(e) = auth.verify_and_spend_gas(state.gas_consumed, ctx.timestamp) {
                return VmExecutionResult::Reverted(e);
            }
        }

        // Commit token mutations only after the entire execution succeeded.
        if let (Some(target), Some(working)) = (ctx.token_registry.as_mut(), working_tokens) {
            **target = working;
        }
        // Commit orderbook mutations only after the entire execution succeeded.
        if let (Some(target), Some(working)) = (ctx.orderbooks.as_mut(), working_books) {
            **target = working;
        }
        // Commit contract mutations only after the entire execution succeeded.
        if let (Some(target), Some(working)) = (ctx.contracts.as_mut(), working_contracts) {
            **target = working;
        }
        // Commit staking mutations only after the entire execution succeeded.
        if let (Some(target), Some(working)) = (ctx.staking.as_mut(), working_staking) {
            **target = working;
        }
        // Commit the PMM curve advance the same way: a swap that reverts (or
        // runs out of gas) mid-payload must not leave the curve moved while
        // the wUSDT leg it priced against was discarded with it.
        if let (Some(target), Some(working)) = (ctx.pmm.as_mut(), working_pmm) {
            *target.state = working;
        }

        VmExecutionResult::Success {
            gas_used: state.gas_consumed,
            return_value: state.stack.last().copied(),
            new_balance: current_balance,
            trades: ctx.trades.clone(),
            transfers: ctx.transfers.clone(),
            payouts: ctx.payouts.clone(),
            burns,
            token_events: ctx.token_events.clone(),
            clob_events,
            outbound_messages,
            events: contract_events,
        }
    }

    /// Route outbound messages produced by smart contracts via `host.send_message`:
    /// - If recipient is local, route to actor inbox (`inbox.push_back`).
    /// - If recipient is on another shard, route to `cross_shard_out` with bounce capability.
    ///
    /// This is the DEFAULT topology (the starting one, where the base
    /// workchain shard holds every workchain address). The live path uses
    /// [`Svm::route_contract_messages_with_topology`], which applies the
    /// node's real topology and therefore the SAME address→shard rule the
    /// RPC layer uses.
    pub fn route_contract_messages(
        messages: &[crate::contract::ContractMessage],
        accounts: &mut HashMap<[u8; 32], crate::state_engine::AccountState>,
        cross_shard_out: &mut Vec<crate::sharding::CrossShardMessage>,
        local_shard: u32,
        sharded: bool,
    ) {
        let topology = crate::sharding::ShardTopology::new();
        Self::route_contract_messages_with_topology(
            messages,
            accounts,
            cross_shard_out,
            local_shard,
            sharded,
            &topology,
        );
    }

    /// Route outbound contract messages under an EXPLICIT shard topology.
    ///
    /// The recipient's shard is resolved by the documented address→shard
    /// rule (see `crate::sharding::ROUTING_RULE`): the longest matching
    /// routing prefix wins, ties broken by the smallest shard id. The master
    /// chain is never a candidate here — it is addressed explicitly.
    pub fn route_contract_messages_with_topology(
        messages: &[crate::contract::ContractMessage],
        accounts: &mut HashMap<[u8; 32], crate::state_engine::AccountState>,
        cross_shard_out: &mut Vec<crate::sharding::CrossShardMessage>,
        local_shard: u32,
        sharded: bool,
        topology: &crate::sharding::ShardTopology,
    ) {
        for msg in messages {
            let target_shard = crate::sharding::route_shard(
                topology,
                &crate::sharding::ShardAddress::Workchain(msg.recipient),
            );
            let is_cross_shard = sharded && (target_shard != local_shard);

            if is_cross_shard {
                let tx = crate::sharding::Transaction {
                    from: msg.sender,
                    to: msg.recipient,
                    amount: msg.value,
                    gas_limit: 100_000,
                    nonce: 0,
                    source_shard: local_shard,
                    target_shard,
                    signature: Vec::new(),
                    payload: Vec::new(),
                    priority_fee_per_gas: 0,
                };
                let mut cross_msg = crate::sharding::CrossShardMessage::new_trusted(
                    local_shard,
                    target_shard,
                    tx,
                    [0u8; 32],
                    [0u8; 32],
                );
                cross_msg.msg_id = msg.msg_id;
                cross_msg.bounce = msg.bounce;
                cross_msg.bounced = false;
                cross_shard_out.push(cross_msg);
            } else {
                let actor_msg = crate::state_engine::ActorMessage {
                    msg_id: msg.msg_id,
                    sender: msg.sender,
                    recipient: msg.recipient,
                    value: msg.value,
                    body: msg.payload.clone(),
                    bounce: msg.bounce,
                    bounced: false,
                };
                if let Some(recipient_acc) = accounts.get_mut(&msg.recipient) {
                    recipient_acc.inbox.push_back(actor_msg);
                } else if msg.bounce {
                    let bounce_msg = crate::state_engine::ActorMessage {
                        msg_id: msg.msg_id,
                        sender: msg.recipient,
                        recipient: msg.sender,
                        value: msg.value,
                        body: msg.payload.clone(),
                        bounce: false,
                        bounced: true,
                    };
                    if let Some(sender_acc) = accounts.get_mut(&msg.sender) {
                        sender_acc.inbox.push_back(bounce_msg);
                    } else {
                        let mut sender_acc = crate::state_engine::AccountState::new(msg.sender, 0);
                        sender_acc.inbox.push_back(bounce_msg);
                        accounts.insert(msg.sender, sender_acc);
                    }
                } else {
                    let mut recipient_acc =
                        crate::state_engine::AccountState::new(msg.recipient, 0);
                    recipient_acc.inbox.push_back(actor_msg);
                    accounts.insert(msg.recipient, recipient_acc);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn test_svm_contract_call_with_host_functions() {
        let code = wat::parse_str(
            r#"(module
                 (import "host" "caller" (func $caller (param i32)))
                 (import "host" "block_time" (func $block_time (result i64)))
                 (memory (export "memory") 1)
                 (func (export "check_env") (param $ptr i64) (result i64)
                   (call $caller (i32.wrap_i64 (local.get $ptr)))
                   (call $block_time)))"#,
        )
        .unwrap();

        let mut contracts = crate::contract::ContractRegistry::new();
        let creator = [0x11u8; 32];
        let addr = contracts.deploy(creator, code, 12345).unwrap();

        let sender = [0x99u8; 32];
        let mut ctx = VmContext {
            sender,
            balance: 1_000_000,
            orderbooks: None,
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            zkml_proof: None,
            timestamp: 1729000000,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: None,
            token_events: Vec::new(),
            contracts: Some(&mut contracts),
            staking: None,
            pmm: None,
            min_validator_bond: 1_000,
            default_commission_bps: 100,
            payouts: Vec::new(),
            oracle: None,
        };

        let instructions = vec![OpCode::SysCallCallContract {
            contract: addr,
            method: b"check_env".to_vec(),
            arg: 0,
        }];

        let res = Svm::execute(&instructions, 100_000, &mut ctx);
        match res {
            VmExecutionResult::Success { gas_used, .. } => {
                assert!(gas_used > 0);
            }
            other => panic!("expected Success, got {:?}", other),
        }
    }

    #[test]
    fn test_svm_contract_call_with_multiple_arguments() {
        // A method with three parameters: the opcode carries them as an
        // ordered list, so no client has to pack them into one integer.
        let code = wat::parse_str(
            r#"(module
                 (func (export "sum3") (param $a i64) (param $b i64) (param $c i64) (result i64)
                   (i64.add (i64.add (local.get $a) (local.get $b)) (local.get $c))))"#,
        )
        .unwrap();

        let mut contracts = crate::contract::ContractRegistry::new();
        let creator = [0x11u8; 32];
        let addr = contracts.deploy(creator, code, 12345).unwrap();

        let sender = [0x99u8; 32];
        let mut ctx = VmContext {
            sender,
            balance: 1_000_000,
            orderbooks: None,
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            zkml_proof: None,
            timestamp: 1729000000,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: None,
            token_events: Vec::new(),
            contracts: Some(&mut contracts),
            staking: None,
            pmm: None,
            min_validator_bond: 1_000,
            default_commission_bps: 100,
            payouts: Vec::new(),
            oracle: None,
        };

        let instructions = vec![OpCode::SysCallCallContractArgs {
            contract: addr,
            method: b"sum3".to_vec(),
            args: vec![10, 20, 12],
            calldata: Vec::new(),
        }];

        let res = Svm::execute(&instructions, 100_000, &mut ctx);
        match res {
            VmExecutionResult::Success { gas_used, .. } => {
                assert!(gas_used > 0);
            }
            other => panic!("expected Success, got {:?}", other),
        }

        // A wrong arity is refused instead of silently dropping an argument.
        let mut ctx = VmContext {
            sender,
            balance: 1_000_000,
            orderbooks: None,
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            zkml_proof: None,
            timestamp: 1729000000,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: None,
            token_events: Vec::new(),
            contracts: Some(&mut contracts),
            staking: None,
            pmm: None,
            min_validator_bond: 1_000,
            default_commission_bps: 100,
            payouts: Vec::new(),
            oracle: None,
        };
        let instructions = vec![OpCode::SysCallCallContractArgs {
            contract: addr,
            method: b"sum3".to_vec(),
            args: vec![10, 20],
            calldata: Vec::new(),
        }];
        let res = Svm::execute(&instructions, 100_000, &mut ctx);
        assert!(
            matches!(res, VmExecutionResult::Reverted(_)),
            "a two-argument call must not reach a three-parameter method"
        );
    }

    #[test]
    fn test_svm_contract_call_collects_emitted_events() {
        let code = wat::parse_str(
            r#"(module
                 (import "host" "emit" (func $emit (param i64 i64)))
                 (func (export "trigger_event") (param $val i64) (result i64)
                   (call $emit (i64.const 101) (local.get $val))
                   (call $emit (i64.const 102) (i64.add (local.get $val) (i64.const 1)))
                   (local.get $val)))"#,
        )
        .unwrap();

        let mut contracts = crate::contract::ContractRegistry::new();
        let creator = [0x22u8; 32];
        let addr = contracts.deploy(creator, code, 100).unwrap();

        let sender = [0x88u8; 32];
        let mut ctx = VmContext {
            sender,
            balance: 1_000_000,
            orderbooks: None,
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            zkml_proof: None,
            timestamp: 1729000000,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: None,
            token_events: Vec::new(),
            contracts: Some(&mut contracts),
            staking: None,
            pmm: None,
            min_validator_bond: 1_000,
            default_commission_bps: 100,
            payouts: Vec::new(),
            oracle: None,
        };

        let instructions = vec![OpCode::SysCallCallContract {
            contract: addr,
            method: b"trigger_event".to_vec(),
            arg: 555,
        }];

        let res = Svm::execute(&instructions, 100_000, &mut ctx);
        match res {
            VmExecutionResult::Success {
                ref events,
                return_value,
                ..
            } => {
                assert_eq!(return_value, Some(555));
                assert_eq!(events.len(), 2);
                assert_eq!(events[0].contract, addr);
                assert_eq!(events[0].topic, 101);
                assert_eq!(events[0].value, 555);
                assert_eq!(events[1].contract, addr);
                assert_eq!(events[1].topic, 102);
                assert_eq!(events[1].value, 556);
            }
            other => panic!("expected Success, got {:?}", other),
        }
    }

    // ------------------------------------------------------------------
    // §PQ EQUIVOCATION REPORT (audit O1/F4, PQ arm)
    // ------------------------------------------------------------------

    /// A VM context with ONLY the staking ledger wired - the shape the
    /// equivocation report needs (every other domain is irrelevant here and
    /// stays `None`, exactly like a direct `Svm::execute` caller).
    fn pq_ctx<'a>(ledger: &'a mut crate::staking::StakingLedger) -> VmContext<'a> {
        VmContext {
            sender: [0x77u8; 32],
            balance: 1_000_000,
            orderbooks: None,
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            zkml_proof: None,
            timestamp: 1_729_000_000,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: None,
            token_events: Vec::new(),
            contracts: None,
            staking: Some(ledger),
            pmm: None,
            min_validator_bond: 1_000,
            default_commission_bps: 100,
            payouts: Vec::new(),
            oracle: None,
        }
    }

    /// A PQ equivocation envelope whose BOTH signatures verify under `sk`.
    ///
    /// The validator has NO registered post-quantum key, so the ledger falls
    /// back to Ed25519 with the validator id as the public key - the same
    /// resolution the live path uses.
    fn signed_pq_evidence(
        sk: &ed25519_dalek::SigningKey,
        height: u64,
        round: u32,
        kind: crate::consensus::VoteKind,
        target_a: Option<[u8; 32]>,
        target_b: Option<[u8; 32]>,
    ) -> crate::staking::CompactPqEquivocationEvidence {
        let msg_a = crate::consensus::vote_sign_bytes(height, round, kind, &target_a);
        let msg_b = crate::consensus::vote_sign_bytes(height, round, kind, &target_b);
        crate::staking::CompactPqEquivocationEvidence {
            voter: sk.verifying_key().to_bytes(),
            height,
            round,
            kind,
            block_hash_a: target_a,
            signature_a: sk.sign(&msg_a).to_bytes().to_vec(),
            block_hash_b: target_b,
            signature_b: sk.sign(&msg_b).to_bytes().to_vec(),
        }
    }

    /// THE HAPPY PATH: a valid PQ equivocation evidence slashes the accused
    /// validator (5% of its stake) and reports the burn to the engine, which
    /// debits the staking pool.
    #[test]
    fn pq_equivocation_report_slashes_the_validator() {
        const NANO: u64 = 1_000_000_000;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let voter = sk.verifying_key().to_bytes();

        let mut ledger = crate::staking::StakingLedger::new();
        ledger.bond(voter, 1_100 * NANO, 0).unwrap();
        let before = ledger.validators[&voter].self_bond;
        let expected = before * 500 / 10_000; // EQUIVOCATION_SLASH_BPS = 5%

        let evidence = signed_pq_evidence(
            &sk,
            42,
            1,
            crate::consensus::VoteKind::Prevote,
            Some([0xA1u8; 32]),
            Some([0xB2u8; 32]),
        );

        let mut ctx = pq_ctx(&mut ledger);
        let ops = vec![OpCode::SysCallReportPqEquivocation {
            evidence: Box::new(evidence),
        }];
        match Svm::execute(&ops, 1_000_000, &mut ctx) {
            VmExecutionResult::Success {
                burns,
                return_value,
                ..
            } => {
                assert_eq!(
                    return_value,
                    Some(expected),
                    "the opcode reports the amount it burned"
                );
                assert_eq!(
                    burns,
                    vec![(crate::staking::STAKING_POOL, expected)],
                    "the burn leaves the staking pool - the engine settles it"
                );
            }
            other => panic!("expected Success, got {:?}", other),
        }

        assert_eq!(
            ledger.validators[&voter].self_bond,
            before - expected,
            "the accused validator must be slashed"
        );
        assert_eq!(ledger.total_burned, expected);
        assert_eq!(
            ledger.pq_equivocation_dedup.len(),
            1,
            "the per-offense dedup key must be consumed"
        );
    }

    /// THE FAIL-CLOSED PATH: an invalid envelope must REVERT the transaction
    /// and move NOTHING (no slash, no burn, no dedup key).
    #[test]
    fn pq_equivocation_report_rejects_invalid_evidence_fail_closed() {
        const NANO: u64 = 1_000_000_000;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let voter = sk.verifying_key().to_bytes();
        let other_sk = ed25519_dalek::SigningKey::from_bytes(&[10u8; 32]);

        let mut ledger = crate::staking::StakingLedger::new();
        ledger.bond(voter, 1_100 * NANO, 0).unwrap();
        let before = ledger.validators[&voter].self_bond;

        let good = signed_pq_evidence(
            &sk,
            7,
            0,
            crate::consensus::VoteKind::Prevote,
            Some([0x01u8; 32]),
            Some([0x02u8; 32]),
        );

        // 1. A FORGED signature (signed by somebody else).
        let mut forged = good.clone();
        let msg_b = crate::consensus::vote_sign_bytes(
            7,
            0,
            crate::consensus::VoteKind::Prevote,
            &Some([0x02u8; 32]),
        );
        forged.signature_b = other_sk.sign(&msg_b).to_bytes().to_vec();

        // 2. The SAME target twice (not an equivocation at all).
        let mut same_target = good.clone();
        same_target.block_hash_b = same_target.block_hash_a;
        let msg_same = crate::consensus::vote_sign_bytes(
            7,
            0,
            crate::consensus::VoteKind::Prevote,
            &Some([0x01u8; 32]),
        );
        same_target.signature_b = sk.sign(&msg_same).to_bytes().to_vec();

        // 3. An UNKNOWN voter (not in the ledger).
        let mut unknown = good.clone();
        unknown.voter = other_sk.verifying_key().to_bytes();

        for (label, ev) in [
            ("forged signature", forged),
            ("same target", same_target),
            ("unknown voter", unknown),
        ] {
            let mut ctx = pq_ctx(&mut ledger);
            let ops = vec![OpCode::SysCallReportPqEquivocation {
                evidence: Box::new(ev),
            }];
            match Svm::execute(&ops, 1_000_000, &mut ctx) {
                VmExecutionResult::Reverted(reason) => {
                    assert!(
                        reason.contains("PQ equivocation evidence rejected"),
                        "the refusal must name the reason ({label}): {reason}"
                    );
                }
                other => panic!("{label}: expected Reverted, got {other:?}"),
            }
            assert_eq!(
                ledger.validators[&voter].self_bond, before,
                "{label}: an invalid report must not slash anything"
            );
            assert_eq!(ledger.total_burned, 0, "{label}: nothing may be burned");
            assert!(
                ledger.pq_equivocation_dedup.is_empty(),
                "{label}: an invalid report must not consume the dedup key"
            );
        }
    }

    /// A REPORT WITH NO LEDGER (direct `Svm::execute` callers) must fail
    /// closed instead of silently succeeding: there is nothing to check
    /// membership against.
    #[test]
    fn pq_equivocation_report_without_a_ledger_reverts() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let evidence = signed_pq_evidence(
            &sk,
            3,
            0,
            crate::consensus::VoteKind::Precommit,
            Some([0x05u8; 32]),
            Some([0x06u8; 32]),
        );
        let mut ledger = crate::staking::StakingLedger::new();
        let mut ctx = pq_ctx(&mut ledger);
        ctx.staking = None;
        let ops = vec![OpCode::SysCallReportPqEquivocation {
            evidence: Box::new(evidence),
        }];
        match Svm::execute(&ops, 1_000_000, &mut ctx) {
            VmExecutionResult::Reverted(reason) => {
                assert!(reason.contains("Staking ledger not available"), "{reason}");
            }
            other => panic!("expected Reverted, got {other:?}"),
        }
    }

    /// The gas table and the dispatch loop must agree on the price of the
    /// PQ report (the same contract the other priced opcodes hold).
    #[test]
    fn pq_equivocation_report_gas_matches_the_priced_table() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]);
        let evidence = signed_pq_evidence(
            &sk,
            1,
            0,
            crate::consensus::VoteKind::Prevote,
            Some([0x07u8; 32]),
            Some([0x08u8; 32]),
        );
        let wire_len = evidence.wire_len();
        let op = OpCode::SysCallReportPqEquivocation {
            evidence: Box::new(evidence),
        };
        assert_eq!(
            opcode_gas(&op),
            equivocation_report_gas(wire_len),
            "the priced table and the helper must agree"
        );
        assert!(
            opcode_gas(&op) >= GAS_EQUIVOCATION_REPORT_BASE,
            "the PQ report must not be cheaper than the base equivocation report"
        );
    }

    // ------------------------------------------------------------------
    // §PROPOSAL EQUIVOCATION REPORT (P3-EQ-ESCAPE variant 2)
    // ------------------------------------------------------------------

    /// A proposal-evidence envelope whose BOTH blocks verify under `sk`.
    fn signed_proposal_evidence(
        sk: &ed25519_dalek::SigningKey,
        height: u64,
        t1: u64,
        t2: u64,
    ) -> crate::consensus::ProposalEquivocationEvidence {
        let mk = |ts: u64| {
            let mut b = crate::sharding::Block {
                height,
                proposer: sk.verifying_key().to_bytes(),
                timestamp: ts,
                ..Default::default()
            };
            b.sign_block(sk);
            b
        };
        crate::consensus::ProposalEquivocationEvidence::new(
            sk.verifying_key().to_bytes(),
            mk(t1),
            mk(t2),
        )
    }

    /// THE HAPPY PATH: a valid proposal evidence is ACCEPTED by the carrier
    /// (stack 1) and moves NOTHING — no coins, no ledger state. The slash
    /// itself fires at the block step, which re-verifies from block bytes;
    /// pinning the carrier's purity here is what keeps exec/scan skew
    /// harmless.
    #[test]
    fn proposal_equivocation_report_carries_valid_evidence_without_slashing() {
        const NANO: u64 = 1_000_000_000;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
        let proposer = sk.verifying_key().to_bytes();

        let mut ledger = crate::staking::StakingLedger::new();
        ledger.bond(proposer, 1_100 * NANO, 0).unwrap();
        let before = ledger.validators[&proposer].self_bond;

        let evidence = signed_proposal_evidence(&sk, 9, 1_000, 2_000);
        assert_ne!(
            evidence.block_a.compute_hash(),
            evidence.block_b.compute_hash(),
            "need two distinct bodies"
        );

        let mut ctx = pq_ctx(&mut ledger);
        let ops = vec![OpCode::SysCallReportProposalEquivocation {
            evidence: Box::new(evidence),
        }];
        match Svm::execute(&ops, 10_000_000, &mut ctx) {
            VmExecutionResult::Success { burns, .. } => {
                assert!(burns.is_empty(), "the carrier moves no coins");
            }
            other => panic!("expected Success, got {other:?}"),
        }

        assert_eq!(
            ledger.validators[&proposer].self_bond, before,
            "the carrier must not slash — the block step does that"
        );
        assert_eq!(ledger.total_burned, 0);
        assert!(
            ledger.equivocation_dedup.is_empty(),
            "the carrier must not consume the dedup key"
        );
    }

    /// THE FAIL-CLOSED PATH: an invalid proposal envelope must REVERT the
    /// transaction and move NOTHING.
    #[test]
    fn proposal_equivocation_report_rejects_invalid_evidence_fail_closed() {
        const NANO: u64 = 1_000_000_000;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[22u8; 32]);
        let proposer = sk.verifying_key().to_bytes();

        let mut ledger = crate::staking::StakingLedger::new();
        ledger.bond(proposer, 1_100 * NANO, 0).unwrap();
        let before = ledger.validators[&proposer].self_bond;

        let good = signed_proposal_evidence(&sk, 9, 1_000, 2_000);

        // 1. The SAME body twice (one proposal repeated is not an offense).
        let same = {
            let one = good.block_a.clone();
            crate::consensus::ProposalEquivocationEvidence::new(proposer, one.clone(), one)
        };

        // 2. A FORGED block (signature byte flipped after signing).
        let mut forged = good.clone();
        forged.block_b.validator_signatures[0].1[0] ^= 0xFF;

        // 3. An UNKNOWN proposer (not in the ledger).
        let outsider = ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]);
        let unknown = signed_proposal_evidence(&outsider, 9, 1_000, 2_000);

        for (label, ev) in [
            ("same body", same),
            ("forged block", forged),
            ("unknown proposer", unknown),
        ] {
            let mut ctx = pq_ctx(&mut ledger);
            let ops = vec![OpCode::SysCallReportProposalEquivocation {
                evidence: Box::new(ev),
            }];
            match Svm::execute(&ops, 10_000_000, &mut ctx) {
                VmExecutionResult::Reverted(reason) => {
                    assert!(
                        reason.contains("proposal equivocation evidence rejected"),
                        "the refusal must name the reason ({label}): {reason}"
                    );
                }
                other => panic!("{label}: expected Reverted, got {other:?}"),
            }
            assert_eq!(
                ledger.validators[&proposer].self_bond, before,
                "{label}: an invalid report must not slash anything"
            );
            assert_eq!(ledger.total_burned, 0, "{label}: nothing may be burned");
            assert!(
                ledger.equivocation_dedup.is_empty(),
                "{label}: an invalid report must not consume the dedup key"
            );
        }
    }

    /// A REPORT WITH NO LEDGER must fail closed: there is nothing to check
    /// membership against.
    #[test]
    fn proposal_equivocation_report_without_a_ledger_reverts() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[24u8; 32]);
        let evidence = signed_proposal_evidence(&sk, 9, 1_000, 2_000);
        let mut ledger = crate::staking::StakingLedger::new();
        let mut ctx = pq_ctx(&mut ledger);
        ctx.staking = None;
        let ops = vec![OpCode::SysCallReportProposalEquivocation {
            evidence: Box::new(evidence),
        }];
        match Svm::execute(&ops, 10_000_000, &mut ctx) {
            VmExecutionResult::Reverted(reason) => {
                assert!(reason.contains("envelope does not verify"), "{reason}");
            }
            other => panic!("expected Reverted, got {other:?}"),
        }
    }

    /// The gas table and the dispatch loop must agree on the price of the
    /// proposal report (the same contract the other priced opcodes hold).
    #[test]
    fn proposal_equivocation_report_gas_matches_the_priced_table() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[25u8; 32]);
        let evidence = signed_proposal_evidence(&sk, 9, 1_000, 2_000);
        let wire_len = evidence.wire_len();
        let op = OpCode::SysCallReportProposalEquivocation {
            evidence: Box::new(evidence),
        };
        assert_eq!(
            opcode_gas(&op),
            equivocation_report_gas(wire_len),
            "the priced table and the helper must agree"
        );
        assert!(
            opcode_gas(&op) >= GAS_EQUIVOCATION_REPORT_BASE,
            "the proposal report must not be cheaper than the base equivocation report"
        );
    }

    // ------------------------------------------------------------------
    // §STAKE WITH COMMISSION (E1b: wallet --commission-bps end-to-end)
    // ------------------------------------------------------------------

    /// A NEW validator bonds with the transaction-supplied commission, not
    /// the governance default.
    #[test]
    fn stake_with_commission_sets_the_supplied_rate_on_new_bond() {
        const NANO: u64 = 1_000_000_000;
        let mut ledger = crate::staking::StakingLedger::new();
        let mut ctx = pq_ctx(&mut ledger);
        ctx.balance = 10_000 * NANO;
        let val = [0x51u8; 32];
        let ops = vec![OpCode::SysCallStakeWithCommission {
            validator: val,
            amount: 2_000 * NANO,
            commission_bps: 2_500,
        }];
        match Svm::execute(&ops, 1_000_000, &mut ctx) {
            VmExecutionResult::Success { transfers, .. } => {
                assert_eq!(
                    transfers,
                    vec![(crate::staking::STAKING_POOL, 2_000 * NANO)]
                );
            }
            other => panic!("expected Success, got {other:?}"),
        }
        assert_eq!(ledger.validators[&val].commission_bps, 2_500);
        assert_eq!(ledger.validators[&val].self_bond, 2_000 * NANO);
    }

    /// A TOP-UP keeps the commission the validator registered with:
    /// commission is IMMUTABLE after bonding, even when the top-up names a
    /// different rate.
    #[test]
    fn stake_with_commission_top_up_keeps_the_registered_rate() {
        const NANO: u64 = 1_000_000_000;
        let mut ledger = crate::staking::StakingLedger::new();
        let mut ctx = pq_ctx(&mut ledger);
        ctx.balance = 10_000 * NANO;
        let val = [0x52u8; 32];
        let first = vec![OpCode::SysCallStakeWithCommission {
            validator: val,
            amount: 2_000 * NANO,
            commission_bps: 1_000,
        }];
        assert!(matches!(
            Svm::execute(&first, 1_000_000, &mut ctx),
            VmExecutionResult::Success { .. }
        ));
        // A top-up naming a DIFFERENT commission must not move the rate.
        let top_up = vec![OpCode::SysCallStakeWithCommission {
            validator: val,
            amount: 500 * NANO,
            commission_bps: 9_999,
        }];
        assert!(matches!(
            Svm::execute(&top_up, 1_000_000, &mut ctx),
            VmExecutionResult::Success { .. }
        ));
        assert_eq!(ledger.validators[&val].commission_bps, 1_000);
        assert_eq!(ledger.validators[&val].self_bond, 2_500 * NANO);
    }

    /// Commission above 10_000 bps, a zero amount, and a below-floor amount
    /// all REVERT with a clear reason and move nothing.
    #[test]
    fn stake_with_commission_rejects_bad_rates_and_bad_amounts_fail_closed() {
        const NANO: u64 = 1_000_000_000;
        let mut ledger = crate::staking::StakingLedger::new();
        let val = [0x53u8; 32];
        for (label, amount, commission, expect) in [
            (
                "commission over 100%",
                2_000 * NANO,
                10_001u64,
                "commission must be <=",
            ),
            ("zero amount", 0u64, 500u64, "must be positive"),
            ("below-floor amount", 999u64, 500u64, "governed minimum"),
        ] {
            let refused = {
                let mut ctx = pq_ctx(&mut ledger);
                ctx.balance = 10_000 * NANO;
                let ops = vec![OpCode::SysCallStakeWithCommission {
                    validator: val,
                    amount,
                    commission_bps: commission,
                }];
                match Svm::execute(&ops, 1_000_000, &mut ctx) {
                    VmExecutionResult::Reverted(reason) => {
                        assert!(
                            reason.contains(expect),
                            "{label}: expected reason containing {expect:?}, got {reason:?}"
                        );
                        reason
                    }
                    other => panic!("{label}: expected Reverted, got {other:?}"),
                }
            };
            assert!(!refused.is_empty());
            assert!(
                !ledger.validators.contains_key(&val),
                "{label}: a refused bond must not register the validator"
            );
        }
    }
}
