//! Differential tests for the O1x behaviour-preserving optimisations.
//!
//! O11 lives here because the public `HeightConsensus` surface is enough to
//! drive it end-to-end; the others need private access and live in their
//! module's own test module.

use stellereum::consensus::{HeightConsensus, Round, ValidatorId, ValidatorSet};

/// Test-local copy of the ORIGINAL O(N^2) `corroborated_peer_round`.
fn old_corroborated_peer_round(hc: &HeightConsensus, validators: &ValidatorSet) -> Option<Round> {
    let mut rounds: Vec<Round> = hc.peer_rounds.values().copied().collect();
    rounds.sort_unstable_by(|a, b| b.cmp(a));
    rounds.dedup();
    rounds.into_iter().find(|r| {
        let total = validators.total_power_exact();
        let power: u128 = hc
            .peer_rounds
            .iter()
            .filter(|(_, peer_round)| *peer_round >= r)
            .map(|(voter, _)| validators.power_of(voter) as u128)
            .sum();
        total > 0 && power.saturating_mul(3) > total
    })
}

fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

#[test]
fn o11_corroborated_peer_round_matches_double_loop() {
    let mut seed: u64 = 0x5EED_1234_ABCD_9876;
    for iter in 0..400u32 {
        let n = 1 + (lcg(&mut seed) % 40) as usize;
        let mut vs = ValidatorSet::new();
        for i in 0..n {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&(i as u32).to_le_bytes());
            id[4..8].copy_from_slice(&iter.to_le_bytes());
            id[9] = 0x11;
            let power = match lcg(&mut seed) % 7 {
                0 => 0, // zero-power peers (never corroborate anything)
                1 => 1,
                2 => 7,
                3 => 1_000,
                4 => 1_000_000_000_000,
                5 => u64::MAX / (n as u64 + 1),
                _ => lcg(&mut seed) % 10_000,
            };
            vs.add(id, power);
        }
        let mut hc = HeightConsensus::new(9, vs.clone());
        // Random reported rounds: duplicates (ties), zero-power reporters,
        // absent peers and extreme rounds.
        let ids: Vec<ValidatorId> = vs.validators.keys().copied().collect();
        for (i, id) in ids.iter().enumerate() {
            if lcg(&mut seed).is_multiple_of(5) {
                continue; // this peer reported nothing
            }
            let round = match lcg(&mut seed) % 8 {
                0 => 0,
                1 => 1,
                2 => 2,
                3 => 7,
                4 => 8,
                5 => 100,
                6 => u32::MAX,
                _ => (lcg(&mut seed) % 12) as Round,
            };
            hc.note_peer_round(*id, round);
            // Occasionally bump the same peer again; the map keeps the max.
            if lcg(&mut seed).is_multiple_of(4) {
                let r2 = (lcg(&mut seed) % 12) as Round;
                hc.note_peer_round(ids[(i + 1) % ids.len()], r2);
            }
        }
        let old = old_corroborated_peer_round(&hc, &vs);
        let new = hc.corroborated_peer_round();
        assert_eq!(old, new, "iteration {iter}: n={n} rounds diverged");
    }
}

#[test]
fn o11_empty_and_all_zero_power_edges() {
    let mut vs = ValidatorSet::new();
    let mut hc = HeightConsensus::new(1, vs.clone());
    assert_eq!(hc.corroborated_peer_round(), None);
    assert_eq!(old_corroborated_peer_round(&hc, &vs), None);

    // Zero total power can never corroborate, however many peers report.
    vs.add([1u8; 32], 0);
    vs.add([2u8; 32], 0);
    hc = HeightConsensus::new(1, vs.clone());
    hc.note_peer_round([1u8; 32], u32::MAX);
    hc.note_peer_round([2u8; 32], u32::MAX);
    assert_eq!(hc.corroborated_peer_round(), None);
    assert_eq!(old_corroborated_peer_round(&hc, &vs), None);

    // Exactly one third is NOT enough (the floor is strictly more than 1/3).
    let mut vs3 = ValidatorSet::new();
    for i in 0..3u8 {
        vs3.add([i + 10; 32], 100);
    }
    let mut hc3 = HeightConsensus::new(1, vs3.clone());
    hc3.note_peer_round([10u8; 32], 5);
    assert_eq!(hc3.corroborated_peer_round(), None);
    assert_eq!(old_corroborated_peer_round(&hc3, &vs3), None);
    // A second reporter crosses it.
    hc3.note_peer_round([11u8; 32], 5);
    assert_eq!(hc3.corroborated_peer_round(), Some(5));
    assert_eq!(old_corroborated_peer_round(&hc3, &vs3), Some(5));
    // A single reporter at a higher round is NOT corroborated (exactly 1/3);
    // a second one at that round makes it the highest corroborated round.
    hc3.note_peer_round([12u8; 32], 9);
    assert_eq!(hc3.corroborated_peer_round(), Some(5));
    assert_eq!(old_corroborated_peer_round(&hc3, &vs3), Some(5));
    hc3.note_peer_round([10u8; 32], 9);
    assert_eq!(hc3.corroborated_peer_round(), Some(9));
    assert_eq!(old_corroborated_peer_round(&hc3, &vs3), Some(9));
}

/// O14: the memoised proposer must equal the uncached draw for every input,
/// and every replacement of the schedule/beacon/validator set must be a miss
/// (a stale answer is impossible).
#[test]
fn o14_proposer_cache_matches_uncached_and_never_goes_stale() {
    use stellereum::consensus::{cnvrf_v3_epoch_of_height, CommitteeSchedule, EpochBeacon};

    let mut vs = ValidatorSet::new();
    for i in 0..9u8 {
        let mut id = [0u8; 32];
        id[0] = i + 1;
        id[5] = 0xC3;
        vs.add(id, 100 + (i as u64) * 37);
    }
    let mut hc = HeightConsensus::new(100, vs.clone());
    let direct = |hc: &HeightConsensus| {
        hc.validators
            .proposer_for_with_schedule(hc.height, hc.round, hc.committee_schedule)
    };

    let beacon_a = EpochBeacon {
        epoch: cnvrf_v3_epoch_of_height(100),
        output: [0xA1; 48],
    };
    let beacon_b = EpochBeacon {
        epoch: cnvrf_v3_epoch_of_height(100),
        output: [0xB2; 48],
    };
    let schedules = [
        CommitteeSchedule::ParentHash,
        CommitteeSchedule::Beacon(None),
        CommitteeSchedule::Beacon(Some(beacon_a)),
        CommitteeSchedule::Beacon(Some(beacon_b)),
    ];

    let mut seed: u64 = 0x0F1E_2D3C_4B5A_6978;
    for _ in 0..2_000 {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        hc.height = 100 + (seed % 500);
        hc.round = ((seed >> 20) % 40) as Round;
        let schedule = schedules[((seed >> 33) % schedules.len() as u64) as usize];
        if hc.committee_schedule != schedule {
            hc.set_committee_schedule(schedule);
        }
        // Beacon epochs must match the CURRENT height for a `Some` beacon to
        // be usable; build one on the fly when the random height moved.
        if let CommitteeSchedule::Beacon(Some(mut beacon)) = hc.committee_schedule {
            beacon.epoch = cnvrf_v3_epoch_of_height(hc.height);
            hc.committee_schedule = CommitteeSchedule::Beacon(Some(beacon));
        }
        let want = direct(&hc);
        assert_eq!(hc.proposer(), want, "cached proposer diverged");
        // A second identical call is the cache hit.
        assert_eq!(hc.proposer(), want);
    }

    // Repeated same (height, round) is a cache hit and stays correct after the
    // round moves and comes back.
    hc.height = 777;
    hc.round = 3;
    hc.set_committee_schedule(CommitteeSchedule::ParentHash);
    let at_r3 = hc.proposer();
    assert_eq!(at_r3, direct(&hc));
    hc.round = 4;
    let at_r4 = hc.proposer();
    assert_eq!(at_r4, direct(&hc));
    hc.round = 3;
    assert_eq!(hc.proposer(), at_r3);

    // VALIDATOR SET REPLACED directly (the runtime installs a freshly rotated
    // set on this field): the fingerprint misses, never a stale proposer.
    let mut vs2 = vs.clone();
    for i in 0..9u8 {
        let mut id = [0u8; 32];
        id[0] = i + 1;
        id[5] = 0xC3;
        vs2.add(id, 1 + (i as u64) * 1_000_003);
    }
    hc.validators = vs2.clone();
    assert_eq!(hc.proposer(), direct(&hc));

    // SCHEDULE/BEACON REPLACED through the setter: the answer must follow.
    hc.set_committee_schedule(CommitteeSchedule::Beacon(None));
    assert_eq!(hc.proposer(), None);
    assert_eq!(hc.proposer(), direct(&hc));
    let epoch = cnvrf_v3_epoch_of_height(hc.height);
    let beacon = EpochBeacon {
        epoch,
        output: [0x5C; 48],
    };
    hc.set_committee_schedule(CommitteeSchedule::Beacon(Some(beacon)));
    assert_eq!(hc.proposer(), direct(&hc));
    let before = hc.proposer();
    let mut changed = false;
    for k in 0..50u8 {
        let next = EpochBeacon {
            epoch,
            output: [k; 48],
        };
        hc.set_committee_schedule(CommitteeSchedule::Beacon(Some(next)));
        // EVERY replacement must be followed exactly (never the old draw)...
        let want = direct(&hc);
        assert_eq!(hc.proposer(), want, "stale proposer after beacon {k}");
        if want != before {
            changed = true;
            break;
        }
    }
    // ...and at least one of 50 distinct beacons must move the proposer, so
    // the loop above really exercised a changed answer.
    assert!(changed, "expected a beacon to change the proposer");
}

/// O5: the single-pass `derived address -> Falcon half` index assembles the
/// SAME µQC envelope bytes as the old per-member linear scan, over randomised
/// vote sets that exercise all three lookup arms (exact id, derived id,
/// reverse derived id).
#[test]
fn o5_uqc_assembly_matches_linear_scan() {
    use std::collections::HashMap;
    use stellereum::consensus::{
        attach_vote_falcon_sig, committee_for_height, encode_pq_micro_envelope,
        micro_committee_size, pq_key_at_height, register_validator_pq_key, CommitteeSchedule,
        FalconKeypair, PqMicroCertificate, Vote, VoteKind, VoteSet,
    };
    use stellereum::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN};

    const H: u64 = 777;
    const R: u32 = 2;
    let target = [0x44u8; 32];
    let parent = [0x33u8; 32];

    let mut vs = ValidatorSet::new();
    let mut regulars: Vec<(stellereum::consensus::ValidatorId, FalconKeypair)> = Vec::new();
    for i in 0..9u8 {
        let id = [0x10 + i; 32];
        vs.add(id, 1_000);
        let kp = FalconKeypair::generate_from_seed(0x80 + i);
        register_validator_pq_key(id, PqScheme::Falcon512, kp.public_key.clone());
        regulars.push((id, kp));
    }

    // W's key derives the validator id V. V does NOT vote and has NO
    // registered key of its own: resolving it can only happen through the
    // old linear tail (O5's reverse index).
    let kw = FalconKeypair::generate_from_seed(0x70);
    let v_id = derive_pq_address(PqScheme::Falcon512, &kw.public_key, &DEFAULT_SALT);
    let w_id = [0x21u8; 32];
    vs.add(w_id, 1_000);
    register_validator_pq_key(w_id, PqScheme::Falcon512, kw.public_key.clone());
    vs.add(v_id, 1);

    // V2's registered key derives A2; A2 votes. V2 does not vote, so resolving
    // V2 goes through the old "derive val_id then look up falcon_sigs[addr]"
    // arm.
    let k2 = FalconKeypair::generate_from_seed(0x60);
    let a2_id = derive_pq_address(PqScheme::Falcon512, &k2.public_key, &DEFAULT_SALT);
    let v2_id = [0x22u8; 32];
    vs.add(v2_id, 1);
    register_validator_pq_key(v2_id, PqScheme::Falcon512, k2.public_key.clone());
    vs.add(a2_id, 1);
    register_validator_pq_key(a2_id, PqScheme::Falcon512, k2.public_key.clone());

    // Test-local copy of the ORIGINAL lookup.
    fn old_lookup(
        val_id: &stellereum::consensus::ValidatorId,
        falcon_sigs: &HashMap<stellereum::consensus::ValidatorId, Vec<u8>>,
        height: u64,
    ) -> Option<Vec<u8>> {
        if let Some(sig) = falcon_sigs.get(val_id) {
            return Some(sig.clone());
        }
        if let Some((scheme, pk)) = pq_key_at_height(val_id, height) {
            let addr = derive_pq_address(scheme, &pk, &DEFAULT_SALT);
            if let Some(sig) = falcon_sigs.get(&addr) {
                return Some(sig.clone());
            }
        }
        for (voter, sig) in falcon_sigs {
            if let Some((scheme, pk)) = pq_key_at_height(voter, height) {
                let addr = derive_pq_address(scheme, &pk, &DEFAULT_SALT);
                if addr == *val_id {
                    return Some(sig.clone());
                }
            }
        }
        None
    }

    let csize = micro_committee_size(vs.len());
    let committee = committee_for_height(
        &vs,
        H,
        R,
        csize,
        Some(&parent),
        CommitteeSchedule::ParentHash,
    );
    assert_eq!(committee.len(), vs.len(), "whole set is the committee");
    assert!(committee.contains(&v_id) && committee.contains(&v2_id));

    let mut seed: u64 = 0xA5A5_1234_5678_9ABC;
    for iter in 0..40u32 {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let mut set = VoteSet::new();
        // 6..=9 regular voters keeps the signed power above the network 2/3.
        let take = 6 + (seed % 4) as usize;
        let offset = ((seed >> 9) as usize) % regulars.len();
        for k in 0..take {
            let (id, kp) = &regulars[(offset + k) % regulars.len()];
            let mut sig = vec![0u8; 64];
            let falcon = vec![(seed >> (k % 40)) as u8; FALCON512_SIG_LEN];
            attach_vote_falcon_sig(&falcon, &mut sig);
            // Keep the key's public half live for the registry read.
            let _ = kp.public_key.len();
            set.add_verified_in_scope(
                Vote::signed_with_in_shard(*id, 0, H, R, VoteKind::Precommit, Some(target), sig),
                &vs,
                H,
                R,
                VoteKind::Precommit,
            )
            .expect("voter is a validator in scope");
        }
        // W votes; A2 votes.
        for voter in [&w_id, &a2_id] {
            let mut sig = vec![0u8; 64];
            let falcon = vec![voter[0]; FALCON512_SIG_LEN];
            attach_vote_falcon_sig(&falcon, &mut sig);
            set.add_verified_in_scope(
                Vote::signed_with_in_shard(*voter, 0, H, R, VoteKind::Precommit, Some(target), sig),
                &vs,
                H,
                R,
                VoteKind::Precommit,
            )
            .expect("voter is a validator in scope");
        }

        let qc = set
            .certificate_with_schedule(
                Some(target),
                &vs,
                Some(&parent),
                CommitteeSchedule::ParentHash,
            )
            .expect("certificate");
        let actual = qc
            .pq_micro_certificate()
            .unwrap_or_else(|| panic!("iteration {iter}: µQC must compile"));

        // Reference assembly with the OLD lookup.
        let falcon_sigs: HashMap<_, _> = set
            .falcon_signatures_for_target(Some(target))
            .into_iter()
            .collect();
        assert!(!falcon_sigs.is_empty());
        let mut bitmask = vec![0u8; (csize as usize).div_ceil(8)];
        let mut sigs = Vec::new();
        for (i, member) in committee.iter().enumerate() {
            if let Some(sig) = old_lookup(member, &falcon_sigs, H) {
                bitmask[i / 8] |= 1 << (i % 8);
                sigs.push(sig);
            }
        }
        let expected =
            PqMicroCertificate::new(PqScheme::Falcon512, H, R, csize, bitmask, sigs, parent);
        assert_eq!(
            encode_pq_micro_envelope(&actual),
            encode_pq_micro_envelope(&expected),
            "iteration {iter}: µQC envelope bytes differ"
        );
        // And the whole certificate serialises identically once the marker is
        // replaced by the reference payload (the Ed list is not touched by O5).
        let mut expected_qc = qc.clone();
        expected_qc.attach_pq_micro_certificate(&expected);
        assert_eq!(
            bincode::serialize(&qc).expect("qc encodes"),
            bincode::serialize(&expected_qc).expect("qc encodes"),
            "iteration {iter}: certificate bytes differ"
        );
    }
}

/// O7: the single-buffer borrowed batch encoder emits byte-for-byte the frame
/// the old deep-cloning path produced, for randomised batches including a
/// proposal-sized member.
#[test]
fn o7_batch_frame_bytes_match_deep_clone_path() {
    use std::borrow::Cow;
    use stellereum::consensus::{Vote, VoteKind};
    use stellereum::consensus_net::{encode_broadcast_payload, ConsensusMsg};
    use stellereum::sharding::Block;

    let topic = "stellereum-consensus-test";
    let mut seed: u64 = 0x0BEE_F00D_1234_5678;
    let mut next = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        seed
    };

    // Proposal-sized body: a large opaque evidence list encodes a member that
    // dwarfs every vote in the batch (still well below MAX_BATCH_BYTES).
    let big = Block {
        height: 9_999,
        proposer: [0x77u8; 32],
        validator_signatures: vec![([0x66u8; 32], vec![0xAB; 180_000])],
        ..Block::default()
    };

    for iter in 0..200u32 {
        let count = 1 + (next() % 8) as usize;
        let mut msgs: Vec<ConsensusMsg> = Vec::with_capacity(count);
        for k in 0..count {
            match (next() >> 8) % 4 {
                0 | 1 => {
                    let len = (next() % 900) as usize;
                    let voter = [(((iter + k as u32) % 251) as u8); 32];
                    msgs.push(ConsensusMsg::Vote {
                        vote: Vote::signed_with_in_shard(
                            voter,
                            0,
                            next() % 1000,
                            (next() % 20) as u32,
                            VoteKind::Prevote,
                            Some([0x11; 32]),
                            vec![0x5A; len],
                        ),
                        locked: if next() % 2 == 0 {
                            None
                        } else {
                            Some([0x22; 32])
                        },
                    });
                }
                2 => msgs.push(ConsensusMsg::Proposal {
                    height: next() % 1000,
                    round: (next() % 20) as u32,
                    block: if k == 0 {
                        big.clone()
                    } else {
                        Block::default()
                    },
                }),
                _ => {
                    // Nil vote (block_hash = None) covers the other Option arm.
                    msgs.push(ConsensusMsg::Vote {
                        vote: Vote::signed_with_in_shard(
                            [0x33; 32],
                            0,
                            next() % 1000,
                            (next() % 20) as u32,
                            VoteKind::Precommit,
                            None,
                            Vec::new(),
                        ),
                        locked: None,
                    });
                }
            }
        }

        // ---- reference: the old deep-clone implementation ----
        let expected = if msgs.len() == 1 {
            let bytes = msgs[0].encode().expect("single encodes");
            (bytes, false)
        } else {
            let owned: Vec<ConsensusMsg> = msgs.to_vec();
            let bytes = ConsensusMsg::batch_encode_owned(owned).expect("batch encodes");
            (bytes, true)
        };
        let expected_data = hex::encode(&expected.0);
        let expected_payload = serde_json::json!({ "topic": topic, "data": &expected_data })
            .to_string()
            .into_bytes();

        // ---- actual: borrowed single-buffer path ----
        let cows: Vec<Cow<'_, ConsensusMsg>> = msgs.iter().map(Cow::Borrowed).collect();
        let frame = encode_broadcast_payload(topic, &cows).expect("frame encodes");
        assert_eq!(frame.payload, expected_payload, "iteration {iter}");
        assert_eq!(frame.data, expected_data, "iteration {iter}");
        assert_eq!(frame.encoded_len, expected.0.len(), "iteration {iter}");
        assert_eq!(frame.is_batch, expected.1, "iteration {iter}");
    }

    // Empty batch is refused exactly like the owned encoder.
    assert!(encode_broadcast_payload(topic, &[]).is_err());
    assert!(ConsensusMsg::batch_encode_owned(Vec::new()).is_err());
}
