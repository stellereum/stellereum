use stellereum::storage::Storage;

#[test]
fn test_inspect_qc_at_node_b() {
    let p = std::path::Path::new("/home/imm/multinode/nodeB/data");
    if !p.exists() {
        println!("Path does not exist");
        return;
    }
    let storage = match Storage::open(p) {
        Ok(s) => s,
        Err(e) => {
            println!("Storage open failed: {e}");
            return;
        }
    };
    let (h, hash) = storage.finalized().unwrap().unwrap();
    println!("NodeB finalized: height={h}, hash={}", hex::encode(hash));

    // Read the finalized block
    if let Ok(Some(blk)) = storage.get_block(&hash) {
        println!(
            "Final block: height={} precommit_qc={:?}",
            blk.height,
            blk.precommit_qc.is_some()
        );
        if let Some(ref qc) = blk.precommit_qc {
            println!(
                "  QC: height={} round={} kind={:?} sigs_len={}",
                qc.height,
                qc.round,
                qc.kind,
                qc.signatures.len()
            );
            for (vid, sig) in &qc.signatures {
                println!(
                    "    signer={}: sig_len={}",
                    hex::encode(&vid[..6]),
                    sig.len()
                );
            }
        }
    }

    if let Ok(Some(domain_bytes)) = storage.domain_at(h) {
        if let Ok(domains) = stellereum::storage::decode_domain_snapshot(&domain_bytes) {
            let vs = domains.staking.to_validator_set();
            println!(
                "Staking ledger at {h}: len={} total_power={} quorum={}",
                vs.len(),
                vs.total_power(),
                vs.quorum_power()
            );
            for (id, p) in &vs.validators {
                println!("  validator {}: power={}", hex::encode(&id[..6]), p);
            }
        }
    }
}
