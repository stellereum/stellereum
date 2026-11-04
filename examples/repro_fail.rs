//! Reproduce the live failure locally: fund the faucet address, advance it
//! to nonce 4 via dust txs (registering the key like the live chain did),
//! then apply the EXACT raw bytes of the failed live tx and print the error.

use anyhow::{Context, Result};

const RAW_HEX: &str = "eff75acfeb416b7e7c48f0c2db79462073e20f86bbd34d2fba03158d80443ea3eff75acfeb416b7e7c48f0c2db79462073e20f86bbd34d2fba03158d80443ea30100000000000000305705000000000004000000000000000000000000000000240600000000000050513102008103092498c0f41e647356ad3cc2b9af024348a46aad08781a460437d7eafa08cab4fbc903088dc900e084cd919ff5ca0b8b1ab2b284368470418c22fe0b3b8e157b2731b743de610d2bf42b8298117757b586e3f781f670c6d694d4e1ad1718cd51965a092902d0f0b59230a8682bd84a2bbb0c78b86967a1395a761335b6a9a618797bfa6ad3541b4096194a49451a5ce79a0d19009e02e966c46c0064267839464ae30a4166a07d087930803f66d658315d4466180c0cd53a08f2f272d0290be86fa0c6a0aab088f28ae1c8d1502a74e1cc08960864cca12b23e28ee98580abca215fd8db92ea1e2d60dc9b4b262072a822b2880b524f7944cf317866ce3fde0812b1493131e8f528c4c25a92701c96506d0f735c884a6108ca08502353dbe7313a42d9118983a1675400b9bacb2d775c12b513666d240000ca2b6cc09d91dff79f5bec92d52fd09695a331e94f621d8c9b870296b597ef030a18392a9e011e090485aa6c2f0d5964d83785a57c48c823b8bfecf538b55662054e150e5676f1f9022f38d5267156964ca35900b3b25444496dc549531a1983b908f620010242d90228355b018f18227917ceea8a7c156a93807739f2368128cec557086d83b9d9400bb8679368dd57643cdff99801b27990cb70f0c61e62518173bd888a5b10fba91cabfbb69a21b558081833891534484d0d25dd28267f94ba0f253441076c5b8dd8aca02d9b6863a4947b71ac64a288eca2348614a45d24747251863c685f1a62e51f910281d2160ff8648933695ae5241d14fc5342d6c48235c55a9dd1c97018bc0591a2dc58d815bba0ea1c36286502c944204e0876536992354246de0041adffb314b99afaa0429bc2c18aa29efb19f4830253210b72b6b3cb6f520952a190317f1cd162d233db3283c521c9d3f10a241655f0dcd2bd919f090c09407096421264f7540bd7e64fec4274c322b3bacdc702abac92ba51438a7ac4f669086c911ed22391c676e3a980a54acc32d00e238352aa99575711b78ba2cbf86b4f6b2d2551abad607936d64338fc177ca716f3520a909e6a116ad4d1ef6c501553600682876e8cd41bcd46ff6b9068d24a1f93b98988a6a0ab6515f5589be48a5c62e52ad9d0d8c1189039c95f0aec52e94972d446fa73609b4868d47b036587167110825941c0611deb141e11ecf83d5b3d27f56720002b1bbac924454463f95e4ec6103b59e8a0d274ea379f3d1e263c63b015dcbe0a39b1cb8848243c85b2e5e7b19a0229719726ebab65fa13e2394c5476a7338f13e96a44950ab6eddc53f0ab1c9757fe10483184a6d33567b08514218f6db3508b5f93778226ed4308b795ad9971c324267f3bca436484846a618956af1b0a5a6e457226864060c4ff4ca05e204ab621a49ef2e2bb03e179ebf78b09a46ad416fd754b1af79a5c939c6be93a4bee754d820639f0aa42146d975d46beebe151f43735dea2b1fd295a9bc66f9e683e0bfd19bbc12511c425ca5bac88864e62ad68cc1aa9bd425f4c82c32469b1076dd4a5b33265c947bab47526091f287e18c7a59010596f8a3b4fe9c59869c678e9b68c73ec802d9e468f733c2bc84152d13a10d6a261e46a6d44bddf7cee527ee3de7e09097993312d1104b874abfb88e1404656a68eed5c9039719691d58656d874cab8c4e2998d1ed0d7ed99dfab9d8f9712d96c5b430cd9a07e8d134b81c9bc458ead15876ef4920dcc3c64f3d7c665d66a0ddc32de158dea3250b2478f29a64d28882688aa36ba58b61103f72822b3e6d6a2ade89cb7d1f74a83eef1f230cc010d795bc829f7665f89ec6b80cd2b36e73ff2eb5ad5de41bb5bf2edefc1e6c9e1540e39decf30daa1383810963277829122a9d163fa188a6cce2b3ef96788fcc299a1b3d226a8da35274dcdd6355c61d5e441c654e08f9cee8f69cc5cacb225bd0ac0cf6709e6ae2d5be9e4557ab41d39735c794763ce8672fba91f08c58dd7a94e752e6d21a5dcea7f0cb5ff60589d0f7e84ec600a6e354dd334fcea5946a864568f8b21f1e1c1affb1caa488e336c44ed8efe2f34eeee68eab3589ccca9d373a66d5926aae4a3dbef7cc04b3a19438b4eee387d8f0476684b1c2986260eb4969b963a3794b9a3ed3e25457895f4a399c4aaf010d9f28ce8ff580642479422ea6d1d49c3d255cc4898c22516f5df5f27400000000000000000000000000000000000";

#[tokio::main]
async fn main() -> Result<()> {
    let raw = hex::decode(RAW_HEX).context("bad raw hex")?;
    let tx: stellereum::sharding::Transaction =
        bincode::deserialize(&raw).context("tx decode failed")?;
    println!(
        "decoded: from={} to={} amount={} gas={} nonce={} src={} dst={} payload_len={}",
        hex::encode(tx.from),
        hex::encode(tx.to),
        tx.amount,
        tx.gas_limit,
        tx.nonce,
        tx.source_shard,
        tx.target_shard,
        tx.payload.len()
    );
    if let Some(env) = tx.pq_envelope() {
        println!(
            "envelope: scheme={} implicit={} pk_len={:?} salt={}",
            env.scheme.name(),
            env.is_implicit,
            env.pubkey.as_ref().map(|p| p.len()),
            hex::encode(env.salt)
        );
        println!(
            "Falcon512 pubkey_size={}",
            stellereum::post_quantum::PqScheme::Falcon512.pubkey_size()
        );
    } else {
        println!("NO PQ ENVELOPE?!");
    }
    println!(
        "is_pq_activation={} verify_signature={}",
        tx.is_pq_activation(),
        tx.verify_signature()
    );

    let engine = stellereum::state_engine::InMemoryStateEngine::new();
    let faucet = tx.from;
    engine
        .credit_native(&faucet, 1_000_000_000_000_000)
        .await
        .map_err(|e| anyhow::anyhow!("fund: {e}"))?;
    let a = engine.get_account(&faucet).await.unwrap();
    println!(
        "funded: balance={} nonce={} scheme={:?} pubkey_hash={:?}",
        a.balance,
        a.nonce,
        a.scheme.name(),
        a.pubkey_hash.map(hex::encode)
    );

    let seed = [0x11u8; 32];
    let key = stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&seed);
    let my_addr = stellereum::post_quantum::derive_pq_address(
        stellereum::post_quantum::PqScheme::Falcon512,
        key.public_key(),
        &stellereum::post_quantum::DEFAULT_SALT,
    );
    println!(
        "my derived addr matches tx.from: {} (pk len {})",
        my_addr == faucet,
        key.public_key().len()
    );

    for n in 0..4u64 {
        let mut dust = stellereum::sharding::Transaction {
            from: faucet,
            to: faucet,
            amount: 1,
            gas_limit: 350_000,
            nonce: n,
            source_shard: 0,
            target_shard: 0,
            signature: vec![],
            payload: vec![],
            priority_fee_per_gas: 0,
        };
        let msg = dust.signing_message();
        let sig = key.sign(&msg);
        dust.signature = stellereum::post_quantum::PqSignatureEnvelope::new_explicit(
            stellereum::post_quantum::PqScheme::Falcon512,
            key.public_key().to_vec(),
            sig,
        )
        .encode();
        match engine.apply_transaction(&dust, 1792703094).await {
            Ok(_) => println!("dust nonce {n}: OK"),
            Err(e) => println!("dust nonce {n}: ERR {e}"),
        }
    }
    let a = engine.get_account(&faucet).await.unwrap();
    println!(
        "after dust: balance={} nonce={} scheme={:?} pubkey_hash={:?}",
        a.balance,
        a.nonce,
        a.scheme.name(),
        a.pubkey_hash.map(hex::encode)
    );

    match engine.apply_transaction(&tx, 1792703094).await {
        Ok(_) => println!("LIVE TX: OK (no error)"),
        Err(e) => println!("LIVE TX: ERR >>> {e} <<<"),
    }
    Ok(())
}
