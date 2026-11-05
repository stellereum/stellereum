use anyhow::{anyhow, Result};
use infnode::node::e2e_decrypt;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use stellereum::storage::Storage;

fn decrypt_blob(manifest_val: &Value, chunks_dir: &Path) -> Result<Vec<u8>> {
    let manifest: Value = serde_json::from_str(manifest_val["value"].as_str().unwrap_or(""))?;
    let key_hex = manifest["key"]
        .as_str()
        .ok_or_else(|| anyhow!("missing key"))?;
    let nonce_hex = manifest["nonce"]
        .as_str()
        .ok_or_else(|| anyhow!("missing nonce"))?;
    let key_bytes = hex::decode(key_hex)?;
    let nonce_bytes = hex::decode(nonce_hex)?;
    let mut dk = [0u8; 32];
    dk.copy_from_slice(&key_bytes);

    let chunks = manifest["chunks"]
        .as_array()
        .ok_or_else(|| anyhow!("missing chunks"))?;
    let mut ct = Vec::new();
    for c in chunks {
        let cid = c["id"]
            .as_str()
            .ok_or_else(|| anyhow!("missing chunk id"))?;
        let cpath = chunks_dir.join(cid);
        let part = fs::read(&cpath).map_err(|e| anyhow!("read {}: {e}", cpath.display()))?;
        ct.extend_from_slice(&part);
    }
    e2e_decrypt(&dk, &nonce_bytes, &ct)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let store_dir = PathBuf::from(args.get(1).map(|s| s.as_str()).unwrap_or("./data/store"));
    let chunks_dir = PathBuf::from(
        args.get(2)
            .map(|s| s.as_str())
            .unwrap_or("./data/chunks/stellstate"),
    );
    let kv_path = PathBuf::from(args.get(3).map(|s| s.as_str()).unwrap_or("./data/kv.json"));
    let target_height: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(278600);
    let shard_id: u32 = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);

    println!(
        "Importing shard {shard_id} snapshot at height {target_height} into {}",
        store_dir.display()
    );
    let kv_data =
        fs::read_to_string(&kv_path).map_err(|e| anyhow!("read {}: {e}", kv_path.display()))?;
    let kv: HashMap<String, Value> = serde_json::from_str(&kv_data)?;

    let storage = Storage::open(&store_dir)?;

    // 1. Main state
    let state_prefix = format!("snap_{shard_id}_{target_height}");
    let mut state_imported = false;
    for (k, v) in &kv {
        if k.contains(&state_prefix) && !k.contains("_dom_") {
            println!("Found main state key: {k}");
            let plain = decrypt_blob(v, &chunks_dir)?;
            storage.put_state(target_height, &plain)?;
            println!("Imported main state: {} bytes", plain.len());
            state_imported = true;
            break;
        }
    }
    if !state_imported {
        eprintln!("Warning: main state for {target_height} not found in kv!");
    }

    // 2. Domains
    let dom_prefix = format!("snap_{shard_id}_{target_height}_dom_");
    for (k, v) in &kv {
        if k.contains(&dom_prefix) {
            let kind = k.split("_dom_").nth(1).unwrap_or("");
            println!("Found domain key: {k} (kind: {kind})");
            match decrypt_blob(v, &chunks_dir) {
                Ok(plain) => {
                    match kind {
                        "domains" => storage.put_domains(target_height, &plain)?,
                        "session" => storage.put_session_keys(target_height, &plain)?,
                        "bridge" => storage.put_bridge(target_height, &plain)?,
                        "zkml" => storage.put_zkml_models(target_height, &plain)?,
                        "cross_shard" => storage.put_cross_shard(target_height, &plain)?,
                        other => println!("  Unknown domain kind: {other}"),
                    }
                    println!("  Imported domain {kind}: {} bytes", plain.len());
                }
                Err(e) => eprintln!("  Failed decrypt domain {kind}: {e}"),
            }
        }
    }

    println!("Finished importing shard {shard_id} snapshot at height {target_height}!");
    Ok(())
}
