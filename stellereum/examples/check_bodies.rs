fn main() {
    let arg = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/root/nodeA/data/store".into());
    let db = sled::open(&arg).expect("open sled");
    let meta = db.open_tree("meta").expect("open meta");
    let _ = meta.remove("faucet_state_v1");
    let _ = db.flush();
    println!("Reset faucet_state_v1 on {}", arg);
}
