fn main() {
    let arg = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/store-check".into());
    let path = std::path::PathBuf::from(arg);
    let storage = stellereum::storage::Storage::open(&path).expect("open storage");
    let fin = storage.finalized().expect("finalized");
    let latest = storage.latest_state().expect("latest_state");
    let latest_paired = storage.latest_paired_snapshot().expect("latest_paired");
    println!("Finalized: {:?}", fin);
    println!(
        "Latest state: {:?}",
        latest.as_ref().map(|(h, v)| (*h, v.len()))
    );
    println!(
        "Latest paired: {:?}",
        latest_paired.as_ref().map(|(h, v)| (*h, v.len()))
    );
    println!("State at 0: {}", storage.get_state(0).unwrap().is_some());
}
