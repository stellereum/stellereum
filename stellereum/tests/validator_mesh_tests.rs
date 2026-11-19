//! Direct validator mesh (mesh wave, task 1).
//!
//! Consensus payloads are addressed by validator id and delivered over warm
//! direct links; the DHT/overlay is only the fallback. These tests pin the
//! routing properties with a deterministic fake transport:
//!
//! * mesh delivery happens without any DHT/overlay call (faster than DHT);
//! * a failed direct link is covered by the overlay fallback, so a message is
//!   not lost when the mesh is degraded;
//! * a stalled DHT does not prevent direct delivery to healthy members;
//! * three consecutive failures evict a peer from direct targets, and the
//!   cooldown + successful probe restore it;
//! * validator-set rotation adds/removes members and resets a changed link.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use stellereum::consensus_net::{mesh_may_substitute, mesh_shortcut_allowed};
use stellereum::network::{
    deliver_unicast, MeshDelivery, MeshFuture, UnicastPath, ValidatorMesh, ValidatorMeshMember,
    ValidatorMeshTransport, VALIDATOR_MESH_COOLDOWN_MS, VALIDATOR_MESH_EVICT_AFTER,
};

#[derive(Default)]
struct FakeTransport {
    direct_ok: Mutex<HashMap<[u8; 20], bool>>,
    probe_ok: Mutex<HashMap<[u8; 20], bool>>,
    direct_delay: Duration,
    overlay_delay: Duration,
    overlay_ok: AtomicBool,
    direct_calls: Mutex<Vec<([u8; 20], String)>>,
    overlay_calls: AtomicUsize,
}

impl FakeTransport {
    fn new(direct_delay_ms: u64, overlay_delay_ms: u64) -> Self {
        Self {
            direct_delay: Duration::from_millis(direct_delay_ms),
            overlay_delay: Duration::from_millis(overlay_delay_ms),
            overlay_ok: AtomicBool::new(true),
            ..Default::default()
        }
    }

    fn set_direct(&self, id: [u8; 20], ok: bool) {
        self.direct_ok.lock().unwrap().insert(id, ok);
        self.probe_ok.lock().unwrap().insert(id, ok);
    }

    fn direct_calls(&self) -> Vec<([u8; 20], String)> {
        self.direct_calls.lock().unwrap().clone()
    }

    fn overlay_calls(&self) -> usize {
        self.overlay_calls.load(Ordering::Relaxed)
    }
}

impl ValidatorMeshTransport for FakeTransport {
    fn deliver_direct<'a>(
        &'a self,
        peer: [u8; 20],
        topic: &'a str,
        data: &'a str,
    ) -> MeshFuture<'a, Result<(), String>> {
        let ok = *self.direct_ok.lock().unwrap().get(&peer).unwrap_or(&true);
        let delay = self.direct_delay;
        self.direct_calls
            .lock()
            .unwrap()
            .push((peer, format!("{topic}:{data}")));
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            if ok {
                Ok(())
            } else {
                Err("direct link down".to_string())
            }
        })
    }

    fn probe<'a>(&'a self, peer: [u8; 20]) -> MeshFuture<'a, Result<(), String>> {
        let ok = *self.probe_ok.lock().unwrap().get(&peer).unwrap_or(&true);
        let delay = self.direct_delay;
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            if ok {
                Ok(())
            } else {
                Err("probe failed".to_string())
            }
        })
    }

    fn publish_overlay<'a>(
        &'a self,
        _topic: &'a str,
        _data: &'a str,
    ) -> MeshFuture<'a, Result<usize, String>> {
        let ok = self.overlay_ok.load(Ordering::Relaxed);
        let delay = self.overlay_delay;
        self.overlay_calls.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            if ok {
                Ok(4)
            } else {
                Err("overlay stalled".to_string())
            }
        })
    }
}

fn member(seed: u8) -> ValidatorMeshMember {
    let mut id = [0u8; 20];
    id[0] = seed;
    id[19] = seed.wrapping_mul(7);
    ValidatorMeshMember::new(
        id,
        vec![format!("127.0.0.1:{}", 30000 + seed as u32)],
        format!("v{seed}"),
    )
}

fn mesh(transport: Arc<FakeTransport>) -> Arc<ValidatorMesh> {
    Arc::new(ValidatorMesh::new(transport))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mesh_delivers_a_proposal_directly_without_any_dht_call() {
    let transport = Arc::new(FakeTransport::new(5, 1_500));
    let mesh = mesh(Arc::clone(&transport));
    let members: Vec<_> = (1..=3).map(member).collect();
    let ids: Vec<_> = members.iter().map(|m| m.id).collect();
    mesh.install(members, 1_000);

    let started = Instant::now();
    let delivery = mesh.deliver("stell/consensus/test", "c0ffee", 1_000).await;
    let elapsed = started.elapsed();

    assert_eq!(delivery.direct_ok, 3);
    assert_eq!(delivery.direct_failed, 0);
    assert!(
        !delivery.fallback_used,
        "DHT must not be touched on a healthy mesh"
    );
    assert!(delivery.delivered());
    assert_eq!(transport.overlay_calls(), 0);
    assert!(
        elapsed < Duration::from_millis(400),
        "mesh must not pay the 1.5 s DHT path (took {elapsed:?})"
    );
    let called: Vec<_> = transport
        .direct_calls()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    for id in ids {
        assert!(
            called.contains(&id),
            "every mesh member must be addressed directly"
        );
    }
    assert!(transport.direct_calls()[0]
        .1
        .contains("stell/consensus/test"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_direct_link_falls_back_to_the_overlay() {
    let transport = Arc::new(FakeTransport::new(1, 1));
    let mesh = mesh(Arc::clone(&transport));
    let a = member(1);
    let b = member(2);
    transport.set_direct(a.id, true);
    transport.set_direct(b.id, false);
    mesh.install(vec![a.clone(), b.clone()], 1_000);

    let delivery = mesh.deliver("stell/consensus/test", "beef", 1_000).await;
    assert_eq!(delivery.direct_ok, 1);
    assert_eq!(delivery.direct_failed, 1);
    assert!(
        delivery.fallback_used,
        "a failed copy must go to the fallback"
    );
    assert!(delivery.fallback_ok);
    // The overlay accepted ONE copy, which is not proof that the FAILED
    // direct target received it. The caller must still run the per-peer
    // broadcast, so this is deliberately NOT a complete delivery.
    assert!(!delivery.delivered());
    assert_eq!(
        transport.overlay_calls(),
        1,
        "one fallback publish per delivery"
    );
    assert_eq!(mesh.consecutive_failures(&b.id), 1);
    assert_eq!(mesh.consecutive_failures(&a.id), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_dht_does_not_block_direct_delivery() {
    let transport = Arc::new(FakeTransport::new(1, 1));
    transport.overlay_ok.store(false, Ordering::Relaxed);
    let mesh = mesh(Arc::clone(&transport));
    let a = member(1);
    let b = member(2);
    transport.set_direct(a.id, true);
    transport.set_direct(b.id, true);
    mesh.install(vec![a, b], 1_000);

    let delivery = mesh
        .deliver("stell/consensus/test", "deadbeef", 1_000)
        .await;
    assert_eq!(
        delivery.direct_ok, 2,
        "the DHT being down must not lose direct copies"
    );
    assert!(!delivery.fallback_used);
    assert!(delivery.delivered());
    assert_eq!(transport.overlay_calls(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_consecutive_failures_evict_and_cooldown_restores() {
    let transport = Arc::new(FakeTransport::new(0, 0));
    let mesh = Arc::new(ValidatorMesh::with_policy(
        Arc::clone(&transport) as Arc<dyn ValidatorMeshTransport>,
        VALIDATOR_MESH_EVICT_AFTER,
        100,
        10,
    ));
    let a = member(1);
    transport.set_direct(a.id, false);
    mesh.install(vec![a.clone()], 1_000);

    for _ in 0..VALIDATOR_MESH_EVICT_AFTER {
        let d = mesh.deliver("t", "x", 1_000).await;
        assert!(d.fallback_used, "each failed copy uses the overlay");
        assert!(d.fallback_ok);
    }
    assert!(
        mesh.is_suspected(&a.id),
        "third failure marks the peer suspected"
    );
    assert_eq!(mesh.evictions_total(), 1);
    assert!(
        mesh.direct_targets(1_000).is_empty(),
        "a suspected peer is withheld from direct targets"
    );

    // While in cooldown the mesh stops dialling the dead peer entirely.
    let before = transport.direct_calls().len();
    let d = mesh.deliver("t", "y", 1_050).await;
    assert_eq!(
        transport.direct_calls().len(),
        before,
        "no direct attempt before the cooldown elapses"
    );
    assert!(
        d.fallback_used && d.fallback_ok,
        "the overlay still carries the copy"
    );

    // Cooldown elapsed: one probe is allowed; success restores the link.
    transport.set_direct(a.id, true);
    let report = mesh.maintain(1_101).await;
    assert_eq!(report.probed, 1);
    assert_eq!(report.recovered, 1);
    assert!(!mesh.is_suspected(&a.id));
    assert_eq!(mesh.consecutive_failures(&a.id), 0);
    assert_eq!(mesh.direct_targets(1_101), vec![a.id]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cooldown_expiry_does_not_reintroduce_a_dead_peer_into_the_frame_path() {
    let transport = Arc::new(FakeTransport::new(0, 0));
    let mesh = Arc::new(ValidatorMesh::with_policy(
        Arc::clone(&transport) as Arc<dyn ValidatorMeshTransport>,
        VALIDATOR_MESH_EVICT_AFTER,
        100,
        10,
    ));
    let a = member(1);
    transport.set_direct(a.id, false);
    mesh.install(vec![a.clone()], 1_000);

    for _ in 0..VALIDATOR_MESH_EVICT_AFTER {
        mesh.deliver("t", "x", 1_000).await;
    }
    assert!(mesh.is_suspected(&a.id));

    // REGRESSION: at the exact cooldown boundary the peer used to re-enter
    // `direct_targets`, so every consensus frame retried the dead link and
    // paid the full mesh timeout on the send path. Reconnect belongs to the
    // off-tick maintenance pass.
    let before = transport.direct_calls().len();
    assert!(
        mesh.direct_targets(1_100).is_empty(),
        "a suspected peer must stay out of the per-frame direct set after cooldown"
    );
    transport.set_direct(a.id, true); // reachable again, but not probed yet
    let delivery = mesh.deliver("t", "y", 1_100).await;
    assert_eq!(
        transport.direct_calls().len(),
        before,
        "per-frame delivery must not dial a suspected peer"
    );
    assert!(delivery.fallback_used && delivery.fallback_ok);
    assert!(
        mesh.is_suspected(&a.id),
        "a fire-and-forget write is not liveness proof; only the acknowledged probe restores"
    );

    // The heartbeat owns recovery: one acknowledged probe clears suspicion.
    let report = mesh.maintain(1_150).await;
    assert_eq!(report.probed, 1);
    assert_eq!(report.recovered, 1);
    assert!(!mesh.is_suspected(&a.id));
    assert_eq!(mesh.direct_targets(1_150), vec![a.id]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_overlay_success_does_not_mask_a_failed_direct_target() {
    let transport = Arc::new(FakeTransport::new(0, 0));
    let mesh = mesh(Arc::clone(&transport));
    let a = member(1);
    let b = member(2);
    let c = member(3);
    transport.set_direct(a.id, true);
    transport.set_direct(b.id, false); // the failed copy
    transport.set_direct(c.id, true);
    mesh.install(vec![a, b, c], 1_000);

    // FakeTransport's overlay reports `Ok(4)` — a count, not per-peer
    // coverage. The failed direct target is NOT proven received.
    let delivery = mesh.deliver("stell/consensus/test", "beef", 1_000).await;
    assert_eq!(delivery.targets, 3);
    assert_eq!(delivery.direct_ok, 2);
    assert_eq!(delivery.direct_failed, 1);
    assert!(delivery.fallback_used && delivery.fallback_ok);
    assert!(
        !delivery.delivered(),
        "the caller must still broadcast so the failed target receives the frame"
    );
}

#[test]
fn partial_mesh_failure_is_not_covered_by_one_overlay_success() {
    // 3 targets, 1 direct failure, and the overlay accepted ONE copy. That
    // count means "some subscriber took it", not "the failed validator got
    // it", so the frame is NOT complete: the per-peer broadcast must still
    // run and reach every peer.
    let delivery = MeshDelivery {
        targets: 3,
        direct_ok: 2,
        direct_failed: 1,
        fallback_used: true,
        fallback_ok: true,
    };
    assert!(
        !delivery.delivered(),
        "one overlay success must never be treated as coverage for a failed direct copy"
    );
    let src = include_str!("../src/consensus_net.rs");
    assert!(
        src.contains("if delivery.delivered() {"),
        "the broadcast path must gate on the strict direct-coverage proof"
    );
    assert!(
        !src.contains("|| self.fallback_ok"),
        "overlay counts must not be folded into `delivered()`"
    );

    // Empty target set is also not success (its own L3 rule), even if the
    // overlay accepted a copy: the caller must still broadcast.
    let empty = MeshDelivery {
        targets: 0,
        direct_ok: 0,
        direct_failed: 0,
        fallback_used: true,
        fallback_ok: true,
    };
    assert!(!empty.delivered());
}

#[test]
fn exempt_committed_frames_never_take_the_mesh_shortcut() {
    // The mesh withholds suspected peers. `Committed` is deliberately exempt
    // from that cooldown because it is the catch-up frame a returning
    // validator needs, so it must use the per-peer path (which attempts
    // cooldown peers, detached) instead of the mesh-only path.
    assert!(
        !mesh_may_substitute(true),
        "Committed must use the per-peer path"
    );
    assert!(
        mesh_may_substitute(false),
        "votes/proposals may use the mesh"
    );

    // The shortcut gate itself: even with a fully capable mesh that covers
    // every peer, an exempt (`Committed`) frame must take the per-peer path.
    assert!(
        !mesh_shortcut_allowed(true, true, true),
        "Committed must never take the mesh shortcut, even on complete coverage"
    );
    assert!(
        mesh_shortcut_allowed(true, false, true),
        "non-exempt frames may take a fully covered mesh"
    );
    assert!(
        !mesh_shortcut_allowed(false, false, true),
        "a non-mesh-capable peer set must use the per-peer path"
    );
    assert!(
        !mesh_shortcut_allowed(true, false, false),
        "an incomplete mesh must use the per-peer path"
    );
}

#[test]
fn resolved_peer_ids_are_cached_for_the_frame_path() {
    // Both consensus and tx gossip used to walk `cfg.peers` and decode every
    // PQ hex on EVERY message (the mesh check and the per-peer send each did
    // their own resolution). At ~4 blocks/s that is pure per-frame overhead.
    let src = include_str!("../src/consensus_net.rs");
    assert_eq!(
        src.matches("peer_ids_cache.get()").count(),
        2,
        "both peer_ids() implementations must consult the cache"
    );
    assert_eq!(
        src.matches("if all_resolved {").count(),
        2,
        "a partially resolved set must stay uncached (registry may fill in later)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_bootstraps_and_rotates_the_mesh_from_the_validator_set() {
    use infnode::config::{NodeConfig, PeerConfig};
    use infnode::keyring::{NodeKeys, PqKeys};
    use infnode::node::Node;
    use std::path::PathBuf;
    use stellereum::network::P2pNetworkAdapter;

    let dir = std::env::temp_dir().join(format!("stell-mesh-adapter-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("tmpdir");

    let pq_a = PqKeys::from_seed([0x51; 32]);
    let pq_b = PqKeys::from_seed([0x52; 32]);
    let consensus_a = [0x61u8; 32];
    let consensus_b = [0x62u8; 32];
    let peer = |name: &str, pq: &PqKeys, consensus: [u8; 32], port: u16| PeerConfig {
        name: name.to_string(),
        consensus_pub: Some(hex::encode(consensus)),
        pq_pub: Some(pq.pq_pub_hex()),
        endpoints: vec![format!("127.0.0.1:{port}")],
        allow: vec!["*".to_string()],
        rate_limit_per_sec: 0,
        role: None,
        storage_roles: vec![],
    };
    let cfg = NodeConfig {
        name: "mesh-adapter".to_string(),
        listen: "127.0.0.1:0".to_string(),
        client_listen: None,
        advertise: None,
        peers: vec![
            peer("a", &pq_a, consensus_a, 28801),
            peer("b", &pq_b, consensus_b, 28802),
        ],
        allow_unknown: false,
        unknown_allow: vec![],
        metrics_listen: None,
        log_level: Some(0),
        roles: Default::default(),
        outbox_ttl_secs: 3600,
        storage_roles: vec![],
        validators: vec![],
        domain: None,
        web_listen: None,
        wallet: None,
        web_static: None,
    };
    let node = Node::new(
        cfg,
        NodeKeys::generate(),
        PqKeys::generate(),
        dir.clone(),
        PathBuf::new(),
    )
    .await
    .expect("node");

    let adapter = P2pNetworkAdapter::new(node);
    let mesh = adapter.validator_mesh();
    assert_eq!(mesh.len(), 2, "adapter bootstraps from the pinned peers");
    let id_a = infnode::proto::pq_id_from_pub(&hex::decode(pq_a.pq_pub_hex()).unwrap());
    let id_b = infnode::proto::pq_id_from_pub(&hex::decode(pq_b.pq_pub_hex()).unwrap());
    assert!(mesh.is_member(&id_a) && mesh.is_member(&id_b));

    // Validator-set rotation: only `a` remains active.
    let rotation = adapter.refresh_validator_mesh(&[consensus_a]).await;
    assert_eq!(rotation.members, 1);
    assert_eq!(rotation.removed, 1);
    assert_eq!(rotation.removed_ids, vec![id_b]);
    assert!(rotation.generation >= 2);
    assert!(mesh.is_member(&id_a));
    assert!(!mesh.is_member(&id_b), "rotated-out validator is dropped");

    // Installing an explicit member set replaces the mesh in place.
    let rotation = adapter.set_validator_mesh_members(vec![member(9)]).await;
    assert_eq!(rotation.members, 1);
    assert!(mesh.is_member(&member(9).id));
    assert!(!mesh.is_member(&id_a));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotation_adds_removes_and_resets_a_changed_link() {
    let transport = Arc::new(FakeTransport::new(0, 0));
    let mesh = mesh(Arc::clone(&transport));
    let a = member(1);
    let b = member(2);
    let c = member(3);
    for id in [a.id, b.id, c.id] {
        transport.set_direct(id, true);
    }

    let first = mesh.install(vec![a.clone(), b.clone()], 1_000);
    assert_eq!((first.generation, first.added, first.removed), (1, 2, 0));
    assert_eq!(first.members, 2);

    let d = mesh.deliver("t", "1", 1_000).await;
    assert_eq!(d.direct_ok, 2);

    // Rotation: b stays (new endpoint), a leaves, c joins.
    let mut b_new = b.clone();
    b_new.endpoints = vec!["127.0.0.1:39999".to_string()];
    let second = mesh.install(vec![b_new.clone(), c.clone()], 1_010);
    assert_eq!(second.generation, 2);
    assert_eq!(second.added, 1);
    assert_eq!(second.removed, 1);
    assert_eq!(second.updated, 1, "endpoint change is an update");
    assert_eq!(second.members, 2);
    assert!(
        !mesh.is_member(&a.id),
        "removed validator is no longer addressed"
    );
    assert!(mesh.is_member(&b.id) && mesh.is_member(&c.id));

    let before = transport.direct_calls().len();
    let d = mesh.deliver("t", "2", 1_020).await;
    assert_eq!(d.direct_ok, 2);
    let new_calls: Vec<_> = transport.direct_calls()[before..]
        .iter()
        .map(|(id, _)| *id)
        .collect();
    assert!(
        !new_calls.contains(&a.id),
        "rotation must stop traffic to removed peers"
    );
    assert!(new_calls.contains(&b.id) && new_calls.contains(&c.id));

    // A suspected link whose endpoint changed is retried immediately: the
    // failure streak belongs to the old address.
    transport.set_direct(b.id, false);
    for _ in 0..VALIDATOR_MESH_EVICT_AFTER {
        mesh.deliver("t", "3", 1_030).await;
    }
    assert!(mesh.is_suspected(&b.id));
    let mut b_rotated = b.clone();
    b_rotated.endpoints = vec!["127.0.0.1:39998".to_string()];
    mesh.install(vec![b_rotated, c], 1_100);
    assert!(
        !mesh.is_suspected(&b.id),
        "new endpoint = fresh link, no suspicion"
    );

    // Default policy constants stay pinned for operators.
    assert_eq!(VALIDATOR_MESH_EVICT_AFTER, 3);
    assert_eq!(VALIDATOR_MESH_COOLDOWN_MS, 60_000);
}

// ---------------------------------------------------------------------------
// UNICAST consensus delivery: one addressed copy, mesh first, direct on a miss.
// This is the transport under `ConsensusNetwork::send_to_peer`, which the
// compact-gossip Body reply uses so a requester is answered without a
// broadcast.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unicast_prefers_the_mesh_and_never_publishes_to_the_overlay() {
    let transport = Arc::new(FakeTransport::new(0, 0));
    let mesh = mesh(Arc::clone(&transport));
    let a = member(1);
    let b = member(2);
    mesh.install(vec![a.clone(), b.clone()], 1_000);

    let path = deliver_unicast(&mesh, a.id, "stell/consensus/t", "beef", || async {
        panic!("the warm mesh link must carry a member's copy")
    })
    .await
    .expect("mesh member is reachable");
    assert_eq!(path, UnicastPath::MeshDirect);

    // ONE copy, to the addressed peer only. `b` is untouched and the overlay
    // (the broadcast path) is never used: no amplification.
    assert_eq!(
        transport.direct_calls(),
        vec![(a.id, "stell/consensus/t:beef".to_string())]
    );
    assert_eq!(transport.overlay_calls(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unicast_falls_back_to_the_direct_link_when_the_mesh_copy_fails() {
    let transport = Arc::new(FakeTransport::new(0, 0));
    let mesh = mesh(Arc::clone(&transport));
    let a = member(1);
    let b = member(2);
    mesh.install(vec![a.clone(), b.clone()], 1_000);
    transport.set_direct(a.id, false);

    let delivered = Arc::new(Mutex::new(Vec::<([u8; 20], String)>::new()));
    let sink = Arc::clone(&delivered);
    let path = deliver_unicast(
        &mesh,
        a.id,
        "stell/consensus/t",
        "c0ffee",
        move || async move {
            sink.lock().unwrap().push((a.id, "c0ffee".to_string()));
            Ok(())
        },
    )
    .await
    .expect("the direct fallback delivered the same frame");
    assert_eq!(path, UnicastPath::PeerDirect);

    // The message was NOT lost: exactly one fallback copy, still addressed to
    // the requester, and still no overlay/broadcast.
    assert_eq!(
        *delivered.lock().unwrap(),
        vec![(a.id, "c0ffee".to_string())]
    );
    assert_eq!(transport.overlay_calls(), 0);
    assert_eq!(
        transport.direct_calls().len(),
        1,
        "only the failed mesh try"
    );

    // Non-members go straight to the direct transport (no mesh attempt).
    let outsider = {
        let mut id = [0x99u8; 20];
        id[1] = 0x01;
        id
    };
    let sink = Arc::clone(&delivered);
    let path = deliver_unicast(&mesh, outsider, "t", "dead", move || async move {
        sink.lock().unwrap().push((outsider, "dead".to_string()));
        Ok(())
    })
    .await
    .expect("direct transport reaches a non-member");
    assert_eq!(path, UnicastPath::PeerDirect);
    assert_eq!(
        transport.direct_calls().len(),
        1,
        "no mesh call for a non-member"
    );
    assert_eq!(delivered.lock().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unicast_reports_an_error_only_when_both_transports_fail() {
    let transport = Arc::new(FakeTransport::new(0, 0));
    let mesh = mesh(Arc::clone(&transport));
    let a = member(1);
    mesh.install(vec![a.clone()], 1_000);
    transport.set_direct(a.id, false);

    let err = deliver_unicast(&mesh, a.id, "t", "baad", || async {
        Err("direct link down".to_string())
    })
    .await
    .expect_err("both transports failed");
    assert!(err.contains("direct link down"));
    // The caller's liveness fallback is now legitimately responsible; the
    // unicast path never substitutes an overlay broadcast on its own.
    assert_eq!(transport.overlay_calls(), 0);
}
