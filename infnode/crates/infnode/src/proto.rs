use anyhow::{bail, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const NODEID_LEN: usize = 20;
pub const MAX_FRAME: usize = 32 * 1024 * 1024;
pub const MAX_AUTH_FRAME: usize = 64 * 1024;
pub const TS_WINDOW_MS: i64 = 600_000;

/// Fail-closed ingress caps (audit 2026-11-01). The 32 MiB `MAX_FRAME` is a
/// transport envelope: individual services accept far less, so one peer
/// cannot turn a single request into a multi-megabyte allocation or a
/// mesh-wide amplification.
pub const MAX_DHT_KEY_LEN: usize = 512;
pub const MAX_DHT_VALUE_LEN: usize = 1024 * 1024;
pub const MAX_PUBSUB_DATA_LEN: usize = 1024 * 1024;
pub const MAX_STORAGE_CHUNK_LEN: usize = 2 * 1024 * 1024;
pub const MAX_NONCE_LEN: usize = 1024;
pub const MAX_TOPIC_LEN: usize = 256;
pub const MAX_ENDPOINTS_PER_NODE: usize = 8;
pub const MAX_ENDPOINT_LEN: usize = 256;
pub const MAX_ROUTES_PER_UPDATE: usize = 512;
pub const MAX_DHT_LOOKUP_TTL: u64 = 8;
pub const MAX_PUBSUB_TTL: u64 = 16;
pub const MAX_DHT_SYNC_LIMIT: usize = 10_000;
pub const MAX_REMOTE_TTL_SECS: u64 = 30 * 24 * 3600;
pub const MAX_SEEN_IDS: usize = 200_000;
pub const MAX_OUTBOX_PER_PEER: usize = 1024;

pub fn topic_ok(topic: &str) -> bool {
    !topic.is_empty() && topic.len() <= MAX_TOPIC_LEN
}

pub fn dht_key_ok(key: &str) -> bool {
    !key.is_empty() && key.len() <= MAX_DHT_KEY_LEN
}

pub fn dht_value_ok(value: &str) -> bool {
    value.len() <= MAX_DHT_VALUE_LEN
}

pub fn pubsub_data_ok(data: &str) -> bool {
    data.len() <= MAX_PUBSUB_DATA_LEN
}

/// Claim a handshake nonce: true = fresh (inserted), false = replayed or
/// malformed. Entries older than `TS_WINDOW_MS` are pruned; the map is
/// hard-bounded so a flood of distinct nonces cannot grow memory without
/// limit (at the cap the handshake is refused — fail closed).
pub fn claim_nonce(seen: &mut HashMap<String, i64>, nonce: &str, now: i64) -> bool {
    if nonce.len() < 8
        || nonce.len() > 128
        || !nonce.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return false;
    }
    // Prune on every claim: handshakes are rare (not per-request), so an O(n)
    // scan here never lands on a hot path, and the window stays exact.
    let cutoff = now.saturating_sub(TS_WINDOW_MS);
    seen.retain(|_, ts| *ts > cutoff);
    if seen.contains_key(nonce) {
        return false;
    }
    if seen.len() >= MAX_SEEN_IDS {
        return false;
    }
    seen.insert(nonce.to_string(), now);
    true
}

pub mod kind {
    pub const PING: u8 = 0;
    pub const PONG: u8 = 1;
    pub const CHALLENGE: u8 = 2;
    pub const AUTH: u8 = 3;
    pub const REQ: u8 = 4;
    pub const RESP: u8 = 5;
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn ts_ok(ts: i64) -> bool {
    (now_ms() - ts).abs() <= TS_WINDOW_MS
}

pub fn svc_id(name: &str) -> u64 {
    let h = blake3::hash(name.as_bytes());
    u64::from_le_bytes(h.as_bytes()[0..8].try_into().unwrap())
}

pub fn svc_name(id: u64) -> Option<&'static str> {
    crate::services::SERVICE_NAMES
        .iter()
        .find(|n| svc_id(n) == id)
        .copied()
}

/// E2E ключ: X25519(shared) + оба NodeID (канонически отсортированы), раздутый через blake3.
/// Симметричный для обеих сторон независимо от направления.
pub fn e2e_key_from_shared(shared: &[u8; 32], id_a: &[u8; 20], id_b: &[u8; 20]) -> [u8; 32] {
    let (lo, hi) = if id_a < id_b {
        (id_a, id_b)
    } else {
        (id_b, id_a)
    };
    let mut h = blake3::Hasher::new();
    h.update(b"infnode-e2e-v1");
    h.update(shared);
    h.update(lo);
    h.update(hi);
    let out = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out.as_bytes()[..32]);
    k
}

/// Сессионный ключ с forward secrecy (X3DH-подобный): смешиваем 4 shared-секрета —
/// ss(static-static), se(static-эфимерный), es(эфемерный-static), ee(эфемерный-эфемерный).
/// Каждое соединение использует свежие эфемерные ключи, поэтому компрометация
/// долгосрочных ключей позже не раскрывает прошлый трафик.
pub fn session_key(
    shared_ss: &[u8; 32],
    shared_se: &[u8; 32],
    shared_es: &[u8; 32],
    shared_ee: &[u8; 32],
    id_a: &[u8; 20],
    id_b: &[u8; 20],
) -> [u8; 32] {
    let (lo, hi) = if id_a < id_b {
        (id_a, id_b)
    } else {
        (id_b, id_a)
    };
    let mut h = blake3::Hasher::new();
    h.update(b"infnode-session-v1");
    h.update(shared_ss);
    h.update(shared_se);
    h.update(shared_es);
    h.update(shared_ee);
    h.update(lo);
    h.update(hi);
    let out = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out.as_bytes()[..32]);
    k
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub kind: u8,
    pub seq: u32,
    pub ts: i64,
    pub src: [u8; NODEID_LEN],
    pub dst: [u8; NODEID_LEN],
    pub svc: u64,
    pub payload: Vec<u8>,
    pub nonce: Vec<u8>,
    pub sig: [u8; 64],
}

const HDR: usize = 68;

impl Frame {
    pub fn sign_data(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(HDR + self.payload.len() + self.nonce.len());
        v.push(1); // version
        v.push(self.kind);
        v.extend_from_slice(&self.seq.to_le_bytes());
        v.extend_from_slice(&self.ts.to_le_bytes());
        v.extend_from_slice(&self.src);
        v.extend_from_slice(&self.dst);
        v.extend_from_slice(&self.svc.to_le_bytes());
        v.extend_from_slice(&(self.nonce.len() as u16).to_le_bytes());
        v.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.payload);
        v.extend_from_slice(&self.nonce);
        v
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.sign_data();
        b.extend_from_slice(&self.sig);
        b
    }

    pub fn decode(b: &[u8]) -> Result<Frame> {
        if b.len() < HDR + 64 {
            bail!("frame too short");
        }
        let plen =
            u32::from_le_bytes(b[64..68].try_into().map_err(|_| anyhow::anyhow!("plen"))?) as usize;
        let nlen =
            u16::from_le_bytes(b[62..64].try_into().map_err(|_| anyhow::anyhow!("nlen"))?) as usize;
        // защита от переполнения usize и out-of-bounds при нечётких/злонамеренных пакетах
        if plen > MAX_FRAME {
            bail!("payload too large");
        }
        // Поле nonce легитимно несёт 24 байта (XChaCha nonce); 64 КиБ
        // злонамеренного nonce на каждом из 1024 стримов — десятки мегабайт.
        if nlen > MAX_NONCE_LEN {
            bail!("nonce too large");
        }
        // проверяем что сумма длин не переполняет usize и точно совпадает с длиной
        let total = HDR
            .checked_add(plen)
            .and_then(|x| x.checked_add(nlen))
            .and_then(|x| x.checked_add(64));
        let total = match total {
            Some(t) => t,
            None => bail!("frame length overflow"),
        };
        if total != b.len() {
            bail!("frame length mismatch");
        }
        let sig: [u8; 64] = b[b.len() - 64..]
            .try_into()
            .map_err(|_| anyhow::anyhow!("sig"))?;
        let f = Frame {
            kind: b[1],
            seq: u32::from_le_bytes(b[2..6].try_into().map_err(|_| anyhow::anyhow!("seq"))?),
            ts: i64::from_le_bytes(b[6..14].try_into().map_err(|_| anyhow::anyhow!("ts"))?),
            src: b[14..34].try_into().map_err(|_| anyhow::anyhow!("src"))?,
            dst: b[34..54].try_into().map_err(|_| anyhow::anyhow!("dst"))?,
            svc: u64::from_le_bytes(b[54..62].try_into().map_err(|_| anyhow::anyhow!("svc"))?),
            payload: b[68..68 + plen].to_vec(),
            nonce: b[68 + plen..68 + plen + nlen].to_vec(),
            sig,
        };
        // version check
        if b[0] != 1 {
            bail!("unsupported version");
        }
        // не допускаем переполнения индексов для нечётких пакетов
        if f.nonce.len() != nlen || f.payload.len() != plen {
            bail!("internal mismatch");
        }
        Ok(f)
    }

    pub fn verify(&self, pk: &VerifyingKey) -> bool {
        // sign-then-hash: подпись над blake3-дайджестом всего фрейма (быстро для больших payload)
        let d = blake3::hash(&self.sign_data());
        pk.verify_strict(d.as_bytes(), &Signature::from_bytes(&self.sig))
            .is_ok()
    }
}

/// Decoder fuzz regressions (Agent 1, stellereum): Frame::decode is the
/// network entry point — it must never panic on peer bytes (plen/nlen abuse,
/// truncations, bit flips). Appended without touching existing code.
#[cfg(test)]
mod decoder_fuzz_regressions {
    use super::*;

    #[test]
    fn frame_adversarial_lengths_never_panic() {
        let f = Frame {
            kind: kind::REQ,
            seq: 1,
            ts: 1,
            src: [1u8; NODEID_LEN],
            dst: [2u8; NODEID_LEN],
            svc: 0,
            payload: b"ping".to_vec(),
            nonce: vec![0u8; 8],
            sig: [0u8; 64],
        };
        let enc = f.encode();
        let mut corpus = vec![vec![], enc.clone()];
        for n in 0..enc.len() {
            corpus.push(enc[..n].to_vec());
        }
        // plen/nlen length-confusion sweeps at the header offsets 62..68.
        for plen in [0u32, 1, u32::MAX, MAX_FRAME as u32 + 1] {
            for nlen in [0u16, 1, u16::MAX] {
                let mut m = enc.clone();
                m[62..64].copy_from_slice(&nlen.to_le_bytes());
                m[64..68].copy_from_slice(&plen.to_le_bytes());
                corpus.push(m);
            }
        }
        for input in &corpus {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = Frame::decode(input);
            }));
            assert!(r.is_ok(), "Frame::decode panicked on len {}", input.len());
        }
    }
}
