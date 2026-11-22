#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "Usage: $0 <node.yaml> [more node.yaml files...]" >&2
  echo "Reads peer pq-pub and endpoints from node.yaml and prints valid stellereum/v1 DNS TXT records." >&2
  exit 2
fi

python3 - "$@" <<'EOF'
import re
import struct
import sys

IV = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]
MSG_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
ROOT = 1 << 3


def rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def g(s, a, b, c, d, mx, my):
    s[a] = (s[a] + s[b] + mx) & 0xFFFFFFFF
    s[d] = rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + my) & 0xFFFFFFFF
    s[d] = rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = rotr(s[b] ^ s[c], 7)


def compress(cv, block_words, counter, block_len, flags):
    s = list(cv) + IV[:4] + [
        counter & 0xFFFFFFFF,
        (counter >> 32) & 0xFFFFFFFF,
        block_len,
        flags,
    ]
    m = list(block_words)
    for r in range(7):
        g(s, 0, 4, 8, 12, m[0], m[1])
        g(s, 1, 5, 9, 13, m[2], m[3])
        g(s, 2, 6, 10, 14, m[4], m[5])
        g(s, 3, 7, 11, 15, m[6], m[7])
        g(s, 0, 5, 10, 15, m[8], m[9])
        g(s, 1, 6, 11, 12, m[10], m[11])
        g(s, 2, 7, 8, 13, m[12], m[13])
        g(s, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[i] for i in MSG_PERM]
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] ^= cv[i]
    return s


def blake3_le1024(data: bytes) -> bytes:
    assert len(data) <= 1024, f"expected <=1024B input, got {len(data)}"
    cv = list(IV)
    num_blocks = (len(data) + 63) // 64
    for i in range(num_blocks):
        blk = data[i * 64 : (i + 1) * 64]
        flags = (CHUNK_START if i == 0 else 0) | (CHUNK_END if i == num_blocks - 1 else 0)
        w = list(struct.unpack("<16I", blk.ljust(64, b"\x00")))
        if i == num_blocks - 1:
            out = compress(cv, w, 0, len(blk), flags | ROOT)
            return struct.pack("<8I", *out[:8])
        cv = compress(cv, w, 0, len(blk), flags)[:8]
    raise AssertionError("unreachable")


def pq_id_from_pub(pq_hex: str) -> str:
    raw = bytes.fromhex(pq_hex)
    if len(raw) != 897:
        raise ValueError(f"expected 897-byte Falcon-512 pubkey, got {len(raw)} bytes")
    digest = blake3_le1024(b"infnode-pqid-v1" + raw)
    return "inf1:" + digest[:20].hex()


peers = {}
pattern = re.compile(
    r'-\s*name:\s*(\S+).*?pq-pub:\s*"([^"]+)".*?endpoints:\s*\["([^"]+)"\]',
    re.S,
)

for path in sys.argv[1:]:
    with open(path, "r", encoding="utf-8") as fh:
        content = fh.read()
    for name, pq_hex, ep in pattern.findall(content):
        host, port_s = ep.rsplit(":", 1)
        port = int(port_s)
        if not (1024 <= port <= 65535):
            raise ValueError(f"{name}: port {port} out of range 1024..=65535")
        nid = pq_id_from_pub(pq_hex)
        rec = f"stellereum/v1 node_id={nid} pq={pq_hex} host={host} port={port}"
        if name in peers and peers[name] != rec:
            raise ValueError(f"conflicting peer definition for {name} in {path}")
        peers[name] = rec

for name in sorted(peers):
    print(f"# {name}")
    print(peers[name])
EOF
