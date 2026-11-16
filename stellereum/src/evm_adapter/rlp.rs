// Minimal Recursive Length Prefix (RLP) Serialization for Signing Hashes

/// RLP encodes a byte slice according to Ethereum Yellow Paper.
pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        vec![data[0]]
    } else if data.len() <= 55 {
        let mut out = Vec::with_capacity(1 + data.len());
        out.push(0x80 + data.len() as u8);
        out.extend_from_slice(data);
        out
    } else {
        let len_bytes = data.len().to_be_bytes();
        let skip = len_bytes.iter().take_while(|&&b| b == 0).count();
        let active = &len_bytes[skip..];
        let mut out = Vec::with_capacity(1 + active.len() + data.len());
        out.push(0xb7 + active.len() as u8);
        out.extend_from_slice(active);
        out.extend_from_slice(data);
        out
    }
}

/// RLP encodes a u64 integer (big-endian with leading zeroes trimmed).
pub fn encode_u64(val: u64) -> Vec<u8> {
    if val == 0 {
        encode_bytes(&[])
    } else {
        let bytes = val.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        encode_bytes(&bytes[skip..])
    }
}

/// RLP encodes a u128 integer (big-endian with leading zeroes trimmed).
pub fn encode_u128(val: u128) -> Vec<u8> {
    if val == 0 {
        encode_bytes(&[])
    } else {
        let bytes = val.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        encode_bytes(&bytes[skip..])
    }
}

/// RLP encodes a list of previously RLP-encoded items.
pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_len: usize = items.iter().map(|it| it.len()).sum();
    let mut out = Vec::new();
    if payload_len <= 55 {
        out.push(0xc0 + payload_len as u8);
    } else {
        let len_bytes = payload_len.to_be_bytes();
        let skip = len_bytes.iter().take_while(|&&b| b == 0).count();
        let active = &len_bytes[skip..];
        out.push(0xf7 + active.len() as u8);
        out.extend_from_slice(active);
    }
    for item in items {
        out.extend_from_slice(item);
    }
    out
}
