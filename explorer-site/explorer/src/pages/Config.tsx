import React from 'react';

export const Config: React.FC = () => {
  return (
    <div className="container" style={{ padding: '28px 20px 48px' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: '1.4rem', fontWeight: 700 }}>Network Parameters & Governance</h1>
        <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem', marginTop: 4 }}>
          On-chain consensus constants, cryptographic parameters, and active software upgrade plans
        </p>
      </div>

      <div className="dashboard-grid">
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">Consensus & Sharding Constants</div>
          </div>
          <div className="detail-rows">
            <div className="detail-row">
              <div className="detail-label">Network ID</div>
              <div className="detail-val mono">5757 (stellereum-testnet)</div>
            </div>
            <div className="detail-row">
              <div className="detail-label">Consensus Protocol</div>
              <div className="detail-val">Pure PQ Falcon-512 BFT (Comet/Tendermint architecture)</div>
            </div>
            <div className="detail-row">
              <div className="detail-label">Target Block Time</div>
              <div className="detail-val mono" style={{ color: 'var(--success)', fontWeight: 600 }}>0.49s (deterministic)</div>
            </div>
            <div className="detail-row">
              <div className="detail-label">Round Timeout</div>
              <div className="detail-val mono">3,500 ms</div>
            </div>
            <div className="detail-row">
              <div className="detail-label">Active Shards</div>
              <div className="detail-val">
                <span className="badge-shard masterchain">Shard 0 (Masterchain)</span>{' '}
                <span className="badge-shard workchain">Shard 1 (EVM Workchain)</span>
              </div>
            </div>
            <div className="detail-row">
              <div className="detail-label">Base Gas Fee</div>
              <div className="detail-val mono">280,000 nano-STELL</div>
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">Cryptographic Architecture</div>
          </div>
          <div className="detail-rows">
            <div className="detail-row">
              <div className="detail-label">Signature Scheme</div>
              <div className="detail-val">
                <span style={{ color: 'var(--primary)', fontWeight: 600 }}>Falcon-512 (FIPS 206)</span>
              </div>
            </div>
            <div className="detail-row">
              <div className="detail-label">Address Encoding</div>
              <div className="detail-val mono">
                Stl57 (Base58 + 4-byte BLAKE3 checksum)
              </div>
            </div>
            <div className="detail-row">
              <div className="detail-label">Hashing Function</div>
              <div className="detail-val mono">BLAKE3 (256-bit SIMD accelerated)</div>
            </div>
            <div className="detail-row">
              <div className="detail-label">State Trie</div>
              <div className="detail-val">Sparse Merkle Trie (SMT) with BLAKE3 node folding</div>
            </div>
            <div className="detail-row">
              <div className="detail-label">P2P Transport</div>
              <div className="detail-val mono">QUIC / UDP 9410 with Noise XX &amp; TLS 1.3</div>
            </div>
            <div className="detail-row">
              <div className="detail-label">Zero-Knowledge SVM</div>
              <div className="detail-val">zkML Halo2 / RISC-V Verification Layer</div>
            </div>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <div className="panel-title">Active Governance Upgrade Proposals</div>
        </div>
        <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-dim)' }}>
          No active fork proposals pending. Current version <span className="mono">v0.1.0-pq-fips206</span> is synchronized across all 4 validators.
        </div>
      </div>
    </div>
  );
};
