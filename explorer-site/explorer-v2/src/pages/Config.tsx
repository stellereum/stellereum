import React, { useEffect, useState } from 'react';
import { NetworkStats, ShardTopology, Validator } from '../types';
import { getStats, getShards, getValidators } from '../lib/api';

export const Config: React.FC = () => {
  const [stats, setStats] = useState<NetworkStats | null>(null);
  const [shardTopo, setShardTopo] = useState<ShardTopology | null>(null);
  const [validators, setValidators] = useState<Validator[] | null>(null);
  const [roundInfo, setRoundInfo] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    Promise.allSettled([getStats(), getShards(), getValidators()])
      .then(([statsRes, shardsRes, valsRes]) => {
        if (cancelled) return;
        if (statsRes.status === 'fulfilled') setStats(statsRes.value);
        if (shardsRes.status === 'fulfilled') setShardTopo(shardsRes.value);
        if (valsRes.status === 'fulfilled') {
          setValidators(valsRes.value.validators);
          setRoundInfo(valsRes.value.round);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const chainId = stats?.chain_id ?? 5757;
  const rawBlockTime = stats?.avg_block_time ?? stats?.block_time;
  const blockTimeDisplay =
    typeof rawBlockTime === 'number' && rawBlockTime > 0
      ? `${rawBlockTime.toFixed(2)}s (deterministic)`
      : loading
        ? 'Loading...'
        : '0.49s (deterministic)';

  const liveValidatorCount: number | null =
    validators !== null
      ? validators.length
      : typeof roundInfo?.validators === 'number'
        ? roundInfo.validators
        : typeof stats?.validators_count === 'number'
          ? stats.validators_count
          : null;

  const shards = shardTopo?.shards ?? [];
  const totalShardsCount = shardTopo?.total_shards ?? stats?.shards ?? (shards.length || null);

  const validatorSyncLabel =
    liveValidatorCount !== null && liveValidatorCount > 0
      ? liveValidatorCount === 1
        ? 'synchronized across 1 active validator'
        : `synchronized across all ${liveValidatorCount} active validators`
      : 'synchronized across active validators';

  return (
    <div className="container" style={{ padding: '28px 20px 48px' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: '1.4rem', fontWeight: 700 }}>Network Parameters &amp; Governance</h1>
        <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem', marginTop: 4 }}>
          On-chain consensus constants, cryptographic parameters, and active software upgrade plans
        </p>
      </div>

      <div className="dashboard-grid">
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">Consensus &amp; Sharding Constants</div>
          </div>
          <div className="detail-rows">
            <div className="detail-row">
              <div className="detail-label">Network ID</div>
              <div className="detail-val mono">{chainId} (stellereum-testnet)</div>
            </div>
            <div className="detail-row">
              <div className="detail-label">Consensus Protocol</div>
              <div className="detail-val">Pure PQ Falcon-512 BFT (Comet/Tendermint architecture)</div>
            </div>
            <div className="detail-row">
              <div className="detail-label">Active Validators</div>
              <div className="detail-val mono">
                {loading && liveValidatorCount === null
                  ? 'Loading...'
                  : liveValidatorCount !== null
                    ? `${liveValidatorCount} (BFT Quorum 2/3+)`
                    : 'Active set'}
              </div>
            </div>
            <div className="detail-row">
              <div className="detail-label">Target Block Time</div>
              <div className="detail-val mono" style={{ color: 'var(--success)', fontWeight: 600 }}>
                {blockTimeDisplay}
              </div>
            </div>
            <div className="detail-row">
              <div className="detail-label">Round Timeout</div>
              <div className="detail-val mono">3,500 ms</div>
            </div>
            <div className="detail-row">
              <div className="detail-label">Active Shards</div>
              <div className="detail-val" style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
                {shards.length > 0 ? (
                  shards.map((s) => (
                    <span
                      key={s.shard_id}
                      className={`badge-shard ${s.type === 'masterchain' ? 'masterchain' : 'workchain'}`}
                    >
                      Shard {s.shard_id} ({s.type === 'masterchain' ? 'Masterchain' : 'Workchain'})
                    </span>
                  ))
                ) : loading && totalShardsCount === null ? (
                  <span style={{ color: 'var(--text-dim)' }}>Loading...</span>
                ) : totalShardsCount !== null && totalShardsCount > 1 ? (
                  <>
                    <span className="badge-shard masterchain">Shard 0 (Masterchain)</span>
                    <span className="badge-shard workchain">{totalShardsCount - 1} Workchain(s)</span>
                  </>
                ) : (
                  <span className="badge-shard masterchain">Shard 0 (Masterchain)</span>
                )}
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
              <div className="detail-val mono">QUIC / UDP 9410 with ML-KEM-768 &amp; Falcon-512 PQ</div>
            </div>
            <div className="detail-row">
              <div className="detail-label">Session &amp; Attestation</div>
              <div className="detail-val">PQ Session Keys (SF1 Falcon-512) &amp; Attestation Layer</div>
            </div>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <div className="panel-title">Active Governance Upgrade Proposals</div>
        </div>
        <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-dim)' }}>
          No active fork proposals pending. Current version <span className="mono">v0.1.0-pq-fips206</span> is{' '}
          {validatorSyncLabel}.
        </div>
      </div>
    </div>
  );
};
