import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ShardTopology } from '../types';
import { getShards } from '../lib/api';
import { truncateMiddle } from '../lib/format';

/**
 * The SHARDS view: the live shard topology and the committed head of every
 * shard.
 *
 * The source is the indexer's `GET /api/v2/shards`, which proxies the node's
 * `stell_getShards` — the answer is therefore the NODE's view of the
 * topology (the heads it committed), never a locally reconstructed one. The
 * page labels the source it used.
 */
export const Shards: React.FC = () => {
  const [topology, setTopology] = useState<ShardTopology | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getShards()
      .then(setTopology)
      .catch((err) => setError(err.message || 'Could not load the shard topology'))
      .finally(() => setLoading(false));
  }, []);

  const shards = topology?.shards || [];
  const params = topology?.sharding;

  return (
    <div className="container" style={{ padding: '28px 20px 48px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 700 }}>Shards</h1>
          <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem', marginTop: 4 }}>
            The live shard topology and the committed head of every shard
          </p>
        </div>
      </div>

      {loading && <div style={{ color: 'var(--text-dim)', padding: 24 }}>Loading shard topology...</div>}
      {error && (
        <div style={{ color: 'var(--danger)', padding: 16, background: 'var(--danger-bg)', borderRadius: 8, marginBottom: 16 }}>
          {error}
        </div>
      )}

      {topology && (
        <>
          <div className="stats-ribbon" style={{ margin: '0 0 24px' }}>
            <div className="stat-card">
              <div className="stat-label">Total Shards</div>
              <div className="stat-value">{topology.total_shards ?? shards.length}</div>
              <div className="stat-sub">active in this network</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Routing Bits</div>
              <div className="stat-value">{topology.routing_prefix_bits ?? 0}</div>
              <div className="stat-sub">ceil(log2(shards))</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Shipped Cap</div>
              <div className="stat-value">{params?.max_shards ?? '-'}</div>
              <div className="stat-sub">max_shards (not the address space)</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Prefix Limit</div>
              <div className="stat-value">{params?.max_prefix_bits ?? '-'}</div>
              <div className="stat-sub">max_prefix_bits</div>
            </div>
          </div>

          <div className="panel" style={{ marginBottom: 20 }}>
            <div className="panel-header">
              <div className="panel-title">
                Shard heads
                <span className="count-badge">{shards.length}</span>
              </div>
              {topology.source && (
                <span className="stat-sub">source: {topology.source}</span>
              )}
            </div>
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Shard</th>
                    <th>Type</th>
                    <th>Tip Height</th>
                    <th>Tip Hash</th>
                    <th>State Root</th>
                    <th>Local</th>
                  </tr>
                </thead>
                <tbody>
                  {shards.length === 0 && (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', padding: 24, color: 'var(--text-dim)' }}>
                        No shard heads reported
                      </td>
                    </tr>
                  )}
                  {shards.map((s) => (
                    <tr key={s.shard_id}>
                      <td style={{ fontWeight: 700 }}>#{s.shard_id}</td>
                      <td>
                        <span className={`badge-shard ${s.type === 'masterchain' ? 'masterchain' : 'workchain'}`}>
                          {s.type === 'masterchain' ? 'MC' : 'WC'}
                        </span>
                      </td>
                      <td>
                        <Link to={`/block/${s.tip_height}`} style={{ fontWeight: 600 }}>
                          #{s.tip_height?.toLocaleString()}
                        </Link>
                      </td>
                      <td className="mono">
                        {s.tip_hash ? (
                          <Link to={`/block/${s.tip_hash}`}>
                            {truncateMiddle(s.tip_hash, 10, 8)}
                          </Link>
                        ) : '-'}
                      </td>
                      <td className="mono" style={{ color: 'var(--text-dim)' }}>
                        {s.state_root ? truncateMiddle(s.state_root, 10, 8) : '-'}
                      </td>
                      <td>
                        {s.local ? (
                          <span className="badge-status success">local</span>
                        ) : (
                          <span className="badge-status pending">remote</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {params && (
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">Routing rule</div>
                {params.rule_id && <span className="stat-sub mono">{params.rule_id}</span>}
              </div>
              <div className="detail-card" style={{ margin: 0, border: 'none' }}>
                <div className="detail-rows">
                  <div className="detail-row">
                    <div className="detail-label">Rule</div>
                    <div className="detail-val" style={{ fontSize: '0.85rem' }}>
                      {params.rule}
                    </div>
                  </div>
                  <div className="detail-row">
                    <div className="detail-label">Masterchain</div>
                    <div className="detail-val mono">
                      shard {params.masterchain_shard ?? 0}, addressed as {params.masterchain_address_form ?? '-1:<addr>'}
                    </div>
                  </div>
                  <div className="detail-row">
                    <div className="detail-label">Base workchain</div>
                    <div className="detail-val mono">shard {params.base_workchain_shard ?? 1}</div>
                  </div>
                  <div className="detail-row">
                    <div className="detail-label">Split / merge</div>
                    <div className="detail-val mono">
                      split at {params.split_load_threshold ?? '-'} txs/window, merge at {params.merge_load_threshold ?? '-'}
                    </div>
                  </div>
                  <div className="detail-row">
                    <div className="detail-label">Min accounts</div>
                    <div className="detail-val mono">{params.min_accounts_per_shard ?? '-'}</div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};
