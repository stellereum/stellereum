import React from 'react';
import { NetworkStats } from '../types';

interface StatsGridProps {
  stats: NetworkStats | null;
  loading?: boolean;
}

export const StatsGrid: React.FC<StatsGridProps> = ({ stats, loading }) => {
  const tipHeight = stats?.tip_height ?? 0;
  const tps = stats?.current_tps ?? 0.0;
  const blockTime = stats?.avg_block_time ? stats.avg_block_time.toFixed(2) : '0.00';
  const valCount = stats?.validators_count ?? 0;

  return (
    <div className="stats-ribbon">
      <div className="stat-card">
        <div className="stat-label">
          <span>Masterchain Tip</span>
          <span className="pulse-indicator" />
        </div>
        <div className="stat-value">
          #{loading ? '...' : tipHeight.toLocaleString()}
        </div>
        <div className="stat-sub">Finalized BFT Consensus</div>
      </div>

      <div className="stat-card">
        <div className="stat-label">
          <span>Throughput</span>
          <span style={{ color: 'var(--primary)', fontSize: '0.7rem', fontWeight: 600 }}>LIVE</span>
        </div>
        <div className="stat-value">
          {loading ? '...' : tps.toFixed(1)} <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>TPS</span>
        </div>
        <div className="stat-sub">{stats?.total_transactions?.toLocaleString() ?? '0'} indexed txs</div>
      </div>

      <div className="stat-card">
        <div className="stat-label">
          <span>Block Time</span>
          <span style={{ color: 'var(--success)', fontSize: '0.7rem', fontWeight: 600 }}>SUB-SECOND</span>
        </div>
        <div className="stat-value">
          {loading ? '...' : `${blockTime}s`}
        </div>
        <div className="stat-sub">Deterministic Falcon µQC</div>
      </div>

      <div className="stat-card">
        <div className="stat-label">
          <span>Active Validators</span>
          <span style={{ color: 'var(--accent)', fontSize: '0.7rem', fontWeight: 600 }}>N={valCount || '—'}</span>
        </div>
        <div className="stat-value">
          {loading ? '...' : `${valCount}`}
        </div>
        <div className="stat-sub">BFT Quorum 2/3+</div>
      </div>
    </div>
  );
};
