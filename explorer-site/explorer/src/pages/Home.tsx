import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Block, Transaction, NetworkStats } from '../types';
import { getStats, getLatestBlocks, getLatestTransactions } from '../lib/api';
import { StatsGrid } from '../components/StatsGrid';
import { formatStell, timeAgo, truncateMiddle } from '../lib/format';

interface HomeProps {
  isLive: boolean;
}

export const Home: React.FC<HomeProps> = ({ isLive }) => {
  const [stats, setStats] = useState<NetworkStats | null>(null);
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [txs, setTxs] = useState<Transaction[]>([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    try {
      const [s, b, t] = await Promise.all([
        getStats().catch(() => null),
        getLatestBlocks(10).catch(() => []),
        getLatestTransactions(10).catch(() => []),
      ]);
      if (s) setStats(s);
      if (Array.isArray(b) && b.length > 0) setBlocks(b);
      if (Array.isArray(t)) setTxs(t);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    if (!isLive) return;
    const interval = setInterval(loadData, 3000);
    return () => clearInterval(interval);
  }, [isLive]);

  return (
    <div className="container" style={{ paddingBottom: 40 }}>
      <StatsGrid stats={stats} loading={loading && !stats} />

      <div className="dashboard-grid">
        {/* Left Column: Recent Blocks */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <span>Latest Blocks</span>
              <span className="count-badge">{blocks.length}</span>
            </div>
            <Link to="/blocks" className="panel-action">View all &rarr;</Link>
          </div>

          <div className="feed-list">
            {blocks.length === 0 && !loading && (
              <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-dim)' }}>
                No blocks indexed yet
              </div>
            )}
            {blocks.map((block) => (
              <div key={block.height} className="feed-item">
                <div className="feed-left">
                  <div className="feed-icon">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="2" y="7" width="20" height="14" rx="2" ry="2" />
                      <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16" />
                    </svg>
                  </div>
                  <div className="feed-info">
                    <div className="feed-title">
                      <Link to={`/block/${block.height}`}>#{block.height.toLocaleString()}</Link>
                      <span className={`badge-shard ${block.shard_id === 0 ? 'masterchain' : 'workchain'}`}>
                        {block.shard_id === 0 ? 'MC' : `WC #${block.shard_id}`}
                      </span>
                    </div>
                    <div className="feed-sub">
                      <span>Proposer: </span>
                      <Link to={`/address/${block.proposer_stl57 || block.proposer}`} className="mono">
                        {truncateMiddle(block.proposer_stl57 || block.proposer, 6, 6)}
                      </Link>
                    </div>
                  </div>
                </div>

                <div className="feed-right">
                  <div className="feed-value">
                    {block.tx_count} {block.tx_count === 1 ? 'tx' : 'txs'}
                  </div>
                  <div className="feed-sub">{timeAgo(block.timestamp)}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Column: Recent Transactions */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <span>Latest Transactions</span>
              <span className="count-badge">{txs.length}</span>
            </div>
            <Link to="/txs" className="panel-action">View all &rarr;</Link>
          </div>

          <div className="feed-list">
            {txs.length === 0 && !loading && (
              <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-dim)' }}>
                No transactions indexed yet
              </div>
            )}
            {txs.map((tx) => (
              <div key={tx.hash} className="feed-item">
                <div className="feed-left">
                  <div className="feed-icon" style={{ color: 'var(--success)' }}>
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
                    </svg>
                  </div>
                  <div className="feed-info">
                    <div className="feed-title">
                      <Link to={`/tx/${tx.hash}`} className="mono">
                        {truncateMiddle(tx.hash, 8, 8)}
                      </Link>
                      <span className={`badge-status ${tx.status || 'success'}`}>
                        {tx.status || 'success'}
                      </span>
                    </div>
                    <div className="feed-sub">
                      <span>From </span>
                      <Link to={`/address/${tx.from_stl57 || tx.from_addr}`} className="mono">
                        {truncateMiddle(tx.from_stl57 || tx.from_addr, 5, 5)}
                      </Link>
                      <span> to </span>
                      <Link to={`/address/${tx.to_stl57 || tx.to_addr}`} className="mono">
                        {truncateMiddle(tx.to_stl57 || tx.to_addr, 5, 5)}
                      </Link>
                    </div>
                  </div>
                </div>

                <div className="feed-right">
                  <div className="feed-value" style={{ color: 'var(--primary)' }}>
                    {formatStell(tx.amount)}
                  </div>
                  <div className="feed-sub">{timeAgo(tx.timestamp)}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
