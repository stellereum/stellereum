import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Block } from '../types';
import { getLatestBlocks } from '../lib/api';
import { timeAgo, truncateMiddle } from '../lib/format';

export const Blocks: React.FC = () => {
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getLatestBlocks(50)
      .then((list) => {
        if (Array.isArray(list)) setBlocks(list);
      })
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="container" style={{ padding: '28px 20px 48px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 700 }}>Blocks</h1>
          <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem', marginTop: 4 }}>
            Real-time feed of finalized blocks across Masterchain and Workchains
          </p>
        </div>
      </div>

      <div className="panel">
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Height</th>
                <th>Shard</th>
                <th>Block Hash</th>
                <th>Proposer</th>
                <th>Txs</th>
                <th>Age</th>
              </tr>
            </thead>
            <tbody>
              {blocks.length === 0 && !loading && (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: 24, color: 'var(--text-dim)' }}>
                    No blocks found
                  </td>
                </tr>
              )}
              {blocks.map((b) => (
                <tr key={b.height}>
                  <td>
                    <Link to={`/block/${b.height}`} style={{ fontWeight: 600 }}>
                      #{b.height.toLocaleString()}
                    </Link>
                  </td>
                  <td>
                    <span className={`badge-shard ${b.shard_id === 0 ? 'masterchain' : 'workchain'}`}>
                      {b.shard_id === 0 ? 'MC' : `WC #${b.shard_id}`}
                    </span>
                  </td>
                  <td className="mono">
                    <Link to={`/block/${b.height}`}>
                      {truncateMiddle(b.block_hash, 10, 10)}
                    </Link>
                  </td>
                  <td className="mono">
                    <Link to={`/address/${b.proposer_stl57 || b.proposer}`}>
                      {truncateMiddle(b.proposer_stl57 || b.proposer, 7, 7)}
                    </Link>
                  </td>
                  <td style={{ fontWeight: 600 }}>{b.tx_count}</td>
                  <td style={{ color: 'var(--text-dim)' }}>{timeAgo(b.timestamp)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
