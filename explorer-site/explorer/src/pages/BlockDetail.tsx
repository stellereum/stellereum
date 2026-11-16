import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Block, Transaction } from '../types';
import { getBlock } from '../lib/api';
import { formatStell, formatDateTime, timeAgo, truncateMiddle, copyToClipboard } from '../lib/format';

export const BlockDetail: React.FC = () => {
  const { height } = useParams<{ height: string }>();
  const [block, setBlock] = useState<Block | null>(null);
  const [txs, setTxs] = useState<Transaction[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!height) return;
    setLoading(true);
    setError(null);
    getBlock(height)
      .then((b) => {
        setBlock(b);
        // If block has transactions field
        if ((b as any).transactions) {
          setTxs((b as any).transactions);
        }
      })
      .catch((err) => setError(err.message || 'Block not found'))
      .finally(() => setLoading(false));
  }, [height]);

  const parsedHeight = Number(height);
  const numHeight = block?.height ?? (Number.isFinite(parsedHeight) ? parsedHeight : undefined);
  const prevLink = numHeight !== undefined ? `/block/${numHeight - 1}` : '/blocks';
  const nextLink = numHeight !== undefined ? `/block/${numHeight + 1}` : '/blocks';

  return (
    <div className="container" style={{ padding: '28px 20px 48px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)', marginBottom: 4 }}>
            <Link to="/blocks">Blocks</Link> / Block #{height}
          </div>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 12 }}>
            <span>Block #{numHeight !== undefined ? numHeight.toLocaleString() : height}</span>
            {block && (
              <span className={`badge-shard ${block.shard_id === 0 ? 'masterchain' : 'workchain'}`}>
                {block.shard_id === 0 ? 'Masterchain' : `Workchain #${block.shard_id}`}
              </span>
            )}
          </h1>
        </div>

        <div style={{ display: 'flex', gap: 8 }}>
          <Link
            to={prevLink}
            style={{
              padding: '6px 12px',
              borderRadius: 6,
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              color: 'var(--text)',
              fontSize: '0.85rem',
            }}
          >
            &lsaquo; Prev
          </Link>
          <Link
            to={nextLink}
            style={{
              padding: '6px 12px',
              borderRadius: 6,
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              color: 'var(--text)',
              fontSize: '0.85rem',
            }}
          >
            Next &rsaquo;
          </Link>
        </div>
      </div>

      {loading && <div style={{ color: 'var(--text-dim)', padding: 24 }}>Loading block details...</div>}
      {error && <div style={{ color: 'var(--danger)', padding: 24, background: 'var(--danger-bg)', borderRadius: 8 }}>{error}</div>}

      {block && (
        <div className="detail-card">
          <div className="detail-header">
            <div className="detail-title">Block Summary</div>
            <div style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>
              {timeAgo(block.timestamp)} ({formatDateTime(block.timestamp)})
            </div>
          </div>

          <div className="detail-rows">
            <div className="detail-row">
              <div className="detail-label">Block Hash</div>
              <div className="detail-val mono">
                {block.block_hash}
                <button
                  className="copy-btn"
                  onClick={() => {
                    copyToClipboard(block.block_hash);
                    setCopied(true);
                    setTimeout(() => setCopied(false), 2000);
                  }}
                >
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>
            </div>

            <div className="detail-row">
              <div className="detail-label">Proposer</div>
              <div className="detail-val mono">
                {(block.proposer_stl57 || block.proposer) ? (
                  <Link to={`/address/${block.proposer_stl57 || block.proposer}`}>
                    {block.proposer_stl57 || block.proposer}
                  </Link>
                ) : (
                  '—'
                )}
              </div>
            </div>

            <div className="detail-row">
              <div className="detail-label">Shard ID</div>
              <div className="detail-val">
                {block.shard_id === 0 ? '0 (Masterchain)' : `${block.shard_id} (Workchain)`}
              </div>
            </div>

            <div className="detail-row">
              <div className="detail-label">Transactions</div>
              <div className="detail-val" style={{ fontWeight: 600 }}>
                {block.tx_count} transactions included
              </div>
            </div>

            {block.state_root && (
              <div className="detail-row">
                <div className="detail-label">State Root</div>
                <div className="detail-val mono">{block.state_root}</div>
              </div>
            )}
          </div>
        </div>
      )}

      {txs.length > 0 && (
        <div className="panel" style={{ marginTop: 24 }}>
          <div className="panel-header">
            <div className="panel-title">Transactions in this Block ({txs.length})</div>
          </div>
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Tx Hash</th>
                  <th>From</th>
                  <th>To</th>
                  <th>Value</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {txs.map((t) => {
                  const fromAddr = t.from_stl57 || t.from_addr;
                  const toAddr = t.to_stl57 || t.to_addr;
                  return (
                  <tr key={t.hash}>
                    <td className="mono">
                      <Link to={`/tx/${t.hash}`}>{truncateMiddle(t.hash, 8, 8)}</Link>
                    </td>
                    <td className="mono">
                      {fromAddr ? (
                        <Link to={`/address/${fromAddr}`}>
                          {truncateMiddle(fromAddr, 6, 6)}
                        </Link>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td className="mono">
                      {toAddr ? (
                        <Link to={`/address/${toAddr}`}>
                          {truncateMiddle(toAddr, 6, 6)}
                        </Link>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td style={{ fontWeight: 600, color: 'var(--primary)' }}>
                      {formatStell(t.amount)}
                    </td>
                    <td>
                      <span className={`badge-status ${t.status || 'success'}`}>
                        {t.status || 'success'}
                      </span>
                    </td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
