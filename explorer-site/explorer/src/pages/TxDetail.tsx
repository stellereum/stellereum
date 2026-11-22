import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Transaction, TxOutcome } from '../types';
import { getTransaction, getTxOutcome } from '../lib/api';
import { formatStell, formatNano, formatDateTime, timeAgo, truncateMiddle, copyToClipboard } from '../lib/format';

export const TxDetail: React.FC = () => {
  const { hash } = useParams<{ hash: string }>();
  const [tx, setTx] = useState<Transaction | null>(null);
  const [outcome, setOutcome] = useState<TxOutcome | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!hash) return;
    setLoading(true);
    setError(null);
    getTransaction(hash)
      .then(setTx)
      .catch((err) => setError(err.message || 'Transaction not found'))
      .finally(() => setLoading(false));

    // The OUTCOME: the contract call's return value, the gas it consumed and
    // the events it emitted. The indexer serves the DECODED events, the node's
    // receipt serves the return value and the gas used.
    getTxOutcome(hash)
      .then(setOutcome)
      .catch(() => setOutcome(null));
  }, [hash]);

  return (
    <div className="container" style={{ padding: '28px 20px 48px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)', marginBottom: 4 }}>
            <Link to="/txs">Transactions</Link> / Details
          </div>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 12 }}>
            <span>Transaction</span>
            {tx && (
              <span className={`badge-status ${tx.status || 'success'}`}>
                {tx.status || 'success'}
              </span>
            )}
          </h1>
        </div>
      </div>

      {loading && <div style={{ color: 'var(--text-dim)', padding: 24 }}>Loading transaction details...</div>}
      {error && <div style={{ color: 'var(--danger)', padding: 24, background: 'var(--danger-bg)', borderRadius: 8 }}>{error}</div>}

      {tx && (
        <>
          {/* Visual Flow Card */}
          <div className="flow-card">
            <div className="flow-side">
              <span className="flow-label">Sender</span>
              {(tx.from_stl57 || tx.from_addr) ? (
                <Link to={`/address/${tx.from_stl57 || tx.from_addr}`} className="mono" style={{ fontSize: '0.95rem', fontWeight: 600 }}>
                  {tx.from_stl57 || tx.from_addr}
                </Link>
              ) : (
                <span className="mono" style={{ fontSize: '0.95rem', fontWeight: 600 }}>—</span>
              )}
            </div>

            <div style={{ textAlign: 'center' }}>
              <div className="flow-arrow">&rarr;</div>
              <div style={{ color: 'var(--primary)', fontWeight: 700, fontSize: '1.1rem', marginTop: 2 }}>
                {formatStell(tx.amount)}
              </div>
            </div>

            <div className="flow-side" style={{ alignItems: 'flex-end' }}>
              <span className="flow-label">Recipient</span>
              {(tx.to_stl57 || tx.to_addr) ? (
                <Link to={`/address/${tx.to_stl57 || tx.to_addr}`} className="mono" style={{ fontSize: '0.95rem', fontWeight: 600 }}>
                  {tx.to_stl57 || tx.to_addr}
                </Link>
              ) : (
                <span className="mono" style={{ fontSize: '0.95rem', fontWeight: 600 }}>—</span>
              )}
            </div>
          </div>

          <div className="detail-card">
            <div className="detail-header">
              <div className="detail-title">Transaction Information</div>
              <div style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>
                {timeAgo(tx.timestamp)} ({formatDateTime(tx.timestamp)})
              </div>
            </div>

            <div className="detail-rows">
              <div className="detail-row">
                <div className="detail-label">Hash</div>
                <div className="detail-val mono">
                  {tx.hash}
                  <button
                    className="copy-btn"
                    onClick={() => {
                      copyToClipboard(tx.hash);
                      setCopied(true);
                      setTimeout(() => setCopied(false), 2000);
                    }}
                  >
                    {copied ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>

              <div className="detail-row">
                <div className="detail-label">Block Height</div>
                <div className="detail-val">
                  <Link to={`/block/${tx.block_height}`} style={{ fontWeight: 600 }}>
                    #{tx.block_height?.toLocaleString()}
                  </Link>
                </div>
              </div>

              <div className="detail-row">
                <div className="detail-label">Transaction Fee</div>
                <div className="detail-val">{formatNano(tx.fee)}</div>
              </div>

              <div className="detail-row">
                <div className="detail-label">Gas Used / Limit</div>
                <div className="detail-val">
                  {outcome?.gas_used != null
                    ? outcome.gas_used.toLocaleString()
                    : tx.gas_used?.toLocaleString() ?? '-'}
                  {' / '}
                  {tx.gas_limit?.toLocaleString() ?? '-'}
                </div>
              </div>

              <div className="detail-row">
                <div className="detail-label">Account Nonce</div>
                <div className="detail-val">{tx.nonce}</div>
              </div>

              <div className="detail-row">
                <div className="detail-label">Shards</div>
                <div className="detail-val">
                  Shard {tx.source_shard ?? 0} &rarr; Shard {tx.target_shard ?? 0}
                </div>
              </div>

              <div className="detail-row">
                <div className="detail-label">Signature Scheme</div>
                <div className="detail-val">
                  <span style={{ background: 'rgba(56, 189, 248, 0.1)', color: 'var(--primary)', padding: '2px 8px', borderRadius: 4, fontSize: '0.8rem', fontWeight: 600 }}>
                    Pure PQ Falcon-512 (FIPS 206)
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* The OUTCOME: return value, gas used, events. */}
          <div className="detail-card" style={{ marginTop: 20 }}>
            <div className="detail-header">
              <div className="detail-title">Outcome</div>
              {outcome && outcome.source.length > 0 && (
                <div style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>
                  events from: {outcome.source.join(', ')}
                </div>
              )}
            </div>

            <div className="detail-rows">
              <div className="detail-row">
                <div className="detail-label">Status</div>
                <div className="detail-val">
                  {outcome?.status ? (
                    <span className={`badge-status ${outcome.status === 'success' ? 'success' : 'failed'}`}>
                      {outcome.status}
                    </span>
                  ) : (
                    <span className="badge-status pending">{tx.status || 'unknown'}</span>
                  )}
                </div>
              </div>

              <div className="detail-row">
                <div className="detail-label">Return Value</div>
                <div className="detail-val mono">
                  {outcome?.return_value !== undefined && outcome?.return_value !== null
                    ? String(outcome.return_value)
                    : '—'}
                </div>
              </div>

              <div className="detail-row">
                <div className="detail-label">Gas Used</div>
                <div className="detail-val mono">
                  {outcome?.gas_used != null ? outcome.gas_used.toLocaleString() : '—'}
                </div>
              </div>

              {outcome?.fee_charged != null && (
                <div className="detail-row">
                  <div className="detail-label">Fee Charged</div>
                  <div className="detail-val mono">{formatNano(outcome.fee_charged)}</div>
                </div>
              )}

              {outcome?.contract_address && (
                <div className="detail-row">
                  <div className="detail-label">Contract</div>
                  <div className="detail-val mono">
                    <Link to={`/address/${outcome.contract_address}`}>
                      {truncateMiddle(outcome.contract_address, 10, 8)}
                    </Link>
                  </div>
                </div>
              )}
            </div>

            <div className="detail-rows" style={{ paddingTop: 0 }}>
              <div className="detail-row">
                <div className="detail-label">Events</div>
                <div className="detail-val">
                  <div style={{ marginBottom: 8 }}>
                    <Link to={`/events?tx=${tx.hash}`} style={{ fontSize: '0.82rem', fontWeight: 600 }}>
                      view events in the Events feed &rarr;
                    </Link>
                  </div>
                  {outcome && outcome.events.length > 0 ? (
                    <div style={{ width: '100%' }}>
                      {outcome.events.map((e, i) => (
                        <div
                          key={`${e.tx_hash}-${e.log_index ?? i}`}
                          style={{
                            borderTop: '1px solid var(--border-subtle)',
                            padding: '10px 0',
                          }}
                        >
                          <div style={{ display: 'flex', gap: 12, alignItems: 'baseline', flexWrap: 'wrap' }}>
                            <span style={{ color: 'var(--primary)', fontWeight: 600, fontSize: '0.85rem' }}>
                              {e.event_name || 'event'}
                            </span>
                            <Link
                              to={`/address/${e.contract_stl57 || e.contract}`}
                              className="mono"
                              style={{ fontSize: '0.75rem' }}
                            >
                              {e.contract_stl57 || e.contract}
                            </Link>
                            {e.log_index !== undefined && (
                              <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>
                                log #{e.log_index}
                              </span>
                            )}
                          </div>
                          {(e.args !== undefined || e.topics !== undefined || e.data !== undefined) && (
                            <pre
                              className="mono"
                              style={{
                                margin: '6px 0 0',
                                fontSize: '0.72rem',
                                color: 'var(--text-dim)',
                                whiteSpace: 'pre-wrap',
                                wordBreak: 'break-all',
                              }}
                            >
                              {JSON.stringify(e.args ?? { topics: e.topics, data: e.data }, null, 2)}
                            </pre>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <span style={{ color: 'var(--text-dim)' }}>No contract events emitted</span>
                  )}
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
