import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { truncateMiddle } from '../lib/format';

export const Saved: React.FC = () => {
  const [savedAddresses, setSavedAddresses] = useState<string[]>([]);
  const [savedTxs, setSavedTxs] = useState<string[]>([]);

  useEffect(() => {
    try {
      const addrs = JSON.parse(localStorage.getItem('stell_saved_addrs') || '[]');
      const txs = JSON.parse(localStorage.getItem('stell_saved_txs') || '[]');
      setSavedAddresses(addrs);
      setSavedTxs(txs);
    } catch {
      // ignore
    }
  }, []);

  return (
    <div className="container" style={{ padding: '28px 20px 48px' }}>
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: '1.4rem', fontWeight: 700 }}>Bookmarked Accounts & Transactions</h1>
        <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem', marginTop: 4 }}>
          Locally saved addresses and transactions for quick monitoring
        </p>
      </div>

      <div className="dashboard-grid">
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">Saved Accounts ({savedAddresses.length})</div>
          </div>
          <div className="feed-list">
            {savedAddresses.length === 0 && (
              <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-dim)' }}>
                No accounts bookmarked yet.
              </div>
            )}
            {savedAddresses.map((a) => (
              <div key={a} className="feed-item">
                <Link to={`/address/${a}`} className="mono">{truncateMiddle(a, 12, 12)}</Link>
              </div>
            ))}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">Saved Transactions ({savedTxs.length})</div>
          </div>
          <div className="feed-list">
            {savedTxs.length === 0 && (
              <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-dim)' }}>
                No transactions bookmarked yet.
              </div>
            )}
            {savedTxs.map((t) => (
              <div key={t} className="feed-item">
                <Link to={`/tx/${t}`} className="mono">{truncateMiddle(t, 12, 12)}</Link>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
