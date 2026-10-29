import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Transaction } from '../types';
import { getLatestTransactions } from '../lib/api';
import { formatStell, formatNano, timeAgo, truncateMiddle } from '../lib/format';

export const Transactions: React.FC = () => {
  const [txs, setTxs] = useState<Transaction[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getLatestTransactions(50)
      .then((list) => {
        if (Array.isArray(list)) setTxs(list);
      })
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="container" style={{ padding: '28px 20px 48px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 700 }}>Transactions</h1>
          <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem', marginTop: 4 }}>
            Live feed of sovereign post-quantum signed transfers and smart contracts
          </p>
        </div>
      </div>

      <div className="panel">
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Tx Hash</th>
                <th>Block</th>
                <th>From</th>
                <th>To</th>
                <th>Value</th>
                <th>Fee</th>
                <th>Status</th>
                <th>Age</th>
              </tr>
            </thead>
            <tbody>
              {txs.length === 0 && !loading && (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: 24, color: 'var(--text-dim)' }}>
                    No transactions found
                  </td>
                </tr>
              )}
              {txs.map((tx) => (
                <tr key={tx.hash}>
                  <td className="mono">
                    <Link to={`/tx/${tx.hash}`} style={{ fontWeight: 600 }}>
                      {truncateMiddle(tx.hash, 8, 8)}
                    </Link>
                  </td>
                  <td>
                    <Link to={`/block/${tx.block_height}`}>
                      #{tx.block_height?.toLocaleString()}
                    </Link>
                  </td>
                  <td className="mono">
                    <Link to={`/address/${tx.from_stl57 || tx.from_addr}`}>
                      {truncateMiddle(tx.from_stl57 || tx.from_addr, 6, 6)}
                    </Link>
                  </td>
                  <td className="mono">
                    <Link to={`/address/${tx.to_stl57 || tx.to_addr}`}>
                      {truncateMiddle(tx.to_stl57 || tx.to_addr, 6, 6)}
                    </Link>
                  </td>
                  <td style={{ fontWeight: 600, color: 'var(--primary)' }}>
                    {formatStell(tx.amount)}
                  </td>
                  <td style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>
                    {formatNano(tx.fee)}
                  </td>
                  <td>
                    <span className={`badge-status ${tx.status || 'success'}`}>
                      {tx.status || 'success'}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-dim)' }}>{timeAgo(tx.timestamp)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
