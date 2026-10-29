import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { AccountInfo, Transaction } from '../types';
import { getAccount, getAccountTransactions } from '../lib/api';
import { formatStell, formatNano, timeAgo, truncateMiddle, copyToClipboard } from '../lib/format';

export const Address: React.FC = () => {
  const { address } = useParams<{ address: string }>();
  const [account, setAccount] = useState<AccountInfo | null>(null);
  const [txs, setTxs] = useState<Transaction[]>([]);
  const [activeTab, setActiveTab] = useState<'txs' | 'tokens' | 'contract' | 'staking'>('txs');
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!address) return;
    setLoading(true);
    Promise.all([
      getAccount(address).catch(() => ({
        address: address,
        address_stl57: address.startsWith('Stl57') ? address : '',
        balance: 0,
        nonce: 0,
        tx_count: 0,
        is_contract: false,
      })),
      getAccountTransactions(address).catch(() => []),
    ])
      .then(([acc, t]) => {
        if (acc) setAccount(acc);
        if (Array.isArray(t)) setTxs(t);
      })
      .finally(() => setLoading(false));
  }, [address]);

  const displayAddr = account?.address_stl57 || account?.address || address || '';
  const stellBal = (account?.balance ?? 0) / 1_000_000_000;
  const usdVal = (stellBal * 0.25).toLocaleString('en-US', { style: 'currency', currency: 'USD' });

  return (
    <div className="container" style={{ padding: '28px 20px 48px' }}>
      {/* Account Balance Card */}
      <div className="detail-card">
        <div className="detail-header">
          <div>
            <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-dim)', fontWeight: 600 }}>
              Sovereign Account
            </div>
            <div className="detail-title mono" style={{ fontSize: '1.1rem', marginTop: 4 }}>
              {displayAddr}
              <button
                className="copy-btn"
                onClick={() => {
                  copyToClipboard(displayAddr);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                }}
              >
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Nonce</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
              {account?.nonce ?? 0}
            </div>
          </div>
        </div>

        <div style={{ padding: '24px', display: 'flex', gap: '32px', flexWrap: 'wrap', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Balance</div>
            <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--primary)', fontFamily: 'var(--font-mono)' }}>
              {formatStell(account?.balance)}
            </div>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-dim)', marginTop: 2 }}>
              &asymp; {usdVal} @ $0.25
            </div>
          </div>

          <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: '32px' }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Activity</div>
            <div style={{ fontSize: '1.2rem', fontWeight: 700 }}>
              {txs.length} transactions
            </div>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-dim)', marginTop: 2 }}>
              Post-Quantum Pure Falcon
            </div>
            <div style={{ marginTop: 8 }}>
              <Link to={`/events?contract=${encodeURIComponent(displayAddr || address || '')}`} style={{ fontSize: '0.82rem', fontWeight: 600 }}>
                view contract events &rarr;
              </Link>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="tab-nav">
          <button
            className={`tab-btn ${activeTab === 'txs' ? 'active' : ''}`}
            onClick={() => setActiveTab('txs')}
          >
            Transactions ({txs.length})
          </button>
          <button
            className={`tab-btn ${activeTab === 'tokens' ? 'active' : ''}`}
            onClick={() => setActiveTab('tokens')}
          >
            Tokens (1)
          </button>
          <button
            className={`tab-btn ${activeTab === 'contract' ? 'active' : ''}`}
            onClick={() => setActiveTab('contract')}
          >
            Contract
          </button>
          <button
            className={`tab-btn ${activeTab === 'staking' ? 'active' : ''}`}
            onClick={() => setActiveTab('staking')}
          >
            Staking
          </button>
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === 'txs' && (
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
                      No transactions recorded for this address
                    </td>
                  </tr>
                )}
                {txs.map((t) => (
                  <tr key={t.hash}>
                    <td className="mono">
                      <Link to={`/tx/${t.hash}`} style={{ fontWeight: 600 }}>
                        {truncateMiddle(t.hash, 8, 8)}
                      </Link>
                    </td>
                    <td>
                      <Link to={`/block/${t.block_height}`}>
                        #{t.block_height?.toLocaleString()}
                      </Link>
                    </td>
                    <td className="mono">
                      <Link to={`/address/${t.from_stl57 || t.from_addr}`}>
                        {truncateMiddle(t.from_stl57 || t.from_addr, 6, 6)}
                      </Link>
                    </td>
                    <td className="mono">
                      <Link to={`/address/${t.to_stl57 || t.to_addr}`}>
                        {truncateMiddle(t.to_stl57 || t.to_addr, 6, 6)}
                      </Link>
                    </td>
                    <td style={{ fontWeight: 600, color: 'var(--primary)' }}>
                      {formatStell(t.amount)}
                    </td>
                    <td style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>
                      {formatNano(t.fee)}
                    </td>
                    <td>
                      <span className={`badge-status ${t.status || 'success'}`}>
                        {t.status || 'success'}
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-dim)' }}>{timeAgo(t.timestamp)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'tokens' && (
        <div className="panel" style={{ padding: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', background: 'var(--surface-hover)', borderRadius: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <img src="/img/stell-mark.svg" alt="STELL" style={{ width: 32, height: 32 }} />
              <div>
                <div style={{ fontWeight: 700 }}>Stellereum Native</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>STELL &middot; Native Token</div>
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{formatStell(account?.balance)}</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>{usdVal}</div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'contract' && (
        <div className="panel" style={{ padding: 24, color: 'var(--text-dim)', textAlign: 'center' }}>
          This address is a standard sovereign Post-Quantum EOA (Externally Owned Account).
        </div>
      )}

      {activeTab === 'staking' && (
        <div className="panel" style={{ padding: 24, textAlign: 'center', color: 'var(--text-dim)' }}>
          No active validator or delegator stake registered on this account.
        </div>
      )}
    </div>
  );
};
