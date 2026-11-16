import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ContractSummary } from '../types';
import { getContracts, getContractEvents, getContractAbi } from '../lib/api';
import { friendlyError } from '../lib/errors';
import { truncateMiddle } from '../lib/format';

const PAGE_SIZE = 50;

/**
 * The CONTRACTS page: the contracts the indexer has seen events from, and the
 * ABI manifest of the selected one.
 *
 * The list comes from `GET /api/v2/contracts` (derived from the event log);
 * the per-contract events come from `GET /api/v2/contract/:address/events` and
 * the manifest from the node's `stell_getContractAbi`.
 */
export const Contracts: React.FC = () => {
  const [contracts, setContracts] = useState<ContractSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [selected, setSelected] = useState<ContractSummary | null>(null);
  const [abi, setAbi] = useState<any>(null);
  const [events, setEvents] = useState<any[]>([]);

  const load = (nextOffset: number) => {
    setLoading(true);
    setError(null);
    getContracts(PAGE_SIZE, nextOffset)
      .then((page) => {
        setContracts(page.contracts || []);
        setTotal(page.total ?? (page.contracts || []).length);
        setOffset(nextOffset);
      })
      .catch((err) => setError(friendlyError(err, 'Could not load contracts')))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load(0);
  }, []);

  // The selected contract: its ABI manifest (from the node) and its most
  // recent events (from the indexer).
  useEffect(() => {
    if (!selected) {
      setAbi(null);
      setEvents([]);
      return;
    }
    setAbi(null);
    setEvents([]);
    getContractAbi(selected.contract)
      .then((m) => setAbi(m))
      .catch(() => setAbi(null));
    getContractEvents(selected.contract, 25, 0)
      .then((page) => setEvents(page.events || []))
      .catch(() => setEvents([]));
  }, [selected]);

  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="container" style={{ padding: '28px 20px 48px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 700 }}>Contracts</h1>
          <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem', marginTop: 4 }}>
            Contracts that emitted events on the chain, with their committed ABI manifests
          </p>
        </div>
      </div>

      {error && (
        <div style={{ padding: 16, background: 'var(--danger-bg)', borderRadius: 8, marginBottom: 16 }}>
          <div style={{ color: 'var(--danger)', marginBottom: 8 }}>{error}</div>
          <button className="panel-button" onClick={() => load(offset)}>
            Try again
          </button>
        </div>
      )}

      <div className="panel">
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Contract</th>
                <th>Address (Stl57)</th>
                <th>Events</th>
                <th>Txs</th>
                <th>First block</th>
                <th>Last block</th>
              </tr>
            </thead>
            <tbody>
              {contracts.length === 0 && !loading && (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: 24, color: 'var(--text-dim)' }}>
                    No contracts found
                  </td>
                </tr>
              )}
              {contracts.map((c) => (
                <tr
                  key={c.contract}
                  onClick={() => setSelected(c)}
                  style={{ cursor: 'pointer' }}
                >
                  <td className="mono">
                    <Link to={`/address/${c.contract_stl57 || c.contract}`} onClick={(e) => e.stopPropagation()}>
                      {truncateMiddle(c.contract, 10, 8)}
                    </Link>
                  </td>
                  <td className="mono">
                    {c.contract_stl57 ? truncateMiddle(c.contract_stl57, 10, 8) : '-'}
                  </td>
                  <td style={{ fontWeight: 600 }}>{c.event_count}</td>
                  <td>{c.tx_count}</td>
                  <td>
                    <Link to={`/block/${c.first_block}`} onClick={(e) => e.stopPropagation()}>
                      #{c.first_block?.toLocaleString()}
                    </Link>
                  </td>
                  <td>
                    <Link to={`/block/${c.last_block}`} onClick={(e) => e.stopPropagation()}>
                      #{c.last_block?.toLocaleString()}
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel-header" style={{ borderTop: '1px solid var(--border)' }}>
          <div className="panel-title">
            Page {page} / {pages}
            <span className="count-badge">{total}</span>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="panel-button" disabled={offset === 0} onClick={() => load(Math.max(0, offset - PAGE_SIZE))}>
              Previous
            </button>
            <button className="panel-button" disabled={offset + PAGE_SIZE >= total} onClick={() => load(offset + PAGE_SIZE)}>
              Next
            </button>
          </div>
        </div>
      </div>

      {selected && (
        <div className="panel" style={{ marginTop: 20 }}>
          <div className="panel-header">
            <div className="panel-title">
              Contract detail
              <span className="count-badge">{selected.event_count} events</span>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <Link
                to={`/events?contract=${encodeURIComponent(selected.contract)}`}
                style={{ fontSize: '0.82rem', fontWeight: 600 }}
              >
                view in the Events feed &rarr;
              </Link>
              <button className="panel-button" onClick={() => setSelected(null)}>
                Close
              </button>
            </div>
          </div>

          <div className="detail-card" style={{ margin: 0, border: 'none' }}>
            <div className="detail-rows">
              <div className="detail-row">
                <div className="detail-label">Address</div>
                <div className="detail-val mono">{selected.contract}</div>
              </div>
              {selected.contract_stl57 && (
                <div className="detail-row">
                  <div className="detail-label">Stl57</div>
                  <div className="detail-val mono">{selected.contract_stl57}</div>
                </div>
              )}
              <div className="detail-row">
                <div className="detail-label">ABI manifest</div>
                <div className="detail-val mono" style={{ fontSize: '0.78rem', wordBreak: 'break-all' }}>
                  {abi?.abi
                    ? JSON.stringify(abi.abi)
                    : abi === null
                      ? 'no manifest (the contract carries no typed interface)'
                      : 'loading...'}
                </div>
              </div>
            </div>
          </div>

          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Block</th>
                  <th>Tx</th>
                  <th>Event</th>
                  <th>Data</th>
                </tr>
              </thead>
              <tbody>
                {events.length === 0 && (
                  <tr>
                    <td colSpan={4} style={{ textAlign: 'center', padding: 20, color: 'var(--text-dim)' }}>
                      No indexed events for this contract
                    </td>
                  </tr>
                )}
                {events.map((e: any, i: number) => (
                  <tr key={`${e.tx_hash}-${e.log_index ?? i}`}>
                    <td>
                      <Link to={`/block/${e.block_height}`}>#{e.block_height?.toLocaleString()}</Link>
                    </td>
                    <td className="mono">
                      <Link to={`/tx/${e.tx_hash}`}>{truncateMiddle(e.tx_hash, 8, 6)}</Link>
                    </td>
                    <td>
                      {e.event_name ? (
                        <span style={{ color: 'var(--primary)', fontWeight: 600 }}>{e.event_name}</span>
                      ) : (
                        <span className="mono" style={{ color: 'var(--text-dim)' }}>
                          {truncateMiddle(e.topic0, 6, 4)}
                        </span>
                      )}
                    </td>
                    <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                      {e.args?.data ? JSON.stringify(e.args.data) : truncateMiddle(String(e.data ?? ''), 20, 8)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
