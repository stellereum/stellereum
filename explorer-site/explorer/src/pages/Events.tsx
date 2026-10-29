import React, { useCallback, useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { ContractEvent } from '../types';
import { getEvents, getTxEvents, getContractAbi } from '../lib/api';
import { truncateMiddle } from '../lib/format';

const PAGE_SIZE = 50;

/**
 * The EVENTS (logs) feed: the contract events the indexer decoded, filtered by
 * contract address, by block range, or by transaction.
 *
 * Sources (all pre-existing, verified against the indexer + node):
 * - `GET /api/v2/events` (filtered feed),
 * - `GET /api/v2/tx/:hash/events` (one transaction, via `?tx=`),
 * - `GET /api/v2/contract/:address/events` (per contract, surfaced on the
 *   Contracts page).
 *
 * ABI decoding: the event names and the named `args.topics` / `args.data`
 * fields are decoded server-side by the indexer with the contract's ABI
 * manifest — the same manifest every node serves via `stell_getContractAbi`
 * (committed to the state trie next to the code hash). There is NO indexer
 * manifest endpoint: the node RPC is the manifest source, so this page fetches
 * it from the node to report the decode status. A row with `decoded=true`
 * (or a resolved `event_name`) shows ABI-resolved names; anything else shows
 * the raw topics/data with a `raw` badge — never blank, never guessed.
 */
export const Events: React.FC = () => {
  const [params, setParams] = useSearchParams();
  const txFilter = (params.get('tx') || '').trim();
  const contractParam = (params.get('contract') || '').trim();

  const [events, setEvents] = useState<ContractEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [contract, setContract] = useState(contractParam);
  const [fromBlock, setFromBlock] = useState(params.get('from') || '');
  const [toBlock, setToBlock] = useState(params.get('to') || '');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // The ABI manifest of the filtered contract, read from the NODE
  // (`stell_getContractAbi`) — the same manifest the indexer decodes with.
  // States: undefined = not asked (no contract filter) or loading;
  // null = asked but absent/unreachable; object = the manifest answer.
  const [abiState, setAbiState] = useState<
    { status: 'idle' | 'loading' | 'ready' | 'missing' | 'unreachable'; eventCount?: number }
  >({ status: 'idle' });

  const load = useCallback(
    (nextOffset: number, c: string, from: string, to: string, tx: string) => {
      setLoading(true);
      setError(null);
      if (tx) {
        // Single-transaction mode: the events of one tx, no pagination.
        getTxEvents(tx)
          .then((page) => {
            setEvents(page.events || []);
            setTotal(page.total ?? (page.events || []).length);
            setOffset(0);
            if ((page.events || []).length === 0) {
              setError(null);
            }
          })
          .catch((err) => {
            setEvents([]);
            setTotal(0);
            setError(err.message || `Could not load events for transaction ${truncateMiddle(tx, 10, 6)}`);
          })
          .finally(() => setLoading(false));
        return;
      }
      getEvents({
        contract: c.trim() || undefined,
        fromBlock: from.trim() ? Number(from.trim()) : undefined,
        toBlock: to.trim() ? Number(to.trim()) : undefined,
        limit: PAGE_SIZE,
        offset: nextOffset,
      })
        .then((page) => {
          setEvents(page.events || []);
          setTotal(page.total ?? (page.events || []).length);
          setOffset(nextOffset);
        })
        .catch((err) => {
          setEvents([]);
          setTotal(0);
          setError(err.message || 'Could not load events');
        })
        .finally(() => setLoading(false));
    },
    []
  );

  // Deep-link support: `?tx=` (from TxDetail "view events") and `?contract=`
  // (from address/contract pages) preset the filters on first render.
  useEffect(() => {
    setContract(contractParam);
    load(0, contractParam, params.get('from') || '', params.get('to') || '', txFilter);
    // Filters are applied on submit (see the form below), not on keystroke.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // The ABI status of the filtered contract: fetched from the node so the
  // page can say whether names below are ABI-resolved or raw.
  useEffect(() => {
    const c = (txFilter ? '' : contract).trim();
    if (!c) {
      setAbiState({ status: 'idle' });
      return;
    }
    setAbiState({ status: 'loading' });
    getContractAbi(c)
      .then((m) => {
        if (!m || m.abi === undefined || m.abi === null) {
          setAbiState({ status: 'missing' });
          return;
        }
        const evts = Array.isArray((m.abi as any)?.events) ? (m.abi as any).events.length : undefined;
        setAbiState({ status: 'ready', eventCount: evts });
      })
      .catch(() => setAbiState({ status: 'unreachable' }));
  }, [contract, txFilter]);

  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const applyFilters = (e: React.FormEvent) => {
    e.preventDefault();
    // Submitting the filter form leaves single-tx mode and returns to the feed.
    setParams(
      contract.trim() ? { contract: contract.trim() } : {},
      { replace: true }
    );
    load(0, contract, fromBlock, toBlock, '');
  };

  const decodedCount = events.filter((e) => e.decoded || e.event_name).length;

  return (
    <div className="container" style={{ padding: '28px 20px 48px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 700 }}>Events</h1>
          <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem', marginTop: 4 }}>
            {txFilter ? (
              <>Contract events emitted by transaction <span className="mono">{truncateMiddle(txFilter, 12, 10)}</span>, decoded with the contract ABI</>
            ) : (
              <>Contract events emitted in finalized blocks, decoded with the contract ABI</>
            )}
          </p>
        </div>
        {txFilter && (
          <Link to={`/tx/${txFilter}`} style={{ fontSize: '0.85rem' }}>
            &larr; back to transaction
          </Link>
        )}
      </div>

      {/* ABI manifest status: which ABI the names below were decoded with. */}
      {!txFilter && contract.trim() && (
        <div
          className="panel"
          style={{
            marginBottom: 16,
            padding: '10px 16px',
            fontSize: '0.82rem',
            color: 'var(--text-dim)',
          }}
        >
          {abiState.status === 'loading' && <>Resolving the contract ABI manifest&hellip;</>}
          {abiState.status === 'ready' && (
            <>
              ABI manifest: <strong style={{ color: 'var(--success)' }}>known</strong>
              {abiState.eventCount !== undefined && <> ({abiState.eventCount} event{abiState.eventCount === 1 ? '' : 's'})</>} via{' '}
              <span className="mono">stell_getContractAbi</span> — names below are ABI-resolved
              {decodedCount < events.length && (
                <>; {events.length - decodedCount} row{events.length - decodedCount === 1 ? '' : 's'} below show raw topics/data the manifest does not identify</>
              )}
              .
            </>
          )}
          {abiState.status === 'missing' && (
            <>No ABI manifest for this contract (the node answers empty) — showing raw topics/data.</>
          )}
          {abiState.status === 'unreachable' && (
            <>The node ABI endpoint is unreachable — showing the indexer-decoded names where present, raw topics/data otherwise.</>
          )}
        </div>
      )}

      {!txFilter && (
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header">
            <div className="panel-title">
              Filter
              <span className="count-badge">{total}</span>
            </div>
          </div>
          <form className="detail-rows" style={{ padding: '14px 18px' }} onSubmit={applyFilters}>
            <div className="detail-row">
              <div className="detail-label">Contract</div>
              <div className="detail-val">
                <input
                  className="filter-input"
                  placeholder="contract address (hex or Stl57)"
                  value={contract}
                  onChange={(e) => setContract(e.target.value)}
                />
              </div>
            </div>
            <div className="detail-row">
              <div className="detail-label">Block range</div>
              <div className="detail-val" style={{ display: 'flex', gap: 10 }}>
                <input
                  className="filter-input"
                  style={{ flex: 1 }}
                  placeholder="from"
                  value={fromBlock}
                  onChange={(e) => setFromBlock(e.target.value)}
                />
                <input
                  className="filter-input"
                  style={{ flex: 1 }}
                  placeholder="to"
                  value={toBlock}
                  onChange={(e) => setToBlock(e.target.value)}
                />
                <button className="panel-button" type="submit">
                  Apply
                </button>
              </div>
            </div>
          </form>
        </div>
      )}

      {error && (
        <div style={{ color: 'var(--danger)', padding: 16, background: 'var(--danger-bg)', borderRadius: 8, marginBottom: 16 }}>
          {error}
        </div>
      )}

      <div className="panel">
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Block</th>
                <th>Tx</th>
                <th>Contract</th>
                <th>Event</th>
                <th>Topics</th>
                <th>Data</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 && !loading && !error && (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: 24, color: 'var(--text-dim)' }}>
                    {txFilter
                      ? 'This transaction emitted no contract events'
                      : 'No events found for these filters'}
                  </td>
                </tr>
              )}
              {loading && events.length === 0 && (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: 24, color: 'var(--text-dim)' }}>
                    Loading events&hellip;
                  </td>
                </tr>
              )}
              {events.map((e, i) => {
                const decoded = Boolean(e.decoded || e.event_name);
                return (
                  <tr key={`${e.tx_hash}-${e.log_index ?? i}`}>
                    <td>
                      {e.block_height !== undefined && e.block_height !== null ? (
                        <Link to={`/block/${e.block_height}`} style={{ fontWeight: 600 }}>
                          #{Number(e.block_height)?.toLocaleString()}
                        </Link>
                      ) : (
                        <span style={{ color: 'var(--text-dim)' }}>—</span>
                      )}
                    </td>
                    <td className="mono">
                      {e.tx_hash ? (
                        <Link to={`/tx/${e.tx_hash}`}>{truncateMiddle(e.tx_hash, 8, 6)}</Link>
                      ) : (
                        <span style={{ color: 'var(--text-dim)' }}>—</span>
                      )}
                    </td>
                    <td className="mono">
                      {e.contract ? (
                        <Link to={`/address/${e.contract_stl57 || e.contract}`}>
                          {truncateMiddle(e.contract_stl57 || e.contract, 8, 8)}
                        </Link>
                      ) : (
                        <span style={{ color: 'var(--text-dim)' }}>—</span>
                      )}
                    </td>
                    <td>
                      {e.event_name ? (
                        <span style={{ color: 'var(--primary)', fontWeight: 600 }}>{e.event_name}</span>
                      ) : (
                        <span className="mono" style={{ color: 'var(--text-dim)' }}>
                          {e.topic0 ? truncateMiddle(e.topic0, 6, 4) : 'unidentified event'}
                        </span>
                      )}{' '}
                      <span
                        className="mono"
                        title={
                          decoded
                            ? 'decoded with the contract ABI manifest (stell_getContractAbi)'
                            : 'no ABI match: raw topics/data as emitted'
                        }
                        style={{
                          fontSize: '0.68rem',
                          padding: '1px 6px',
                          borderRadius: 4,
                          background: decoded ? 'rgba(52, 211, 153, 0.12)' : 'rgba(251, 191, 36, 0.12)',
                          color: decoded ? 'var(--success)' : 'var(--warning, #fbbf24)',
                          fontWeight: 700,
                        }}
                      >
                        {decoded ? 'decoded' : 'raw'}
                      </span>
                    </td>
                    <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                      {formatArgs(e.args?.topics) || formatRaw(e.topics) || '—'}
                    </td>
                    <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                      {formatArgs(e.args?.data) || formatRaw(e.data) || '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {!txFilter && (
          <div className="panel-header" style={{ borderTop: '1px solid var(--border)' }}>
            <div className="panel-title">
              Page {page} / {pages}
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                className="panel-button"
                disabled={offset === 0}
                onClick={() => load(Math.max(0, offset - PAGE_SIZE), contract, fromBlock, toBlock, '')}
              >
                Previous
              </button>
              <button
                className="panel-button"
                disabled={offset + PAGE_SIZE >= total}
                onClick={() => load(offset + PAGE_SIZE, contract, fromBlock, toBlock, '')}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

/** The named fields of a decoded event, rendered compactly. */
function formatArgs(args?: Record<string, unknown>): string {
  if (!args) return '';
  const entries = Object.entries(args);
  if (entries.length === 0) return '';
  return entries.map(([k, v]) => `${k}=${stringify(v)}`).join(' ');
}

/** A raw (undecoded) event payload: topics array or data blob. */
function formatRaw(data: unknown): string {
  if (data === undefined || data === null) return '';
  if (typeof data === 'string') return data.length > 28 ? truncateMiddle(data, 18, 8) : data;
  if (Array.isArray(data) && data.length === 0) return '';
  try {
    const s = JSON.stringify(data);
    return s.length > 40 ? truncateMiddle(s, 18, 8) : s;
  } catch {
    return '';
  }
}

function stringify(v: unknown): string {
  if (typeof v === 'string') return v;
  if (v === null || v === undefined) return '-';
  try {
    return truncateMiddle(JSON.stringify(v), 10, 6);
  } catch {
    return String(v);
  }
}
