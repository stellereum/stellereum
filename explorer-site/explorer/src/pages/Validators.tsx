import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Validator, LiveValidatorSet } from '../types';
import { getValidators, getLiveValidators, getLiveStakeOf } from '../lib/api';
import { formatStell, truncateMiddle } from '../lib/format';

type Source = 'live' | 'indexer' | 'none';

/**
 * The validator set.
 *
 * The LIVE set comes from the node's `stell_getValidators` — the set the node
 * itself derives from the staking ledger at every height boundary, with each
 * member's voting power, the total power and the quorum threshold. The
 * bonded amount of each member comes from `stell_stakeOf` (the node does not
 * expose the bond and the power separately in one answer).
 *
 * The indexer's `/api/v2/validators` is a STATIC snapshot, so it is only used
 * as a fallback (when the node's RPC is unreachable) — and the page says
 * which source it is showing, so a static snapshot is never mistaken for the
 * live set.
 */
export const Validators: React.FC = () => {
  const [validators, setValidators] = useState<Validator[]>([]);
  const [live, setLive] = useState<LiveValidatorSet | null>(null);
  const [stakes, setStakes] = useState<Record<string, string>>({});
  const [limits, setLimits] = useState<any>(null);
  const [round, setRound] = useState<any>(null);
  const [source, setSource] = useState<Source>('none');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // The LIVE set first.
    getLiveValidators()
      .then((set) => {
        setLive(set);
        setSource('live');
        // The bonded amount of each member, one `stell_stakeOf` per validator.
        // Bounded: the live set is capped at 250 active validators, and a
        // missing answer is simply not shown.
        const ids = (set.validators || []).slice(0, 64).map((v) => v.validator);
        if (ids.length === 0) return;
        Promise.all(
          ids.map(async (id) => {
            try {
              const s = await getLiveStakeOf(id);
              return [id, s.total] as const;
            } catch {
              return null;
            }
          })
        ).then((rows) => {
          const next: Record<string, string> = {};
          for (const row of rows) {
            if (row) next[row[0]] = row[1];
          }
          setStakes(next);
        });
      })
      .catch(() => {
        // The indexer snapshot is the fallback.
        return getValidators()
          .then((res) => {
            setValidators(res.validators || []);
            setLimits(res.limits);
            setRound(res.round);
            setSource('indexer');
          })
          .catch(() => setSource('none'));
      })
      .finally(() => setLoading(false));
  }, []);

  const liveRows = live?.validators || [];
  const totalPower = live?.total_power ?? round?.total_stake ?? '0';
  const quorum = live?.quorum ?? round?.quorum ?? '0';
  const fragileReason = live?.fragile_reason ?? null;

  const members = liveRows.length
    ? liveRows.map((v, i) => ({
        rank: i + 1,
        address: v.validator,
        address_stl57: '' as string,
        name: `Validator ${i + 1}`,
        stake: v.power,
        self_bond: v.power,
        delegated: '0',
        weight: 0,
        main: true,
        status: 'active',
        uptime: 100,
        commission_bps: 0,
        falcon_pubkey: '',
        blocks_proposed: 0,
      }))
    : validators;

  return (
    <div className="container" style={{ padding: '28px 20px 48px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 700 }}>Validators</h1>
          <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem', marginTop: 4 }}>
            Consensus validator cluster secured by Post-Quantum Falcon-512 &micro;QC
          </p>
        </div>
        {source !== 'none' && (
          <span
            className="badge-status"
            style={{
              background: source === 'live' ? 'var(--success-bg)' : 'rgba(251, 191, 36, 0.1)',
              color: source === 'live' ? 'var(--success)' : 'var(--warning)',
              border: '1px solid var(--border)',
            }}
            title={
              source === 'live'
                ? 'Read live from the node: stell_getValidators'
                : 'Static snapshot from the indexer (the node RPC was unreachable)'
            }
          >
            {source === 'live' ? 'LIVE · stell_getValidators' : 'INDEXER SNAPSHOT'}
          </span>
        )}
      </div>

      {source === 'indexer' && (
        <div
          style={{
            color: 'var(--warning)',
            padding: 12,
            background: 'rgba(251, 191, 36, 0.08)',
            borderRadius: 8,
            marginBottom: 16,
            fontSize: '0.85rem',
          }}
        >
          The node's <span className="mono">stell_getValidators</span> was unreachable: this is the
          indexer's <strong>static</strong> validator snapshot, not the live set.
        </div>
      )}

      {live?.fragile && (
        <div
          style={{
            color: 'var(--danger)',
            padding: 12,
            background: 'var(--danger-bg)',
            borderRadius: 8,
            marginBottom: 16,
            fontSize: '0.85rem',
          }}
        >
          <strong>Fragile quorum.</strong> The quorum needs 100% of the set, so a single validator
          down stops the chain.
          {fragileReason ? ` (${fragileReason})` : ''}
        </div>
      )}

      <div className="stats-ribbon" style={{ margin: '0 0 24px' }}>
        <div className="stat-card">
          <div className="stat-label">Active Set</div>
          <div className="stat-value">{members.length}</div>
          <div className="stat-sub">{source === 'live' ? 'from the node' : 'from the indexer'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Total Staked</div>
          <div className="stat-value">{formatStell(totalPower)}</div>
          <div className="stat-sub">Quorum: {formatStell(quorum)}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Quorum Rule</div>
          <div className="stat-value" style={{ fontSize: '1.05rem', color: 'var(--primary)' }}>
            floor(2W/3)+1
          </div>
          <div className="stat-sub">power-weighted</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Bond Range</div>
          <div className="stat-value" style={{ fontSize: '1.05rem', color: 'var(--primary)' }}>
            {limits ? `${formatStell(limits.min_stake)} - ${formatStell(limits.max_stake)}` : '1K - 2K STELL'}
          </div>
          <div className="stat-sub">Min validator self-bond</div>
        </div>
      </div>

      <div className="panel">
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Rank</th>
                <th>Validator</th>
                <th>Address (Stl57)</th>
                <th>Stake</th>
                <th>{source === 'live' ? 'Voting Power' : 'Power'}</th>
                <th>Proposed</th>
                <th>Uptime</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {members.length === 0 && !loading && (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: 24, color: 'var(--text-dim)' }}>
                    No active validators found
                  </td>
                </tr>
              )}
              {members.map((v) => (
                <tr key={v.address}>
                  <td style={{ fontWeight: 700, color: 'var(--text-dim)' }}>#{v.rank}</td>
                  <td>
                    <div style={{ fontWeight: 600 }}>{v.name}</div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                      {source === 'live' ? 'PQ: Falcon-512 (FIPS 206)' : `PQ: ${v.falcon_pubkey ? v.falcon_pubkey.slice(0, 16) + '...' : 'Falcon-512'}`}
                    </div>
                  </td>
                  <td className="mono">
                    <Link to={`/address/${v.address_stl57 || v.address}`}>
                      {truncateMiddle(v.address_stl57 || v.address, 8, 8)}
                    </Link>
                  </td>
                  <td style={{ fontWeight: 600, color: 'var(--primary)', fontFamily: 'var(--font-mono)' }}>
                    {source === 'live'
                      ? stakes[v.address]
                        ? formatStell(stakes[v.address])
                        : '-'
                      : formatStell(v.stake)}
                  </td>
                  <td style={{ fontWeight: 600 }}>
                    {source === 'live' ? v.stake : v.weight ? `${(v.weight * 100).toFixed(1)}%` : '-'}
                  </td>
                  <td>{v.blocks_proposed ? v.blocks_proposed.toLocaleString() : '-'}</td>
                  <td>
                    <span style={{ color: 'var(--success)', fontWeight: 600 }}>
                      {v.uptime !== undefined ? `${v.uptime}%` : '-'}
                    </span>
                  </td>
                  <td>
                    <span className="badge-status success">{v.status || 'Active'}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
