import React from 'react';
import { NavLink, Link } from 'react-router-dom';
import { SearchBar } from './SearchBar';

interface HeaderProps {
  isLive?: boolean;
  onToggleLive?: () => void;
}

export const Header: React.FC<HeaderProps> = ({ isLive = true, onToggleLive }) => {
  return (
    <header className="site-header">
      <div className="container header-inner">
        <Link to="/" className="header-logo">
          <img src="/img/stell-mark.svg" alt="Stellereum" />
          <span>STELLEREUM</span>
          <span className="badge-net">TESTNET</span>
        </Link>

        <SearchBar />

        <nav className="nav-links">
          <NavLink to="/blocks" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            Blocks
          </NavLink>
          <NavLink to="/txs" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            Transactions
          </NavLink>
          <NavLink to="/contracts" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            Contracts
          </NavLink>
          <NavLink to="/events" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            Events
          </NavLink>
          <NavLink to="/shards" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            Shards
          </NavLink>
          <NavLink to="/validators" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            Validators
          </NavLink>
          <NavLink to="/config" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            Config
          </NavLink>
          <NavLink to="/saved" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            Saved
          </NavLink>

          {onToggleLive && (
            <button
              onClick={onToggleLive}
              style={{
                marginLeft: 8,
                padding: '4px 10px',
                borderRadius: 6,
                border: '1px solid var(--border)',
                background: isLive ? 'rgba(52, 211, 153, 0.1)' : 'rgba(255, 255, 255, 0.05)',
                color: isLive ? 'var(--success)' : 'var(--text-dim)',
                fontSize: '0.75rem',
                fontWeight: 600,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              <span className={isLive ? 'pulse-indicator' : ''} style={{ width: 6, height: 6 }} />
              {isLive ? 'LIVE' : 'PAUSED'}
            </button>
          )}
        </nav>
      </div>
    </header>
  );
};
