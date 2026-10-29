import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { search } from '../lib/api';

export const SearchBar: React.FC = () => {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === '/' && document.activeElement !== inputRef.current) {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    const q = query.trim();
    if (!q) return;

    // Direct routing heuristics
    if (/^\d+$/.test(q)) {
      navigate(`/block/${q}`);
      setQuery('');
      return;
    }

    if (q.startsWith('Stl57') || (q.length === 64 && /^[0-9a-fA-F]+$/.test(q))) {
      setLoading(true);
      setError(null);
      try {
        const res = await search(q);
        if (res.type === 'block') {
          navigate(`/block/${res.value.height || q}`);
        } else if (res.type === 'tx') {
          navigate(`/tx/${res.value.hash || q}`);
        } else if (res.type === 'address') {
          navigate(`/address/${res.value.address || q}`);
        } else {
          // Default to address if starts with Stl57 or is 64 hex
          navigate(`/address/${q}`);
        }
        setQuery('');
      } catch {
        navigate(`/address/${q}`);
        setQuery('');
      } finally {
        setLoading(false);
      }
      return;
    }

    navigate(`/search?q=${encodeURIComponent(q)}`);
  };

  return (
    <form className="search-wrapper" onSubmit={handleSearch}>
      <div className="search-input-box">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ marginRight: 8, opacity: 0.6 }}>
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
        <input
          ref={inputRef}
          type="text"
          placeholder="Search by Address (Stl57 / hex), Tx Hash, Block #..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        {loading ? (
          <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Searching...</span>
        ) : (
          <span className="search-shortcut">/</span>
        )}
      </div>
      {error && <div style={{ position: 'absolute', top: '100%', left: 0, right: 0, background: 'var(--danger-bg)', color: 'var(--danger)', padding: '6px 12px', borderRadius: 6, fontSize: '0.8rem', marginTop: 4 }}>{error}</div>}
    </form>
  );
};
