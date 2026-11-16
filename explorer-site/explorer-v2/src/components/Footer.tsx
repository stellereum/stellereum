import React from 'react';

export const Footer: React.FC = () => {
  return (
    <footer className="site-footer">
      <div className="container footer-inner">
        <div>
          <span>Stellereum Network Explorer &middot; Pure PQ Falcon-512 &middot; Chain ID 5757</span>
        </div>
        <div className="footer-links">
          <a href="https://stellereum.org" target="_blank" rel="noreferrer">Website</a>
          <a href="https://rpc.stellereum.org" target="_blank" rel="noreferrer">RPC Node</a>
          <a href="https://github.com/stellereum" target="_blank" rel="noreferrer">GitHub</a>
          <a href="https://t.me/stellereum" target="_blank" rel="noreferrer">Community</a>
        </div>
      </div>
    </footer>
  );
};
