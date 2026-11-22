import React, { useState } from 'react';
import { Routes, Route } from 'react-router-dom';
import { Header } from './components/Header';
import { Footer } from './components/Footer';
import { ErrorBoundary } from './components/ErrorBoundary';
import { Home } from './pages/Home';
import { Blocks } from './pages/Blocks';
import { BlockDetail } from './pages/BlockDetail';
import { Transactions } from './pages/Transactions';
import { TxDetail } from './pages/TxDetail';
import { Address } from './pages/Address';
import { Validators } from './pages/Validators';
import { Config } from './pages/Config';
import { Saved } from './pages/Saved';
import { Contracts } from './pages/Contracts';
import { Events } from './pages/Events';
import { Shards } from './pages/Shards';

export const App: React.FC = () => {
  const [isLive, setIsLive] = useState(true);

  return (
    <>
      <Header isLive={isLive} onToggleLive={() => setIsLive((v) => !v)} />
      <main style={{ flex: 1 }}>
        <ErrorBoundary>
        <Routes>
          <Route path="/" element={<Home isLive={isLive} />} />
          <Route path="/blocks" element={<Blocks />} />
          <Route path="/block/:height" element={<BlockDetail />} />
          <Route path="/txs" element={<Transactions />} />
          <Route path="/tx/:hash" element={<TxDetail />} />
          <Route path="/address/:address" element={<Address />} />
          <Route path="/validators" element={<Validators />} />
          <Route path="/contracts" element={<Contracts />} />
          <Route path="/events" element={<Events />} />
          <Route path="/shards" element={<Shards />} />
          <Route path="/config" element={<Config />} />
          <Route path="/saved" element={<Saved />} />
          <Route path="*" element={<Home isLive={isLive} />} />
        </Routes>
        </ErrorBoundary>
      </main>
      <Footer />
    </>
  );
};
