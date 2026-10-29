import React from 'react';
import { Link } from 'react-router-dom';

interface ErrorBoundaryProps {
  children: React.ReactNode;
}

/**
 * App-level safety net: a render crash in ANY page must never become a white
 * screen. The boundary renders the error as a visible card (the header and
 * footer above/below stay mounted) instead of unmounting the whole tree.
 */
export class ErrorBoundary extends React.Component<ErrorBoundaryProps, { error: Error | null }> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    // Visible in the headless smoke check (`--enable-logging` captures it).
    console.error('Explorer render crash:', error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="container" style={{ padding: '48px 20px', maxWidth: 640 }}>
          <div
            style={{
              padding: 24,
              background: 'var(--danger-bg)',
              border: '1px solid var(--border)',
              borderRadius: 12,
            }}
          >
            <h1 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: 8 }}>
              Something went wrong rendering this page
            </h1>
            <p className="mono" style={{ fontSize: '0.8rem', color: 'var(--danger)', wordBreak: 'break-all' }}>
              {this.state.error.message || String(this.state.error)}
            </p>
            <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
              <button
                className="panel-button"
                onClick={() => this.setState({ error: null })}
              >
                Try again
              </button>
              <button
                className="panel-button"
                onClick={() => window.location.reload()}
              >
                Reload
              </button>
              <Link to="/" className="panel-button" onClick={() => this.setState({ error: null })}>
                Home
              </Link>
            </div>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
