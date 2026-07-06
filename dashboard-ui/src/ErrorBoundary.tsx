import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

// A single bad value rendered anywhere in the tree (e.g. a non-string LLM
// response slipping through as a message) would otherwise unmount the entire
// app with no recovery, since React has no default fallback for a render
// crash - this is what surfaced as a full black screen. Catching it here
// keeps the sidebar/nav usable so a bad view doesn't take down the whole app.
class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('Dashboard render error:', error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
          height: '100%', padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)'
        }}>
          <AlertTriangle size={40} style={{ color: 'var(--accent-red)', marginBottom: '1rem' }} />
          <h2 style={{ color: 'var(--text-primary)', marginBottom: '0.5rem' }}>This view hit an error</h2>
          <p style={{ maxWidth: '480px', marginBottom: '1.5rem' }}>
            Something in this view failed to render. Other tabs should still work - switching tabs or resetting
            the environment usually clears it.
          </p>
          <button className="btn btn-reset" style={{ width: 'auto', padding: '10px 24px' }} onClick={() => this.setState({ error: null })}>
            Try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

export default ErrorBoundary;
