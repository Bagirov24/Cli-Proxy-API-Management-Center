import { Component, type ReactNode } from 'react';
import { Link } from 'react-router-dom';

interface Props {
  children: ReactNode;
}
interface State {
  failed: boolean;
}

/** Isolate a broken opt-in mockup from the operational Management Center UI. */
export class SaasDemoErrorBoundary extends Component<Props, State> {
  state: State = { failed: false };

  static getDerivedStateFromError(): State {
    return { failed: true };
  }

  render() {
    if (this.state.failed) {
      return (
        <section role="alert" style={{ padding: '32px 12px', lineHeight: 1.7 }}>
          <h1>Демонстрация SaaS временно недоступна / SaaS demo is unavailable</h1>
          <p>Основная панель управления не затронута. / The core Management Center is unaffected.</p>
          <Link to="/">Вернуться на Dashboard / Back to Dashboard</Link>
        </section>
      );
    }
    return this.props.children;
  }
}
