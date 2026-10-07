import { StrictMode, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';
type Scan = {
  id: string;
  status: string;
  score: number | null;
  findings: number;
  createdAt: string;
};
function App() {
  const [scans, setScans] = useState<Scan[]>([]);
  useEffect(() => {
    fetch(`${import.meta.env.VITE_API_URL ?? 'http://localhost:3000'}/dashboard`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((d) => setScans(d.scans))
      .catch(() => setScans([]));
  }, []);
  return (
    <main>
      <header>
        <div>
          <span className="eyebrow">SECURITY OPERATIONS</span>
          <h1>SecureFlow</h1>
          <p>Continuous application security, without the noise.</p>
        </div>
        <button>New scan</button>
      </header>
      <section className="hero">
        <div>
          <span className="eyebrow">RISK POSTURE</span>
          <strong>{scans[0]?.score ?? '—'}</strong>
          <span>/100</span>
        </div>
        <div className="pill">
          ● {scans.length ? 'Pipeline monitored' : 'Connect your first project'}
        </div>
      </section>
      <h2>Recent scans</h2>
      <div className="table">
        {scans.length ? (
          scans.map((scan) => (
            <article key={scan.id}>
              <div>
                <b>{scan.id.slice(0, 10)}</b>
                <small>{new Date(scan.createdAt).toLocaleString()}</small>
              </div>
              <span>{scan.findings} findings</span>
              <span className={scan.status.toLowerCase()}>{scan.status}</span>
              <strong>{scan.score ?? '—'}</strong>
            </article>
          ))
        ) : (
          <div className="empty">No scans yet. Start the API and submit a repository.</div>
        )}
      </div>
    </main>
  );
}
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
