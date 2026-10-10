import { useCallback, useEffect, useMemo, useState } from 'react';
import { Agent, Api, Approval, AuditEntry, Campaign, Incident } from './api';
import { FlowDiagram } from './FlowDiagram';

type Tab = 'overview' | 'redteam' | 'incidents' | 'approvals' | 'audit';

export function App() {
  const [key, setKey] = useState(() => sessionStorage.getItem('sf-key') ?? '');
  const api = useMemo(() => new Api(key), [key]);
  const [role, setRole] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>('overview');
  const [error, setError] = useState<string | null>(null);

  const [agents, setAgents] = useState<Agent[]>([]);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [chain, setChain] = useState<{ valid: boolean; length: number } | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [a, c, i, p, l, v] = await Promise.all([api.agents(), api.campaigns(), api.incidents(), api.approvals(), api.audit(), api.verifyAudit()]);
      setAgents(a); setCampaigns(c); setIncidents(i); setApprovals(p); setAudit(l); setChain(v);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }, [api]);

  useEffect(() => {
    if (!key) return;
    api.me().then((m) => { setRole(m.role); sessionStorage.setItem('sf-key', key); }).catch((e) => { setRole(null); setError(e.message); });
    void refresh();
    // Actualización en vivo por SSE; el sondeo lento es solo red de seguridad.
    const stop = api.stream(() => void refresh());
    const t = setInterval(refresh, 20000);
    return () => { stop(); clearInterval(t); };
  }, [key, api, refresh]);

  if (!role) return <Login onKey={setKey} error={error} />;

  const pending = approvals.filter((a) => a.status === 'pending').length;
  const canSign = role !== 'VIEWER';

  return (
    <div className="shell">
      <header>
        <h1>SpecterFlow <span>AI</span></h1>
        <nav>
          {(['overview', 'redteam', 'incidents', 'approvals', 'audit'] as Tab[]).map((t) => (
            <button key={t} className={tab === t ? 'active' : ''} onClick={() => setTab(t)}>
              {{ overview: 'Resumen', redteam: 'Red Teaming', incidents: 'Incidentes', approvals: 'Aprobaciones', audit: 'Auditoría' }[t]}
              {t === 'approvals' && pending > 0 && <b className="badge">{pending}</b>}
            </button>
          ))}
        </nav>
        <div className="who">{role} <button onClick={() => { sessionStorage.removeItem('sf-key'); setKey(''); setRole(null); }}>Salir</button></div>
      </header>
      {error && <div className="err">{error}</div>}
      <main>
        {tab === 'overview' && <Overview agents={agents} incidents={incidents} pending={pending} api={api} refresh={refresh} canAct={canSign} />}
        {tab === 'redteam' && <RedTeam agents={agents} campaigns={campaigns} api={api} refresh={refresh} canAct={role === 'SECOPS' || role === 'ADMIN'} />}
        {tab === 'incidents' && <Incidents incidents={incidents} />}
        {tab === 'approvals' && <Approvals approvals={approvals} api={api} refresh={refresh} canSign={canSign} />}
        {tab === 'audit' && <Audit entries={audit} chain={chain} />}
      </main>
    </div>
  );
}

function Login({ onKey, error }: { onKey: (k: string) => void; error: string | null }) {
  const [v, setV] = useState('');
  return (
    <div className="login">
      <h1>SpecterFlow <span>AI</span></h1>
      <p>Red Teaming autónomo · SOAR · Gobernanza financiera de agentes</p>
      <input type="password" placeholder="API key (secops-key, finops-key…)" value={v} onChange={(e) => setV(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && onKey(v)} />
      <button onClick={() => onKey(v)}>Entrar</button>
      {error && <div className="err">{error}</div>}
    </div>
  );
}

const sevClass = (s: string) => `sev sev-${s}`;
const usd = (n?: number) => (n === undefined ? '—' : `$${n.toFixed(4)}`);

function Overview({ agents, incidents, pending, api, refresh, canAct }: { agents: Agent[]; incidents: Incident[]; pending: number; api: Api; refresh: () => void; canAct: boolean }) {
  const [id, setId] = useState('demo-agent');
  const [url, setUrl] = useState('http://vulnerable-agent:9000');
  const open = agents.filter((a) => a.breaker.state !== 'CLOSED').length;
  const spend = agents.reduce((s, a) => s + a.breaker.windowCostUsd, 0);
  return (
    <>
      <div className="stats">
        <Stat label="Agentes" value={agents.length} />
        <Stat label="Breakers abiertos" value={open} bad={open > 0} />
        <Stat label="Gasto en ventana" value={usd(spend)} />
        <Stat label="Incidentes" value={incidents.length} bad={incidents.length > 0} />
        <Stat label="Aprobaciones pendientes" value={pending} bad={pending > 0} />
      </div>
      <FlowDiagram agents={agents} incidents={incidents.length} pending={pending} />
      <section>
        <h2>Agentes protegidos</h2>
        <table>
          <thead><tr><th>ID</th><th>Upstream</th><th>Breaker</th><th>Gasto / presupuesto</th><th>Req.</th><th>Estado</th><th /></tr></thead>
          <tbody>
            {agents.map((a) => (
              <tr key={a.id}>
                <td>{a.id}</td><td className="mono">{a.url}</td>
                <td><span className={`pill breaker-${a.breaker.state}`}>{a.breaker.state}</span></td>
                <td>{usd(a.breaker.windowCostUsd)} / ${a.breaker.budgetUsd}</td>
                <td>{a.breaker.requestsInWindow}</td>
                <td>{a.paused ? 'PAUSADO (aprobado)' : a.breaker.lastTrip?.reason ?? 'OK'}</td>
                <td>{canAct && a.breaker.state !== 'CLOSED' && <button onClick={async () => { await api.resetBreaker(a.id); refresh(); }}>Reset</button>}</td>
              </tr>
            ))}
            {!agents.length && <tr><td colSpan={7} className="empty">Registra un agente para enrutarlo por el proxy: <code>/proxy/&lt;id&gt;/…</code></td></tr>}
          </tbody>
        </table>
        {canAct && (
          <div className="row">
            <input value={id} onChange={(e) => setId(e.target.value)} placeholder="id" />
            <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="URL del agente" style={{ flex: 1 }} />
            <button onClick={async () => { await api.registerAgent(id, url).catch((e) => alert(e.message)); refresh(); }}>Registrar agente</button>
          </div>
        )}
      </section>
    </>
  );
}

const Stat = ({ label, value, bad }: { label: string; value: string | number; bad?: boolean }) => (
  <div className={`stat ${bad ? 'bad' : ''}`}><div className="v">{value}</div><div className="l">{label}</div></div>
);

function RedTeam({ agents, campaigns, api, refresh, canAct }: { agents: Agent[]; campaigns: Campaign[]; api: Api; refresh: () => void; canAct: boolean }) {
  const [target, setTarget] = useState(agents[0]?.url ?? 'http://vulnerable-agent:9000');
  const [budget, setBudget] = useState(1);
  return (
    <section>
      <h2>Simulación de ataques</h2>
      <p className="muted">Solo se permiten objetivos registrados o en la allow-list del sandbox. Catálogo: inyección de prompts, exfiltración de secretos, escalado de privilegios (MCP), APIs maliciosas y Token DoS.</p>
      {canAct ? (
        <div className="row">
          <input list="targets" value={target} onChange={(e) => setTarget(e.target.value)} style={{ flex: 1 }} />
          <datalist id="targets">{agents.map((a) => <option key={a.id} value={a.url} />)}</datalist>
          <label>Presupuesto $ <input type="number" step="0.1" min="0.01" value={budget} onChange={(e) => setBudget(Number(e.target.value))} style={{ width: 80 }} /></label>
          <button onClick={async () => { await api.startCampaign(target, budget).catch((e) => alert(e.message)); refresh(); }}>Lanzar campaña</button>
        </div>
      ) : <p className="muted">Se requiere rol SECOPS para lanzar campañas.</p>}
      <table>
        <thead><tr><th>Fecha</th><th>Objetivo</th><th>Estado</th><th>Explotados</th><th>Gravedad</th><th>Coste</th></tr></thead>
        <tbody>
          {campaigns.map((c) => (
            <tr key={c.id}>
              <td>{new Date(c.createdAt).toLocaleTimeString()}</td><td className="mono">{c.targetUrl}</td>
              <td>{c.status}{c.error && <span className="muted"> — {c.error}</span>}</td>
              <td>{c.exploited ?? '—'}</td><td>{c.maxSeverity && <span className={sevClass(c.maxSeverity)}>{c.maxSeverity}</span>}</td><td>{usd(c.costUsd)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function Incidents({ incidents }: { incidents: Incident[] }) {
  const [sel, setSel] = useState<Incident | null>(null);
  return (
    <div className="split">
      <section>
        <h2>Incidentes</h2>
        <ul className="list">
          {incidents.map((i) => (
            <li key={i.id} className={sel?.id === i.id ? 'sel' : ''} onClick={() => setSel(i)}>
              <span className={sevClass(i.severity)}>{i.severity}</span> {i.title}
              <div className="muted">{new Date(i.createdAt).toLocaleString()} · {i.kind} · {usd(i.costUsd)}</div>
            </li>
          ))}
          {!incidents.length && <li className="empty">Sin incidentes.</li>}
        </ul>
      </section>
      <section>
        <h2>Evidencia forense</h2>
        {sel ? (
          <>
            <h3>{sel.title}</h3>
            {sel.evidence.snapshot?.sha256 && <p className="mono">sha256 {sel.evidence.snapshot.sha256}</p>}
            <pre className="log">{JSON.stringify(sel.evidence, null, 2)}</pre>
            {sel.postmortem && <><h3>Post-mortem</h3><pre className="log">{sel.postmortem}</pre></>}
          </>
        ) : <p className="muted">Selecciona un incidente.</p>}
      </section>
    </div>
  );
}

function Approvals({ approvals, api, refresh, canSign }: { approvals: Approval[]; api: Api; refresh: () => void; canSign: boolean }) {
  const act = async (id: string, d: 'approve' | 'reject') => {
    const comment = d === 'reject' ? prompt('Motivo del rechazo') ?? undefined : undefined;
    await api.decide(id, d, comment).catch((e) => alert(e.message));
    refresh();
  };
  return (
    <section>
      <h2>Bandeja de aprobación (SecOps + FinOps)</h2>
      <p className="muted">Las mitigaciones permanentes solo se aplican cuando firman todos los roles requeridos.</p>
      {approvals.map((a) => (
        <div key={a.id} className={`card status-${a.status}`}>
          <div className="head"><b>{a.action}</b> <span className="mono">{a.agentId}</span> <span className={`pill st-${a.status}`}>{a.status}</span></div>
          <p>{a.summary}</p>
          <div className="sigs">
            {a.requiredRoles.map((r) => {
              const s = a.signatures.find((x) => x.signedAs === r);
              return <span key={r} className={`sig ${s ? 'ok' : ''}`}>{r}: {s ? (s.decision === 'approve' ? '✔ firmado' : '✘ rechazado') : 'pendiente'}</span>;
            })}
          </div>
          {a.status === 'pending' && canSign && (
            <div className="row"><button onClick={() => act(a.id, 'approve')}>Aprobar</button><button className="danger" onClick={() => act(a.id, 'reject')}>Rechazar</button></div>
          )}
          {a.appliedAt && <div className="muted">Aplicada {new Date(a.appliedAt).toLocaleString()}</div>}
          {a.execution && (
            <div className={a.execution.status === 'ok' ? 'muted' : 'err'}>
              Ejecución en el gateway: {a.execution.status === 'ok' ? '✔ correcta' : '✘ fallida'} ({a.execution.attempts} intento/s) — {a.execution.detail.slice(0, 160)}
              {a.execution.status === 'failed' && canSign && <button onClick={async () => { await api.retryExecute(a.id).catch((e) => alert(e.message)); refresh(); }}>Reintentar</button>}
            </div>
          )}
        </div>
      ))}
      {!approvals.length && <p className="empty">Nada que aprobar.</p>}
    </section>
  );
}

function Audit({ entries, chain }: { entries: AuditEntry[]; chain: { valid: boolean; length: number } | null }) {
  return (
    <section>
      <h2>Auditoría inmutable {chain && <span className={`pill ${chain.valid ? 'st-approved' : 'st-rejected'}`}>{chain.valid ? `cadena íntegra (${chain.length})` : 'CADENA ROTA'}</span>}</h2>
      <pre className="log">{[...entries].reverse().map((e) => `#${e.seq} ${e.ts} ${e.actor.padEnd(14)} ${e.action.padEnd(24)} ${JSON.stringify(e.detail)}  ${e.hash.slice(0, 10)}`).join('\n')}</pre>
    </section>
  );
}
