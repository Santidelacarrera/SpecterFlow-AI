import { Agent } from './api';

interface Props {
  agents: Agent[];
  incidents: number;
  pending: number;
}

/** Diagrama de flujo en vivo: Red Teaming → Engine → SOAR/FinOps → Bandeja de aprobación. */
export function FlowDiagram({ agents, incidents, pending }: Props) {
  const open = agents.filter((a) => a.breaker.state === 'OPEN').length;
  const nodes = [
    { x: 20, label: 'Red Teaming', sub: 'Ataques y prompts', hot: false },
    { x: 215, label: 'Agent Engine', sub: 'Intención y tokens', hot: false },
    { x: 410, label: 'SOAR & FinOps', sub: open ? `${open} breaker abierto` : 'Circuit breaker', hot: open > 0 },
    { x: 605, label: 'Bandeja', sub: pending ? `${pending} pendientes` : 'SecOps + FinOps', hot: pending > 0 },
  ];
  return (
    <svg viewBox="0 0 800 110" className="flow" role="img" aria-label="Flujo de SpecterFlow">
      <defs>
        <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
          <path d="M0 0L10 5L0 10z" fill="currentColor" />
        </marker>
      </defs>
      {nodes.map((n, i) => (
        <g key={n.label}>
          <rect x={n.x} y={25} width={175} height={60} rx={8} className={n.hot ? 'node hot' : 'node'} />
          <text x={n.x + 87} y={52} textAnchor="middle" className="t1">{n.label}</text>
          <text x={n.x + 87} y={71} textAnchor="middle" className="t2">{n.sub}</text>
          {i < nodes.length - 1 && <line x1={n.x + 177} y1={55} x2={n.x + 213} y2={55} stroke="currentColor" markerEnd="url(#arr)" />}
        </g>
      ))}
      <text x={400} y={14} textAnchor="middle" className="t2">{agents.length} agentes · {incidents} incidentes</text>
    </svg>
  );
}
