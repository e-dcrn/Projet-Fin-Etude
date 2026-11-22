import { useState } from 'react';
import { toggled, useAction } from '../hooks/useAction.js';
import { attackTargets, benignTargets, devicesOf } from '../utils/topology.js';

// Types de trafic bénin (identifiants de backend/app/traffic_agent.py).
export const BENIGN_KINDS = [
  { id: 'icmp', label: 'Ping' },
  { id: 'http', label: 'Web (HTTP)' },
  { id: 'ssh', label: 'SSH' },
  { id: 'ftp', label: 'FTP' },
];

const STATUS = {
  running: { label: 'en cours', className: 'scenario--running' },
  exited: { label: 'terminé', className: 'scenario--done' },
  stopped: { label: 'arrêté', className: 'scenario--done' },
};

/**
 * Panneau « Simulation » :
 *   - trafic bénin : des PC imitent des utilisateurs (ping, web, SSH, FTP) vers
 *     toutes les autres machines. C'est le trafic « normal » de référence ;
 *   - attaques : un scan nmap ou une force brute hydra lancée depuis une machine
 *     vers une cible, puis le journal des attaques lancées.
 */
export default function SimulationPanel({ traffic, topology, onClose }) {
  const pcs = devicesOf(topology, 'pc');
  const sources = devicesOf(topology, 'pc', 'server');

  // Trafic bénin
  const [kinds, setKinds] = useState(() => new Set(BENIGN_KINDS.map((k) => k.id)));
  const [profile, setProfile] = useState('moderate');
  const [emitters, setEmitters] = useState(() => new Set(pcs.map((pc) => pc.id)));

  // Attaque
  const [source, setSource] = useState('');
  const [attackId, setAttackId] = useState('');
  const [target, setTarget] = useState('');
  const [speed, setSpeed] = useState('fast');
  const [log, setLog] = useState(null);

  const { busy, error, act } = useAction();
  const attack = traffic.attacks.find((a) => a.id === attackId);
  const nameOf = (id) => topology.nodes.find((n) => n.id === id)?.name ?? id;

  const startBenign = () =>
    act(() => Promise.all([...emitters].map((id) =>
      traffic.startBenign(id, profile, benignTargets(topology, id), 'toutes les machines', [...kinds]))));

  const showLog = (id) =>
    act(async () => {
      const { logs } = await traffic.fetchLogs(id);
      setLog({ id, text: logs || '(aucune sortie pour le moment)' });
    });

  return (
    <aside className="traffic-panel" aria-label="Simulation">
      <header className="traffic-panel__head">
        <strong>⚡ Simulation</strong>
        <button type="button" className="icon-btn" title="Fermer" onClick={onClose}>×</button>
      </header>

      {error && <div className="traffic-error" role="alert">{error}</div>}

      <section className="traffic-section traffic-section--first">
        <h3 className="traffic-section__title">Trafic bénin</h3>
        <p className="panel-hint panel-hint--tight">
          Les PC cochés imitent des utilisateurs vers toutes les autres machines : le trafic « normal » de référence.
        </p>

        <div className="traffic-field">
          <span className="field__label">Types de trafic</span>
          <div className="check-row">
            {BENIGN_KINDS.map((k) => (
              <label key={k.id} className="check">
                <input type="checkbox" checked={kinds.has(k.id)} onChange={() => setKinds((prev) => toggled(prev, k.id))} />
                <span>{k.label}</span>
              </label>
            ))}
          </div>
        </div>

        <div className="traffic-field">
          <span className="field__label">Émetteurs</span>
          <div className="check-row">
            {pcs.map((pc) => (
              <label key={pc.id} className="check">
                <input type="checkbox" checked={emitters.has(pc.id)} onChange={() => setEmitters((prev) => toggled(prev, pc.id))} />
                <span>{pc.name}</span>
              </label>
            ))}
          </div>
        </div>

        <label className="field field--compact">
          <span className="field__label">Fréquence</span>
          <select className="field__input" value={profile} onChange={(e) => setProfile(e.target.value)}>
            {traffic.profiles.map((p) => (
              <option key={p.id} value={p.id}>{p.label}</option>
            ))}
          </select>
        </label>

        <div className="traffic-actions">
          <button type="button" className="btn btn--primary" onClick={startBenign} disabled={busy || emitters.size === 0 || kinds.size === 0}>
            ▶ Démarrer
          </button>
          <button type="button" className="btn" onClick={() => act(() => traffic.stopBenign())} disabled={busy || traffic.benign.length === 0}>
            ■ Tout arrêter
          </button>
        </div>

        {traffic.benign.length > 0 && (
          <ul className="traffic-list">
            {traffic.benign.map((agent) => (
              <li key={agent.node} className="traffic-list__row">
                <span className="traffic-dot traffic-dot--on" />
                <span className="traffic-list__name">{nameOf(agent.node)}<span className="traffic-list__dest"> → {agent.dest}</span></span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="traffic-section">
        <h3 className="traffic-section__title">Attaque</h3>

        <label className="field field--compact">
          <span className="field__label">Depuis (source)</span>
          <select className="field__input" value={source} onChange={(e) => setSource(e.target.value)}>
            <option value="" disabled>Choisir un équipement…</option>
            {sources.map((s) => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </select>
        </label>

        <label className="field field--compact">
          <span className="field__label">Attaque</span>
          <select className="field__input" value={attackId} onChange={(e) => { setAttackId(e.target.value); setTarget(''); }}>
            <option value="" disabled>Choisir une attaque…</option>
            {traffic.attacks.map((a) => (
              <option key={a.id} value={a.id}>{a.name}</option>
            ))}
          </select>
        </label>
        {attack && <p className="field__hint">{attack.description}</p>}

        <label className="field field--compact">
          <span className="field__label">Cible{attack?.needs === 'subnet' ? ' (sous-réseau)' : ''}</span>
          <select className="field__input" value={target} onChange={(e) => setTarget(e.target.value)} disabled={!attack}>
            <option value="" disabled>{attack ? 'Choisir une cible…' : 'Choisir d\'abord une attaque'}</option>
            {attack && attackTargets(topology, attack.needs).map((t) => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </select>
        </label>

        <label className="field field--compact">
          <span className="field__label">Vitesse</span>
          <select className="field__input" value={speed} onChange={(e) => setSpeed(e.target.value)}>
            {traffic.speeds.map((s) => (
              <option key={s.id} value={s.id}>{s.label}</option>
            ))}
          </select>
        </label>

        <div className="traffic-actions">
          <button type="button" className="btn btn--danger" onClick={() => act(() => traffic.runScenario(source, attackId, target, speed))}
            disabled={busy || !source || !attackId || !target}>
            ⚡ Lancer l'attaque
          </button>
          <button type="button" className="btn btn--light" onClick={() => act(() => traffic.clearScenarios())} disabled={busy}>
            Effacer les terminées
          </button>
        </div>

        <ul className="traffic-list">
          {traffic.scenarios.map((s) => {
            const status = STATUS[s.status] ?? { label: s.status, className: '' };
            return (
              <li key={s.id} className="scenario">
                <div className="scenario__line">
                  <span className={`scenario__badge ${status.className}`}>{status.label}</span>
                  <span className="scenario__name">{s.name}</span>
                </div>
                <div className="scenario__meta">
                  {nameOf(s.source)} → {s.target} · vitesse {s.speed?.toLowerCase()}
                  {s.durationSec != null && ` · ${s.durationSec.toLocaleString('fr-FR')} s`}
                </div>
                {s.result && (
                  <div className={`scenario__result scenario__result--${s.result.ok ? 'ok' : 'fail'}`}
                    title="Résultat de l'attaque, indépendant de la détection">
                    {s.result.ok ? '✓' : '✗'} {s.result.text}
                  </div>
                )}
                {s.command && <code className="scenario__cmd">{s.command}</code>}
                <div className="scenario__actions">
                  {s.status === 'running' && (
                    <button type="button" className="btn btn--xs" onClick={() => act(() => traffic.stopScenarios(s.id))} disabled={busy}>
                      ■ Arrêter
                    </button>
                  )}
                  <button type="button" className="btn btn--light btn--xs" onClick={() => showLog(s.id)} disabled={busy}>
                    Voir le résultat
                  </button>
                </div>
                {log?.id === s.id && <pre className="scenario__log">{log.text}</pre>}
              </li>
            );
          })}
        </ul>
      </section>
    </aside>
  );
}
