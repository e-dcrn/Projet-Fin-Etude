import { useMemo, useState } from 'react';
import { scenarioTargets, trafficSources } from '../utils/trafficTargets.js';
import { scenarioFlowsUrl } from '../services/topologyApi.js';

/** Horodatage court « il y a 12 s / 3 min ». */
function sinceLabel(startedSec) {
  if (!startedSec) return '';
  const secs = Math.max(0, Math.round(Date.now() / 1000 - startedSec));
  if (secs < 60) return `il y a ${secs} s`;
  return `il y a ${Math.round(secs / 60)} min`;
}

const STATUS = {
  running: { label: 'en cours', className: 'scenario--running' },
  exited: { label: 'terminé', className: 'scenario--done' },
};

/** Flux étiquetés produits par un scénario (CICFlowMeter → CSV téléchargeable). */
function ScenarioFlows({ scenario }) {
  const flows = scenario.flows ?? { status: 'none' };
  if (flows.status === 'pending') return <p className="scenario__flows">Flux étiquetés : préparation…</p>;
  if (flows.status === 'error') return <p className="scenario__flows">Flux étiquetés : export indisponible.</p>;
  if (flows.status !== 'ready') return null;

  const entries = Object.entries(flows.counts ?? {});
  return (
    <div className="scenario__flows">
      <div className="flow-counts">
        {entries.map(([label, n]) => (
          <span key={label} className={`flow-chip${label === 'BENIGN' ? '' : ' flow-chip--attack'}`}>
            {label} : {n}
          </span>
        ))}
      </div>
      <a className="btn btn--light btn--xs" href={scenarioFlowsUrl(scenario.id)} download>
        ⤓ Flux étiquetés ({flows.total} flux, CSV)
      </a>
    </div>
  );
}

/**
 * Panneau des scénarios d'audit : une activité malveillante typique
 * (reconnaissance nmap, force brute hydra) lancée au nom d'un équipement vers
 * une cible, puis le journal des scénarios avec leurs flux étiquetés (le trafic
 * « attaque » à détecter). Distinct de la génération de trafic bénin.
 */
export default function ScenarioPanel({ traffic, nodes, edges, onlineIds, onClose }) {
  const sources = useMemo(() => trafficSources(nodes, onlineIds), [nodes, onlineIds]);

  const [source, setSource] = useState('');
  const [attackId, setAttackId] = useState('');
  const [target, setTarget] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [log, setLog] = useState(null);

  const attack = traffic.attacks.find((a) => a.id === attackId) ?? null;
  const targetList = useMemo(
    () => (attack ? scenarioTargets(nodes, edges, attack.needs) : []),
    [attack, nodes, edges],
  );

  const guard = async (fn) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError(err.messages ? err.messages.join('\n') : String(err));
    } finally {
      setBusy(false);
    }
  };

  const launch = () => guard(() => traffic.runScenario(source, attackId, target));
  const showLog = (id) =>
    guard(async () => {
      const { logs } = await traffic.fetchLogs(id);
      setLog({ id, text: logs || '(aucune sortie pour le moment)' });
    });

  const canLaunch = source && attackId && target && !busy;

  return (
    <aside className="traffic-panel nokey" aria-label="Scénarios d'audit">
      <header className="traffic-panel__head">
        <strong>⚡ Scénarios d'audit</strong>
        <button type="button" className="icon-btn" title="Fermer" onClick={onClose}>×</button>
      </header>

      {error && <div className="traffic-error" role="alert">{error}</div>}

      <section className="traffic-section traffic-section--first">
        <p className="panel-hint panel-hint--tight">
          Reconnaissance ou attaque lancée au nom d'un équipement : le trafic « attaque » à détecter,
          exporté en flux étiquetés (format CICFlowMeter).
        </p>

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
          <span className="field__label">Scénario</span>
          <select
            className="field__input"
            value={attackId}
            onChange={(e) => { setAttackId(e.target.value); setTarget(''); }}
          >
            <option value="" disabled>Choisir un scénario…</option>
            {traffic.attacks.map((a) => (
              <option key={a.id} value={a.id}>{a.name}</option>
            ))}
          </select>
        </label>
        {attack && <p className="field__hint">{attack.description}</p>}

        <label className="field field--compact">
          <span className="field__label">Cible{attack?.needs === 'subnet' ? ' (sous-réseau)' : ''}</span>
          <select className="field__input" value={target} onChange={(e) => setTarget(e.target.value)} disabled={!attack}>
            <option value="" disabled>{attack ? 'Choisir une cible…' : 'Choisir d\'abord un scénario'}</option>
            {targetList.map((t) => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </select>
        </label>

        <button type="button" className="btn btn--danger btn--block" onClick={launch} disabled={!canLaunch}>
          ⚡ Lancer le scénario
        </button>
      </section>

      {traffic.scenarios.length > 0 && (
        <section className="traffic-section">
          <div className="traffic-section__head">
            <h3 className="traffic-section__title">Scénarios</h3>
            <button type="button" className="btn btn--light btn--xs" onClick={() => guard(() => traffic.clearScenarios())} disabled={busy}>
              Effacer les terminés
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
                    {s.subcategory} · vers {s.target} · {sinceLabel(s.started)}
                  </div>
                  <button type="button" className="btn btn--light btn--xs" onClick={() => showLog(s.id)} disabled={busy}>
                    Voir le résultat
                  </button>
                  {log?.id === s.id && <pre className="scenario__log">{log.text}</pre>}
                  <ScenarioFlows scenario={s} />
                </li>
              );
            })}
          </ul>
        </section>
      )}
    </aside>
  );
}
