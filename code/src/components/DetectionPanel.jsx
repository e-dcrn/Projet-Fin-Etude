import { useMemo, useState } from 'react';
import { formatPercent } from '../utils/format.js';

// Issue d'un verdict comparé à la vérité terrain (voir backend/app/detection.py).
const OUTCOMES = {
  alert: { icon: '✔', label: 'Attaque détectée', className: 'det-event--detected' },
  missed: { icon: '✕', label: 'Manquée', className: 'det-event--missed' },
};

const PROTOCOLS = { 1: 'ICMP', 6: 'TCP', 17: 'UDP' };

const clock = (epoch) => (epoch ? new Date(epoch * 1000).toLocaleTimeString('fr-FR') : '');

/** Adresse IP → nom de l'équipement, d'après les câbles de la topologie. */
function useIpNames(nodes, edges) {
  return useMemo(() => {
    const names = new Map(nodes.map((n) => [n.id, n.data?.properties?.name]));
    return new Map(edges.filter((e) => e.data?.ip).map((e) => [e.data.ip, names.get(e.source) ?? e.data.ip]));
  }, [nodes, edges]);
}

/**
 * Panneau de détection en direct : une Sonde IDS (reliée au switch qu'elle
 * surveille) analyse le trafic avec un modèle entraîné. Tout flux classé ATTACK
 * est affiché comme une attaque détectée ; les attaques lancées depuis l'interface
 * permettent en plus de signaler celles que le modèle a manquées.
 */
export default function DetectionPanel({ detection, models, topology, nodes, edges, onlineIds, onClose }) {
  const probes = useMemo(
    () => nodes.filter((n) => n.data?.deviceType === 'ids' && onlineIds.has(n.id)).map((n) => ({ id: n.id, name: n.data.properties.name })),
    [nodes, onlineIds],
  );
  const ipNames = useIpNames(nodes, edges);
  const [ids, setIds] = useState('');
  const [model, setModel] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const chosenIds = ids || probes[0]?.id || '';
  const chosenModel = model || models[0]?.id || '';
  // Le modèle utilisé (ou choisi) a-t-il été entraîné dans les mêmes conditions que cette détection ?
  const modelMeta = models.find((m) => m.id === (detection.running ? detection.model?.id : chosenModel));
  const warnings = [];
  if (modelMeta && modelMeta.flowWindowSec !== (detection.windowSec ?? 5)) {
    warnings.push(
      'Ce modèle a été entraîné sur des flux non découpés en fenêtres : les flux de la détection (pings, connexions '
      + 'longues coupées toutes les 5 s) lui sont inconnus et risquent de lever de fausses alertes. Réentraînez-le sur un '
      + 'dataset récent.',
    );
  }
  if (modelMeta?.topologies?.length && !modelMeta.topologies.some((t) => t.signature === topology.signature)) {
    warnings.push(
      `Ce modèle a été entraîné sur « ${modelMeta.topologies.map((t) => t.name).join(', ')} », pas sur la topologie `
      + `affichée (« ${topology.name} ») : ses résultats ne sont pas garantis.`,
    );
  }
  const name = (ip) => ipNames.get(ip) ?? ip;

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

  const { running, stats } = detection;
  const ago = detection.lastWindowAt ? Math.max(0, Math.round(Date.now() / 1000 - detection.lastWindowAt)) : null;

  return (
    <aside className="traffic-panel nokey" aria-label="Détection en direct">
      <header className="traffic-panel__head">
        <strong>🛡 Détection en direct</strong>
        <button type="button" className="icon-btn" title="Fermer" onClick={onClose}>×</button>
      </header>

      {(error || detection.error) && <div className="traffic-error" role="alert">{error || detection.error}</div>}
      {warnings.map((w) => (
        <div key={w} className="issue-group issue-group--warning det-warning">{w}</div>
      ))}

      <section className="traffic-section traffic-section--first">
        <p className="panel-hint panel-hint--tight">
          La Sonde IDS reçoit une copie de tout le trafic du switch qu'elle surveille (port miroir). Le modèle classe
          chaque flux toutes les {detection.windowSec ?? 5} s.
        </p>

        {running ? (
          <>
            <p className="det-status">
              <span className="traffic-dot traffic-dot--on" />
              <span>
                <strong>{detection.ids?.name}</strong> analyse avec « {detection.model?.name} »
                <br />
                <span className="traffic-list__dest">
                  {ago === null ? 'première fenêtre en cours…' : `dernière analyse il y a ${ago} s`}
                </span>
              </span>
            </p>
            <button type="button" className="btn btn--block" onClick={() => guard(detection.stop)} disabled={busy}>
              ■ Arrêter la détection
            </button>
          </>
        ) : probes.length === 0 ? (
          <p className="panel-hint">
            Aucune Sonde IDS allumée : ajoutez-en une, reliez-la au switch à surveiller (« segment surveillé » dans ses
            propriétés), puis validez la topologie.
          </p>
        ) : models.length === 0 ? (
          <p className="panel-hint">Aucun modèle : entraînez-en un d'abord (🧠 IDS).</p>
        ) : (
          <>
            <label className="field field--compact">
              <span className="field__label">Sonde IDS</span>
              <select className="field__input" value={chosenIds} onChange={(e) => setIds(e.target.value)}>
                {probes.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </label>
            <label className="field field--compact">
              <span className="field__label">Modèle</span>
              <select className="field__input" value={chosenModel} onChange={(e) => setModel(e.target.value)}>
                {models.map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}
              </select>
            </label>
            <button type="button" className="btn btn--primary btn--block" disabled={busy || !chosenIds || !chosenModel}
              onClick={() => guard(() => detection.start(chosenIds, chosenModel))}>
              ▶ Démarrer la détection
            </button>
          </>
        )}
      </section>

      {stats && (
        <section className="traffic-section">
          <div className="traffic-section__head">
            <h3 className="traffic-section__title">Bilan {running ? 'en direct' : 'de la dernière détection'}</h3>
            <button type="button" className="btn btn--light btn--xs" onClick={() => guard(detection.reset)} disabled={busy}
              title={running ? 'Remet le bilan à zéro ; la détection continue' : 'Efface le bilan de la dernière détection'}>
              Effacer
            </button>
          </div>
          <div className="det-kpis">
            <div className="det-kpi">
              <span className="det-kpi__value">{stats.alerts}</span>
              <span className="det-kpi__label">flux détectés comme attaque</span>
            </div>
            <div className="det-kpi">
              <span className="det-kpi__value">{stats.missed}</span>
              <span className="det-kpi__label">flux d'attaque manqués</span>
            </div>
            <div className="det-kpi">
              <span className="det-kpi__value">{stats.flows}</span>
              <span className="det-kpi__label">flux analysés</span>
            </div>
          </div>
          {detection.byAttack?.length > 0 && (
            <ul className="det-attacks">
              {detection.byAttack.map((a) => (
                <li key={a.label}>
                  <strong>{a.label}</strong> : {a.detected}/{a.detected + a.missed} flux détectés
                  {modelMeta?.train?.attacks && !modelMeta.train.attacks[a.label] && ' (attaque absente de l\'entraînement)'}
                </li>
              ))}
            </ul>
          )}
          <p className="field__hint">
            « Manqué » n'est possible que pour les attaques lancées depuis ⚡ Scénarios ou 🗂 Datasets : le moteur ne connaît
            pas celles tapées dans un terminal. Le taux de fausses alertes se lit dans le rapport du modèle (🧠 IDS).
          </p>
        </section>
      )}

      {detection.events.length > 0 && (
        <section className="traffic-section">
          <h3 className="traffic-section__title">Derniers événements</h3>
          <ul className="det-events">
            {detection.events.map((ev, i) => {
              const outcome = OUTCOMES[ev.outcome];
              return (
                <li key={`${ev.time}-${ev.src}-${ev.dstPort}-${i}`} className={`det-event ${outcome.className}`}>
                  <span className="det-event__badge" title={outcome.label}>{outcome.icon} {outcome.label}</span>
                  <span className="det-event__flow">
                    {name(ev.src)} → {name(ev.dst)}
                    <span className="traffic-list__dest"> {PROTOCOLS[ev.protocol] ?? ev.protocol}{ev.dstPort ? ` :${ev.dstPort}` : ''}</span>
                  </span>
                  <span className="det-event__meta">
                    {clock(ev.time)} · modèle : {ev.predicted} ({formatPercent(ev.confidence)}){ev.truth !== 'BENIGN' ? ` · scénario : ${ev.truth}` : ''}
                  </span>
                </li>
              );
            })}
          </ul>
        </section>
      )}
    </aside>
  );
}
