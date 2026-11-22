import { useState } from 'react';
import { useAction } from '../hooks/useAction.js';
import { formatPercent } from '../utils/format.js';
import { devicesOf, namesByIp } from '../utils/topology.js';

// Issue d'un verdict comparé à la vérité terrain (voir backend/app/detection.py).
const OUTCOMES = {
  alert: { icon: '✔', label: 'Attaque détectée', className: 'det-event--detected' },
  missed: { icon: '✕', label: 'Manquée', className: 'det-event--missed' },
};

const PROTOCOLS = { 1: 'ICMP', 6: 'TCP', 17: 'UDP' };

const clock = (epoch) => (epoch ? new Date(epoch * 1000).toLocaleTimeString('fr-FR') : '');

/**
 * Panneau de détection en direct : la Sonde IDS de la topologie (reliée au switch
 * qu'elle surveille) analyse le trafic avec un modèle entraîné. Tout flux classé
 * ATTACK est affiché comme une attaque détectée ; les attaques lancées depuis
 * l'interface permettent en plus de signaler celles que le modèle a manquées.
 */
export default function DetectionPanel({ detection, models, topology, onClose }) {
  const probe = devicesOf(topology, 'ids')[0];
  const ipNames = namesByIp(topology);
  const [model, setModel] = useState('');
  const { busy, error, act: guard } = useAction();

  const chosenModel = model || models[0]?.id || '';
  const modelMeta = models.find((m) => m.id === (detection.running ? detection.model?.id : chosenModel));
  const name = (ip) => ipNames.get(ip) ?? ip;

  const { running, stats } = detection;
  const ago = detection.lastWindowAt ? Math.max(0, Math.round(Date.now() / 1000 - detection.lastWindowAt)) : null;

  return (
    <aside className="traffic-panel" aria-label="Détection en direct">
      <header className="traffic-panel__head">
        <strong>🛡 Détection en direct</strong>
        <button type="button" className="icon-btn" title="Fermer" onClick={onClose}>×</button>
      </header>

      {(error || detection.error) && <div className="traffic-error" role="alert">{error || detection.error}</div>}

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
        ) : models.length === 0 ? (
          <p className="panel-hint">Aucun modèle : entraînez-en un d'abord (🧠 IDS).</p>
        ) : (
          <>
            <p className="field__hint">Sonde : <strong>{probe.name}</strong></p>
            <label className="field field--compact">
              <span className="field__label">Modèle</span>
              <select className="field__input" value={chosenModel} onChange={(e) => setModel(e.target.value)}>
                {models.map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}
              </select>
            </label>
            <button type="button" className="btn btn--primary btn--block" disabled={busy || !chosenModel}
              onClick={() => guard(() => detection.start(probe.id, chosenModel))}>
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
            « Manqué » n'est possible que pour les attaques lancées depuis ⚡ Simulation ou 🗂 Datasets : le moteur ne connaît
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
