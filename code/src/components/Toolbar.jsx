import TopologyMenu from './TopologyMenu.jsx';

const LAB_STATUS = {
  unknown: { label: 'État inconnu', className: '' },
  offline: { label: 'Moteur de simulation hors ligne', className: 'lab-status--offline' },
  stopped: { label: 'Réseau arrêté', className: 'lab-status--stopped' },
  running: { label: 'Réseau en fonctionnement', className: 'lab-status--running' },
};

/**
 * Barre d'outils : choix de la topologie, démarrage / arrêt du réseau, et
 * ouverture des panneaux (simulation, détection) et des boîtes de dialogue
 * (datasets, modèles).
 *
 * `panel` : panneau de droite ouvert ('simulation', 'detection' ou null).
 * `active` : ce qui tourne en ce moment { simulation, detection, dataset, training }.
 */
export default function Toolbar({ lab, topologyId, onChooseTopology, panel, onTogglePanel, active, onOpenDatasets, onOpenModels }) {
  const status = LAB_STATUS[lab.status];
  const running = lab.status === 'running';
  const online = lab.status !== 'offline';
  const buttonClass = (on) => `btn${on ? ' btn--active' : ''}`;

  return (
    <header className="toolbar">
      <div className="toolbar__brand">
        <strong>IDS Lab</strong>
        <span className={`lab-status ${status.className}`} title={status.label}>
          <span className="lab-status__dot" />
          {lab.busy ? (running ? 'Arrêt…' : 'Démarrage… (plus long la première fois)') : status.label}
        </span>
      </div>

      <div className="toolbar__actions">
        <TopologyMenu topologyId={topologyId} onChoose={onChooseTopology} disabled={running || lab.busy} />
        {running ? (
          <button type="button" className="btn" onClick={lab.stop} disabled={lab.busy}>■ Arrêter</button>
        ) : (
          <button type="button" className="btn btn--primary" onClick={() => lab.start(topologyId)} disabled={!online || lab.busy}>
            ▶ Démarrer le réseau
          </button>
        )}

        {running && (
          <button type="button" className={buttonClass(panel === 'simulation' || active.simulation)} onClick={() => onTogglePanel('simulation')}
            title="Générer du trafic bénin et lancer des attaques">
            ⚡ Simulation{active.simulation ? ' (active)' : ''}
          </button>
        )}
        {running && (
          <button type="button" className={buttonClass(panel === 'detection' || active.detection)} onClick={() => onTogglePanel('detection')}
            title="Détection en direct : la Sonde IDS analyse le trafic avec un modèle entraîné">
            🛡 Détection{active.detection ? ' (active)' : ''}
          </button>
        )}
        {online && (
          <button type="button" className={buttonClass(active.dataset)} onClick={onOpenDatasets}
            title="Générer et télécharger des datasets étiquetés (trafic bénin + attaques)">
            🗂 Datasets{active.dataset ? ' (en cours…)' : ''}
          </button>
        )}
        {online && (
          <button type="button" className={buttonClass(active.training)} onClick={onOpenModels}
            title="Entraîner et évaluer un modèle ML-IDS sur les datasets">
            🧠 IDS{active.training ? ' (entraînement…)' : ''}
          </button>
        )}
      </div>
    </header>
  );
}
