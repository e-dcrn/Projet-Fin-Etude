import ExamplesMenu from './ExamplesMenu.jsx';

const LAB_STATUS = {
  unknown: { label: 'État inconnu', className: '' },
  offline: { label: 'Moteur de simulation hors ligne', className: 'lab-status--offline' },
  stopped: { label: 'Réseau arrêté', className: 'lab-status--stopped' },
  running: { label: 'Réseau en fonctionnement', className: 'lab-status--running' },
};

/**
 * Barre d'outils supérieure : exemples, outil câble, validation, état du réseau instancié.
 */
export default function Toolbar({
  cableModeActive,
  onToggleCableMode,
  onValidate,
  onClear,
  onLoadExample,
  onStopLab,
  onToggleTraffic,
  trafficActive,
  trafficRunning,
  onToggleScenario,
  scenarioActive,
  scenarioRunning,
  onOpenDatasets,
  datasetRunning,
  onOpenModels,
  trainingRunning,
  onToggleDetection,
  detectionActive,
  detectionRunning,
  nodeCount,
  errorCount,
  labStatus,
  busy,
}) {
  const status = LAB_STATUS[labStatus] ?? LAB_STATUS.unknown;

  return (
    <header className="toolbar">
      <div className="toolbar__brand">
        <strong>IDS Lab</strong>
        <span className="toolbar__subtitle">Éditeur de topologie</span>
        <span className={`lab-status ${status.className}`} title={status.label}>
          <span className="lab-status__dot" />
          {status.label}
        </span>
      </div>

      <div className="toolbar__actions">
        <ExamplesMenu onLoad={onLoadExample} disabled={busy} />

        <button
          type="button"
          className={`btn${cableModeActive ? ' btn--active' : ''}`}
          onClick={onToggleCableMode}
          aria-pressed={cableModeActive}
          title="Cliquez sur un équipement puis sur un switch pour les relier (Échap pour quitter)"
        >
          🔌 Câble {cableModeActive ? '(actif)' : ''}
        </button>

        {labStatus === 'running' && (
          <button
            type="button"
            className={`btn${trafficActive || trafficRunning ? ' btn--active' : ''}`}
            onClick={onToggleTraffic}
            aria-pressed={trafficActive}
            title="Générer du trafic de fond (bénin) sur le réseau"
          >
            📡 Trafic{trafficRunning ? ' (actif)' : ''}
          </button>
        )}
        {labStatus === 'running' && (
          <button
            type="button"
            className={`btn${scenarioActive || scenarioRunning ? ' btn--active' : ''}`}
            onClick={onToggleScenario}
            aria-pressed={scenarioActive}
            title="Lancer un scénario d'audit (reconnaissance, force brute)"
          >
            ⚡ Scénarios{scenarioRunning ? ' (actif)' : ''}
          </button>
        )}
        {labStatus === 'running' && (
          <button
            type="button"
            className={`btn${detectionActive || detectionRunning ? ' btn--active' : ''}`}
            onClick={onToggleDetection}
            aria-pressed={detectionActive}
            title="Détection en direct : une Sonde IDS analyse le trafic avec un modèle entraîné"
          >
            🛡 Détection{detectionRunning ? ' (active)' : ''}
          </button>
        )}
        {labStatus !== 'offline' && (
          <button
            type="button"
            className={`btn${datasetRunning ? ' btn--active' : ''}`}
            onClick={onOpenDatasets}
            title="Générer et télécharger des datasets étiquetés (trafic bénin + attaques)"
          >
            🗂 Datasets{datasetRunning ? ' (en cours…)' : ''}
          </button>
        )}
        {labStatus !== 'offline' && (
          <button
            type="button"
            className={`btn${trainingRunning ? ' btn--active' : ''}`}
            onClick={onOpenModels}
            title="Entraîner et évaluer un modèle ML-IDS sur les datasets"
          >
            🧠 IDS{trainingRunning ? ' (entraînement…)' : ''}
          </button>
        )}

        <button type="button" className="btn btn--danger" onClick={onClear} disabled={nodeCount === 0}>
          Tout effacer
        </button>
        {labStatus === 'running' && (
          <button type="button" className="btn" onClick={onStopLab} disabled={busy}>
            ■ Arrêter
          </button>
        )}

        {errorCount > 0 && <span className="toolbar__errors">{errorCount} erreur(s)</span>}
        <button type="button" className="btn btn--primary" onClick={onValidate} disabled={nodeCount === 0 || busy}>
          ✔ Valider la topologie
        </button>
      </div>
    </header>
  );
}
