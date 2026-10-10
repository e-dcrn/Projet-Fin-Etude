/**
 * Barre d'outils supérieure : outil câble, validation et réinitialisation.
 */
export default function Toolbar({
  cableModeActive,
  onToggleCableMode,
  onValidate,
  onClear,
  nodeCount,
  linkCount,
}) {
  return (
    <header className="toolbar">
      <div className="toolbar__brand">
        <strong>IDS Lab</strong>
        <span className="toolbar__subtitle">Éditeur de topologie</span>
      </div>

      <div className="toolbar__actions">
        <button
          type="button"
          className={`btn${cableModeActive ? ' btn--active' : ''}`}
          onClick={onToggleCableMode}
          aria-pressed={cableModeActive}
          title="Cliquez sur un équipement puis sur un autre pour les relier (Échap pour quitter)"
        >
          🔌 Câble {cableModeActive ? '(actif)' : ''}
        </button>

        <button type="button" className="btn btn--danger" onClick={onClear} disabled={nodeCount === 0}>
          Tout effacer
        </button>

        <span className="toolbar__stats">
          {nodeCount} équipement(s) · {linkCount} lien(s)
        </span>

        <button type="button" className="btn btn--primary" onClick={onValidate} disabled={nodeCount === 0}>
          ✔ Valider la topologie
        </button>
      </div>
    </header>
  );
}
