/**
 * Boîte de dialogue de création du réseau (voir useDeployment pour les phases).
 *
 *   review  → bilan des problèmes détectés, confirmation
 *   running → barre de progression + étape en cours + étapes terminées
 *   done / failed → résultat
 */
export default function DeployDialog({ run, onConfirm, onClose }) {
  if (!run) return null;

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="deploy-title">
        {run.phase === 'review' ? (
          <ReviewContent run={run} onConfirm={onConfirm} onClose={onClose} />
        ) : (
          <ProgressContent run={run} onClose={onClose} />
        )}
      </div>
    </div>
  );
}

function ReviewContent({ run, onConfirm, onClose }) {
  const errors = run.issues.filter((i) => i.level === 'error');
  const warnings = run.issues.filter((i) => i.level === 'warning');

  return (
    <>
      <h2 id="deploy-title" className="modal__title">Vérification de la topologie</h2>
      <p className="modal__text">
        {run.blocked
          ? 'Le réseau ne peut pas être créé tant que ces erreurs ne sont pas corrigées.'
          : 'Le réseau peut être créé, mais certains points méritent votre attention.'}
      </p>

      {errors.length > 0 && <IssueGroup title={`Erreurs (${errors.length})`} level="error" items={errors.map((i) => i.message)} />}
      {warnings.length > 0 && (
        <IssueGroup title={`Avertissements (${warnings.length})`} level="warning" items={warnings.map((i) => i.message)} />
      )}

      <div className="modal__actions">
        <button type="button" className="btn btn--light" onClick={onClose}>
          {run.blocked ? 'Corriger' : 'Annuler'}
        </button>
        {!run.blocked && (
          <button type="button" className="btn btn--primary" onClick={() => onConfirm(run.topology)}>
            Créer le réseau quand même
          </button>
        )}
      </div>
    </>
  );
}

function ProgressContent({ run, onClose }) {
  const { phase, step, total, steps, warnings, errors } = run;
  const running = phase === 'running';
  // L'étape en cours n'est pas encore terminée : step - 1 étapes faites
  const percent = phase === 'done' ? 100 : total ? Math.round((Math.max(step - 1, 0) / total) * 100) : 0;
  const current = steps[steps.length - 1];

  const title = { running: 'Création du réseau…', done: 'Réseau opérationnel', failed: 'Échec de la création du réseau' }[phase];

  return (
    <>
      <h2 id="deploy-title" className={`modal__title modal__title--${phase}`}>
        {phase === 'done' && '✔ '}
        {title}
      </h2>

      <div
        className={`progress progress--${phase}`}
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent}
      >
        <div className="progress__bar" style={{ width: `${phase === 'failed' ? Math.max(percent, 4) : percent}%` }} />
      </div>
      <div className="progress__caption">
        <span>{running ? (current ?? 'Connexion au moteur de simulation…') : phase === 'done' ? `${run.deviceCount} équipement(s) en fonctionnement` : ''}</span>
        {total > 0 && <span className="progress__count">{phase === 'done' ? `${total}/${total}` : `Étape ${step}/${total}`}</span>}
      </div>

      {phase === 'failed' && <IssueGroup level="error" items={errors} />}
      {warnings.length > 0 && <IssueGroup level="warning" items={warnings} />}

      {steps.length > 0 && (
        <ol className="steps">
          {steps.map((label, i) => {
            const isCurrent = i === steps.length - 1 && phase !== 'done';
            const state = !isCurrent ? 'done' : running ? 'current' : 'failed';
            return (
              <li key={i} className={`steps__item steps__item--${state}`}>
                <span className="steps__icon" aria-hidden>
                  {{ done: '✓', current: '', failed: '✕' }[state]}
                </span>
                {label}
              </li>
            );
          })}
        </ol>
      )}

      <div className="modal__actions">
        <button type="button" className="btn btn--primary" onClick={onClose} disabled={running}>
          {running ? 'Patientez…' : 'Fermer'}
        </button>
      </div>
    </>
  );
}

function IssueGroup({ title, level, items }) {
  return (
    <div className={`issue-group issue-group--${level}`}>
      {title && <h3 className="issue-group__title">{title}</h3>}
      <ul>
        {items.map((message, i) => (
          <li key={i}>{message}</li>
        ))}
      </ul>
    </div>
  );
}
