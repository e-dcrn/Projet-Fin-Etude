import JobProgress, { IssueGroup } from './JobProgress.jsx';

/**
 * Boîte de dialogue de création du réseau (voir useDeployment pour les phases).
 *
 *   review  → bilan des problèmes détectés, confirmation
 *   running / done / failed → suivi de la tâche de fond (JobProgress)
 */
export default function DeployDialog({ run, onConfirm, onClose }) {
  if (!run) return null;

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="deploy-title">
        {run.phase === 'review' ? (
          <ReviewContent run={run} onConfirm={onConfirm} onClose={onClose} />
        ) : (
          <JobProgress
            run={run}
            titleId="deploy-title"
            titles={{ running: 'Création du réseau…', done: 'Réseau opérationnel', failed: 'Échec de la création du réseau' }}
            doneCaption={`${run.deviceCount} équipement(s) en fonctionnement`}
            onDone={onClose}
            doneLabel="Fermer"
          />
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
