import { useState } from 'react';

/**
 * Suivi d'une tâche de fond (génération de dataset, entraînement : voir useRecords) :
 * titre, barre de progression, erreurs / avertissements, étapes, et boutons
 * « Masquer » / « Annuler » pendant l'exécution. `children` : le résultat, une
 * fois la tâche terminée.
 */
export default function JobProgress({ run, titles, doneCaption, onCancel, onHide, onDone, doneLabel, titleId, children }) {
  const { phase, step, total, steps, warnings, errors } = run;
  const running = phase === 'running';
  const [cancelling, setCancelling] = useState(false);
  // L'étape en cours n'est pas encore terminée : step - 1 étapes faites
  const percent = phase === 'done' ? 100 : total ? Math.round((Math.max(step - 1, 0) / total) * 100) : 0;
  const current = steps[steps.length - 1];
  const title = phase === 'failed' && run.cancelled ? titles.cancelled : titles[phase];

  const cancel = async () => {
    setCancelling(true);
    try {
      await onCancel();
    } catch {
      setCancelling(false);
    }
  };

  return (
    <>
      <h2 id={titleId} className={`modal__title modal__title--${phase}`}>
        {phase === 'done' && '✔ '}
        {title}
      </h2>

      <div className={`progress progress--${phase}`} role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent}>
        <div className="progress__bar" style={{ width: `${phase === 'failed' ? Math.max(percent, 4) : percent}%` }} />
      </div>
      <div className="progress__caption">
        <span>{running ? (current ?? 'Préparation…') : phase === 'done' ? doneCaption : ''}</span>
        {total > 0 && <span className="progress__count">{phase === 'done' ? `${total}/${total}` : `Étape ${step}/${total}`}</span>}
      </div>

      {phase === 'failed' && <div className="issue-group issue-group--error"><ul>{errors.map((m, i) => <li key={i}>{m}</li>)}</ul></div>}
      {warnings.length > 0 && <div className="issue-group issue-group--warning"><ul>{warnings.map((m, i) => <li key={i}>{m}</li>)}</ul></div>}

      {phase === 'done' && children}

      {steps.length > 0 && (
        <ol className="steps">
          {steps.map((label, i) => {
            const isCurrent = i === steps.length - 1 && phase !== 'done';
            const state = !isCurrent ? 'done' : running ? 'current' : 'failed';
            return (
              <li key={i} className={`steps__item steps__item--${state}`}>
                <span className="steps__icon" aria-hidden>{{ done: '✓', current: '', failed: '✕' }[state]}</span>
                {label}
              </li>
            );
          })}
        </ol>
      )}

      <div className="modal__actions">
        {running ? (
          <>
            <button type="button" className="btn btn--light" onClick={onHide} title="La tâche continue en arrière-plan">
              Masquer
            </button>
            <button type="button" className="btn btn--danger" onClick={cancel} disabled={cancelling}>
              {cancelling ? 'Annulation…' : 'Annuler'}
            </button>
          </>
        ) : (
          <button type="button" className="btn btn--primary" onClick={onDone}>{doneLabel}</button>
        )}
      </div>
    </>
  );
}
