/**
 * Suivi d'une tâche de fond du serveur (déploiement, dataset, entraînement :
 * voir backend/app/jobs.py), tel qu'il est affiché dans l'interface.
 *
 * `run` :
 *   phase     'running' | 'done' | 'failed'
 *   step      numéro de l'étape en cours, sur `total`
 *   steps     libellés des étapes déjà commencées (la dernière est en cours)
 *   warnings  avertissements non bloquants remontés par le serveur
 *   errors    messages d'échec
 *   done      l'événement de fin complet (porte le résultat : { dataset }, { model }…)
 */
export const newRun = (extra = {}) => ({ phase: 'running', step: 0, total: 0, steps: [], warnings: [], errors: [], ...extra });

/** Nouvel état de `run` après un événement reçu du serveur. */
export function applyJobEvent(run, event) {
  if (!run) return run;
  switch (event.type) {
    case 'progress':
      return { ...run, step: event.step, total: event.total, steps: [...run.steps, event.label] };
    case 'warning':
      return { ...run, warnings: [...run.warnings, event.message] };
    case 'done':
      return { ...run, phase: 'done', step: run.total, done: event };
    case 'error':
      return { ...run, phase: 'failed', errors: [event.message] };
    default:
      return run;
  }
}

export const isFinal = (event) => event.type === 'done' || event.type === 'error';
