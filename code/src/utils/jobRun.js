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
 *   done      le résultat de la tâche ({ dataset }, { model }…), une fois terminée
 */
export const newRun = (extra = {}) => ({ phase: 'running', step: 0, total: 0, steps: [], warnings: [], errors: [], ...extra });

/** Nouvel état de `run` d'après l'état de la tâche renvoyé par GET /jobs/{id}. */
export function applyJobState(run, job) {
  if (!run) return run;
  const updated = { ...run, steps: job.steps, warnings: job.warnings, total: job.total ?? run.total, step: job.steps.length };
  if (job.status === 'done') return { ...updated, phase: 'done', step: updated.total, done: { total: job.total, ...job.result } };
  if (job.status === 'failed') return { ...updated, phase: 'failed', errors: [job.error] };
  return updated;
}

export const isFinal = (job) => job.status !== 'running';
