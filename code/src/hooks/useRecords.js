import { useCallback, useEffect, useRef, useState } from 'react';

const newRun = (jobId) => ({ phase: 'running', jobId, step: 0, total: 0, steps: [], warnings: [], errors: [], result: null });

/**
 * Enregistrements produits par une tâche de fond du serveur (datasets, modèles
 * entraînés : voir backend/app/store.py et jobs.py) : liste des enregistrements
 * sauvegardés et création d'un nouvel enregistrement, suivie en temps réel.
 *
 * `api` décrit le type d'enregistrement :
 *   list()          → { [listKey]: [meta…], job: id de la tâche en cours ou null, ... }
 *   start(spec)     → { id } (tâche lancée)
 *   follow(id, cb)  → fonction d'arrêt du suivi (événements SSE)
 *   cancel(id), remove(id)
 *   listKey         clé de la liste dans la réponse de list()
 *   resultKey       clé du résultat dans l'événement `done`
 *
 * `run` décrit la tâche affichée :
 *   phase      'running' | 'done' (result : description de l'enregistrement, done : l'événement
 *              de fin complet) | 'failed' (errors)
 *   cancelled  vrai si l'échec vient d'une annulation demandée par l'utilisateur
 *   steps      étapes déjà commencées (la dernière est l'étape en cours)
 *   warnings   avertissements non bloquants remontés par le serveur
 *
 * Tant que `active` est vrai, la liste est chargée ; une tâche lancée avant un
 * rechargement de la page est reprise automatiquement.
 */
export function useRecords(active, api) {
  const [records, setRecords] = useState([]);
  const [info, setInfo] = useState({}); // le reste de la réponse de list() (options…)
  const [error, setError] = useState(null);
  const [run, setRun] = useState(null);
  const unfollow = useRef(null);
  const apiRef = useRef(api);
  apiRef.current = api;

  const refresh = useCallback(async () => {
    try {
      const { [apiRef.current.listKey]: list, ...rest } = await apiRef.current.list();
      setRecords(list);
      setInfo(rest);
      setError(null);
      return rest;
    } catch (err) {
      setError(err.messages ? err.messages.join('\n') : String(err));
      return null;
    }
  }, []);

  const handleEvent = useCallback(
    (event) => {
      setRun((current) => {
        if (!current) return current;
        switch (event.type) {
          case 'progress':
            return { ...current, step: event.step, total: event.total, steps: [...current.steps, event.label] };
          case 'warning':
            return { ...current, warnings: [...current.warnings, event.message] };
          case 'done':
            return { ...current, phase: 'done', step: current.total, result: event[apiRef.current.resultKey], done: event };
          case 'error':
            return { ...current, phase: 'failed', errors: [event.message] };
          default:
            return current;
        }
      });
      if (event.type === 'done' || event.type === 'error') refresh();
    },
    [refresh],
  );

  const follow = useCallback(
    (jobId) => {
      unfollow.current?.();
      setRun(newRun(jobId));
      unfollow.current = apiRef.current.follow(jobId, handleEvent);
    },
    [handleEvent],
  );

  useEffect(() => {
    if (!active) return;
    refresh().then((rest) => {
      // Tâche en cours côté serveur (page rechargée) : on en reprend le suivi.
      if (rest?.job && !unfollow.current) follow(rest.job);
    });
  }, [active, refresh, follow]);

  useEffect(() => () => unfollow.current?.(), []);

  /** Lance la tâche. Les erreurs de validation remontent à l'appelant. */
  const start = useCallback(
    async (spec) => {
      const { id } = await apiRef.current.start(spec);
      follow(id);
    },
    [follow],
  );

  const cancel = useCallback(async () => {
    if (!run?.jobId) return;
    await apiRef.current.cancel(run.jobId);
    setRun((current) => (current ? { ...current, cancelled: true } : current));
  }, [run]);

  const dismissRun = useCallback(() => {
    unfollow.current?.();
    unfollow.current = null;
    setRun(null);
  }, []);

  const remove = useCallback(
    async (id) => {
      await apiRef.current.remove(id);
      await refresh();
    },
    [refresh],
  );

  return { records, info, error, run, start, cancel, dismissRun, remove };
}
