import { useCallback, useEffect, useRef, useState } from 'react';
import { cancelJob, followJob } from '../services/topologyApi.js';
import { applyJobEvent, isFinal, newRun } from '../utils/jobRun.js';

/**
 * Enregistrements produits par une tâche de fond du serveur (datasets, modèles
 * entraînés : voir backend/app/store.py et jobs.py) : liste des enregistrements
 * sauvegardés et création d'un nouvel enregistrement, suivie en temps réel.
 *
 * `api` décrit le type d'enregistrement :
 *   list()          → { [listKey]: [meta…], job: id de la tâche en cours ou null, ... }
 *   start(spec)     → { id } (tâche lancée)
 *   remove(id)
 *   listKey         clé de la liste dans la réponse de list()
 *
 * `run` décrit la tâche affichée (voir utils/jobRun.js), plus `jobId` et
 * `cancelled` (vrai si l'échec vient d'une annulation demandée par l'utilisateur).
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
      setError(err.message);
      return null;
    }
  }, []);

  const follow = useCallback(
    (jobId) => {
      unfollow.current?.();
      setRun(newRun({ jobId }));
      unfollow.current = followJob(jobId, (event) => {
        setRun((current) => applyJobEvent(current, event));
        if (isFinal(event)) refresh();
      });
    },
    [refresh],
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
    await cancelJob(run.jobId);
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
