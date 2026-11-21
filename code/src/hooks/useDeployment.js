import { useCallback, useEffect, useRef, useState } from 'react';
import { fetchLabStatus, followJob, startDeployment, stopLab } from '../services/topologyApi.js';
import { applyJobState, isFinal, newRun } from '../utils/jobRun.js';
import { hasErrors } from '../utils/validators.js';

/**
 * Cycle de vie de l'instanciation du réseau.
 *
 * `run` décrit le déploiement affiché dans la boîte de dialogue :
 *   phase 'review' : problèmes détectés, en attente de confirmation (topology, issues, blocked) ;
 *   sinon, suivi de la tâche de fond (voir utils/jobRun.js), plus deviceCount.
 *
 * `lab` décrit l'état du réseau instancié :
 *   status   'unknown' | 'offline' (moteur injoignable) | 'stopped' | 'running'
 *   onlineIds  identifiants des équipements allumés
 */
export function useDeployment() {
  const [run, setRun] = useState(null);
  const [lab, setLab] = useState({ status: 'unknown', onlineIds: new Set() });
  const unfollow = useRef(null);

  const refreshLab = useCallback(async () => {
    try {
      const status = await fetchLabStatus();
      setLab({
        status: status.running ? 'running' : 'stopped',
        onlineIds: new Set([...status.devices.filter((d) => d.running).map((d) => d.id), ...status.networks]),
      });
    } catch {
      setLab({ status: 'offline', onlineIds: new Set() });
    }
  }, []);

  useEffect(() => {
    refreshLab();
    return () => unfollow.current?.();
  }, [refreshLab]);

  /** Lance la création du réseau à partir d'une topologie sérialisée. */
  const deploy = useCallback(
    async (topology) => {
      setRun(newRun({ deviceCount: topology.nodes.length }));
      try {
        const { id } = await startDeployment(topology);
        unfollow.current = followJob(id, (job) => {
          setRun((current) => applyJobState(current, job));
          if (isFinal(job)) refreshLab();
        });
      } catch (err) {
        setRun((current) => ({ ...current, phase: 'failed', errors: err.messages ?? [String(err)] }));
        refreshLab();
      }
    },
    [refreshLab],
  );

  /**
   * Point d'entrée du bouton « Valider la topologie » : sans problème détecté,
   * la création démarre directement ; sinon on affiche d'abord le bilan.
   */
  const validate = useCallback(
    (topology, issues) => {
      if (issues.length === 0) deploy(topology);
      else setRun({ phase: 'review', topology, issues, blocked: hasErrors(issues) });
    },
    [deploy],
  );

  const stop = useCallback(async () => {
    try {
      await stopLab();
    } finally {
      await refreshLab();
    }
  }, [refreshLab]);

  const dismiss = useCallback(() => {
    unfollow.current?.();
    unfollow.current = null;
    setRun(null);
  }, []);

  return { run, lab, validate, deploy, stop, dismiss };
}
