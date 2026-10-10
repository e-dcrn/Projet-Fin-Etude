import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError, fetchLabStatus, followDeployment, startDeployment, stopLab } from '../services/topologyApi.js';
import { hasErrors } from '../utils/validators.js';

/**
 * Cycle de vie de l'instanciation du réseau.
 *
 * `run` décrit le déploiement affiché dans la boîte de dialogue :
 *   phase    'review'  : problèmes détectés, en attente de confirmation
 *            'running' : création en cours (step / total / label)
 *            'done'    : réseau opérationnel
 *            'failed'  : échec (errors : liste de messages)
 *   steps    étapes déjà commencées (la dernière est l'étape en cours)
 *   warnings avertissements non bloquants remontés par le serveur
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
            return { ...current, phase: 'done', step: current.total };
          case 'error':
            return { ...current, phase: 'failed', errors: [event.message] };
          default:
            return current;
        }
      });
      if (event.type === 'done' || event.type === 'error') refreshLab();
    },
    [refreshLab],
  );

  /** Lance la création du réseau à partir d'une topologie sérialisée. */
  const deploy = useCallback(
    async (topology) => {
      setRun({ phase: 'running', step: 0, total: 0, steps: [], warnings: [], errors: [], deviceCount: topology.nodes.length });
      try {
        const { id } = await startDeployment(topology);
        unfollow.current = followDeployment(id, handleEvent);
      } catch (err) {
        const errors = err instanceof ApiError ? err.messages : [String(err)];
        setRun((current) => ({ ...current, phase: 'failed', errors }));
        refreshLab();
      }
    },
    [handleEvent, refreshLab],
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
