import { useCallback, useEffect, useState } from 'react';
import * as api from '../services/topologyApi.js';

const IDLE = { running: false, stats: null, events: [] };

/**
 * Détection en direct par une Sonde IDS (voir backend/app/detection.py).
 * Tant que `active` est vrai (réseau allumé), l'état est rafraîchi toutes les
 * deux secondes : verdicts du modèle et bilan face à la vérité terrain.
 */
export function useDetection(active) {
  const [state, setState] = useState(IDLE);

  const refresh = useCallback(async () => {
    try {
      setState({ ...IDLE, ...(await api.fetchDetection()) });
    } catch {
      // moteur injoignable : l'état du réseau (useDeployment) l'affiche déjà
    }
  }, []);

  useEffect(() => {
    if (!active) {
      setState(IDLE);
      return undefined;
    }
    refresh();
    const timer = setInterval(refresh, 2000);
    return () => clearInterval(timer);
  }, [active, refresh]);

  const start = useCallback(async (ids, model) => {
    setState({ ...IDLE, ...(await api.startDetection(ids, model)) });
  }, []);

  const stop = useCallback(async () => {
    setState({ ...IDLE, ...(await api.stopDetection()) });
  }, []);

  const reset = useCallback(async () => {
    setState({ ...IDLE, ...(await api.resetDetection()) });
  }, []);

  return { ...state, start, stop, reset };
}
