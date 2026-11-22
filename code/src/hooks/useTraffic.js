import { useCallback, useEffect, useState } from 'react';
import * as api from '../services/topologyApi.js';

const EMPTY = { benign: [], scenarios: [], profiles: [], attacks: [], speeds: [] };

/**
 * État de la génération de trafic et actions associées (voir backend/app/traffic.py).
 *
 * Tant que `active` est vrai, l'activité (agents bénins en cours, scénarios et
 * leur état) est rafraîchie régulièrement. Les actions renvoient une promesse
 * et déclenchent un rafraîchissement ; les erreurs du serveur sont
 * laissées remonter à l'appelant, qui les affiche.
 */
export function useTraffic(active) {
  const [data, setData] = useState(EMPTY);
  const [error, setError] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const overview = await api.fetchTraffic();
      setData(overview);
      setError(null);
    } catch (err) {
      setError(err.message);
    }
  }, []);

  useEffect(() => {
    if (!active) {
      setData(EMPTY);
      return undefined;
    }
    refresh();
    const timer = setInterval(refresh, 2000);
    return () => clearInterval(timer);
  }, [active, refresh]);

  const act = useCallback(
    async (fn) => {
      try {
        return await fn();
      } finally {
        await refresh();
      }
    },
    [refresh],
  );

  const startBenign = useCallback(
    (node, profile, targets, dest, kinds) => act(() => api.startBenign(node, profile, targets, dest, kinds)),
    [act],
  );
  const stopBenign = useCallback((node) => act(() => api.stopBenign(node)), [act]);
  const runScenario = useCallback(
    (source, attack, target, speed) => act(() => api.runScenario(source, attack, target, speed)),
    [act],
  );
  const stopScenarios = useCallback((id) => act(() => api.stopScenarios(id)), [act]);
  const clearScenarios = useCallback(() => act(() => api.clearScenarios()), [act]);

  return {
    profiles: data.profiles,
    attacks: data.attacks,
    speeds: data.speeds,
    benign: data.benign,
    scenarios: data.scenarios,
    // vrai si du trafic bénin ou une attaque tourne en ce moment
    active: data.benign.length > 0 || data.scenarios.some((s) => s.status === 'running'),
    error,
    startBenign,
    stopBenign,
    runScenario,
    stopScenarios,
    clearScenarios,
  };
}
