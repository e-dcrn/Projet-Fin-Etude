import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import * as api from '../services/topologyApi.js';

const EMPTY = { benign: [], scenarios: [], profiles: [], attacks: [] };

/**
 * État de la génération de trafic et actions associées (voir backend/app/traffic.py).
 *
 * Tant que `active` est vrai, l'activité (agents bénins en cours, scénarios et
 * leur état) est rafraîchie régulièrement. Les actions renvoient une promesse
 * et déclenchent un rafraîchissement ; les erreurs du serveur (ApiError) sont
 * laissées remonter à l'appelant, qui les affiche.
 */
export function useTraffic(active) {
  const [data, setData] = useState(EMPTY);
  const [error, setError] = useState(null);
  const timer = useRef(null);

  const refresh = useCallback(async () => {
    try {
      const overview = await api.fetchTraffic();
      setData(overview);
      setError(null);
    } catch (err) {
      setError(err.messages ? err.messages.join('\n') : String(err));
    }
  }, []);

  useEffect(() => {
    if (!active) {
      setData(EMPTY);
      return undefined;
    }
    refresh();
    timer.current = setInterval(refresh, 2000);
    return () => clearInterval(timer.current);
  }, [active, refresh]);

  const act = useCallback(
    async (fn) => {
      try {
        const result = await fn();
        await refresh();
        return result;
      } catch (err) {
        await refresh();
        throw err;
      }
    },
    [refresh],
  );

  const startBenign = useCallback(
    (node, profile, targets, dest, kinds) => act(() => api.startBenign(node, profile, targets, dest, kinds)),
    [act],
  );
  const stopBenign = useCallback((node) => act(() => api.stopBenign(node)), [act]);
  const runScenario = useCallback((source, attack, target) => act(() => api.runScenario(source, attack, target)), [act]);
  const clearScenarios = useCallback(() => act(() => api.clearScenarios()), [act]);

  // Équipements où un agent bénin tourne ; sources de scénarios encore en cours
  const benignNodes = useMemo(() => new Set(data.benign.map((b) => b.node)), [data.benign]);
  const scenarioSources = useMemo(
    () => new Set(data.scenarios.filter((s) => s.status === 'running').map((s) => s.source)),
    [data.scenarios],
  );

  return {
    profiles: data.profiles,
    attacks: data.attacks,
    benign: data.benign,
    scenarios: data.scenarios,
    benignNodes,
    scenarioSources,
    error,
    startBenign,
    stopBenign,
    runScenario,
    clearScenarios,
    fetchLogs: api.fetchScenarioLogs,
  };
}
