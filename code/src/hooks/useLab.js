import { useEffect, useState } from 'react';
import * as api from '../services/topologyApi.js';

/**
 * État du réseau simulé (voir backend/app/lab.py) et commandes démarrer / arrêter.
 *
 *   status     'unknown' | 'offline' (moteur injoignable) | 'stopped' | 'running'
 *   topology   identifiant de la topologie en cours (« 1-petit-lan »), ou null
 *   onlineIds  identifiants des équipements allumés
 *   busy       vrai pendant un démarrage ou un arrêt (docker compose up / down)
 *   error      message du dernier échec
 */
export function useLab() {
  const [lab, setLab] = useState({ status: 'unknown', topology: null, onlineIds: new Set() });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  // Réponse du serveur ({ running, topology, devices }) → état affiché
  const show = (status) =>
    setLab({
      status: status.running ? 'running' : 'stopped',
      topology: status.topology,
      onlineIds: new Set(status.devices.filter((d) => d.running).map((d) => d.id)),
    });

  useEffect(() => {
    api.fetchLabStatus().then(show).catch(() => setLab({ status: 'offline', topology: null, onlineIds: new Set() }));
  }, []);

  /** Lance `call` (démarrage ou arrêt) et affiche le nouvel état du réseau. */
  const run = async (call) => {
    setBusy(true);
    setError(null);
    try {
      show(await call());
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return {
    ...lab,
    busy,
    error,
    start: (topologyId) => run(() => api.startLab(topologyId)),
    stop: () => run(api.stopLab),
  };
}
