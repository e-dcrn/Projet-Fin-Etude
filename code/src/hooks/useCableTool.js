import { useCallback, useEffect, useState } from 'react';

/**
 * Outil « câble », à la manière de Packet Tracer :
 *   1. on active le mode câblage ;
 *   2. on clique sur un premier équipement (il est mis en surbrillance) ;
 *   3. on clique sur un second équipement → le lien est créé.
 *
 * Le mode reste actif pour enchaîner plusieurs câbles.
 * Échap annule le câble en cours, puis quitte le mode.
 *
 * @param {(sourceId: string, targetId: string) => string | null} connectDevices
 *        retourne null si le câble est créé, sinon le motif du refus
 * @param {(message: string) => void} onRefused affiche le motif du refus
 */
export function useCableTool(connectDevices, onRefused) {
  const [isActive, setIsActive] = useState(false);
  const [sourceId, setSourceId] = useState(null);

  const toggle = useCallback(() => {
    setIsActive((active) => !active);
    setSourceId(null);
  }, []);

  const cancel = useCallback(() => setSourceId(null), []);

  /** À appeler lors d'un clic sur un nœud. */
  const handleNodeClick = useCallback(
    (nodeId) => {
      if (!isActive) return;

      if (!sourceId) {
        setSourceId(nodeId); // premier clic : on mémorise l'extrémité de départ
        return;
      }
      if (sourceId === nodeId) {
        setSourceId(null); // re-clic sur le même nœud : annulation
        return;
      }
      const refusal = connectDevices(sourceId, nodeId); // second clic : création du lien
      if (refusal) onRefused?.(refusal);
      setSourceId(null);
    },
    [isActive, sourceId, connectDevices, onRefused],
  );

  // Raccourci clavier Échap
  useEffect(() => {
    if (!isActive) return undefined;
    const onKeyDown = (event) => {
      if (event.key !== 'Escape') return;
      if (sourceId) setSourceId(null);
      else setIsActive(false);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [isActive, sourceId]);

  return { isActive, sourceId, toggle, cancel, handleNodeClick };
}
