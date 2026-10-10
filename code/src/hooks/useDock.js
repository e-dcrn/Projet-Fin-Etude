import { useCallback, useState } from 'react';

/**
 * Onglets du panneau du bas (voir Dock.jsx) :
 *   - terminal : shell d'un équipement (target = id du nœud) ;
 *   - capture  : trafic d'un lien (target = id du câble).
 *
 * Un onglet par cible : rouvrir une cible déjà ouverte affiche son onglet.
 * Chaque onglet garde sa propre session : changer d'onglet ne la ferme pas,
 * fermer l'onglet l'arrête (shell et tout ce qu'il lançait, ou capture).
 *
 * `requests[key]` est incrémenté à chaque demande d'ouverture : une session
 * terminée redémarre quand on redemande la même cible.
 */
export function useDock() {
  const [tabs, setTabs] = useState([]); // [{ key, kind, target }]
  const [selectedKey, setSelectedKey] = useState(null);
  const [requests, setRequests] = useState({});

  const open = useCallback((kind, target) => {
    const key = `${kind}:${target}`;
    setTabs((current) => (current.some((t) => t.key === key) ? current : [...current, { key, kind, target }]));
    setSelectedKey(key);
    setRequests((current) => ({ ...current, [key]: (current[key] ?? 0) + 1 }));
  }, []);

  const close = useCallback((key) => setTabs((current) => current.filter((t) => t.key !== key)), []);

  /** Ferme les onglets dont l'équipement (terminal) ou le câble (capture) a été supprimé. */
  const keepOnly = useCallback(
    (nodeIds, edgeIds) =>
      setTabs((current) => {
        const kept = current.filter((t) => (t.kind === 'terminal' ? nodeIds : edgeIds).has(t.target));
        return kept.length === current.length ? current : kept;
      }),
    [],
  );

  // Onglet affiché : le dernier sélectionné, à défaut le dernier ouvert
  const activeKey = tabs.some((t) => t.key === selectedKey) ? selectedKey : tabs.at(-1)?.key ?? null;

  return { tabs, activeKey, requests, open, close, select: setSelectedKey, keepOnly };
}
