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
 * Le panneau peut être divisé en deux volets côte à côte (pane 0 : gauche,
 * pane 1 : droite), chacun avec ses onglets et son onglet affiché. Il est
 * divisé dès que le volet de droite a un onglet ; vidé, il disparaît.
 * Ouvrir une capture alors qu'un terminal est seul affiché divise le panneau :
 * on voit le trafic à droite de la commande qui le produit.
 *
 * `requests[key]` est incrémenté à chaque demande d'ouverture : une session
 * terminée redémarre quand on redemande la même cible.
 */
const INITIAL = { tabs: [], selected: [null, null], focused: 0 }; // tabs : [{ key, kind, target, pane }]

/** Onglet affiché dans chaque volet : le dernier sélectionné, à défaut le dernier ouvert. */
function activeKeysOf({ tabs, selected }) {
  return [0, 1].map((pane) => {
    const inPane = tabs.filter((t) => t.pane === pane);
    return inPane.some((t) => t.key === selected[pane]) ? selected[pane] : inPane.at(-1)?.key ?? null;
  });
}

/** Volet gauche vidé : le volet droit prend sa place. */
function normalize(state) {
  if (state.tabs.some((t) => t.pane === 0) || !state.tabs.length) return state;
  return { tabs: state.tabs.map((t) => ({ ...t, pane: 0 })), selected: [state.selected[1], null], focused: 0 };
}

/** Volet d'un nouvel onglet. */
function paneFor(state, kind) {
  const kindOf = (key) => state.tabs.find((t) => t.key === key)?.kind;
  const active = activeKeysOf(state);
  if (!state.tabs.some((t) => t.pane === 1)) {
    return kind === 'capture' && kindOf(active[0]) === 'terminal' ? 1 : 0;
  }
  // Panneau divisé : à côté des onglets du même genre (terminaux à gauche, captures à droite…)
  const sameKind = [0, 1].find((pane) => kindOf(active[pane]) === kind);
  return sameKind ?? state.focused;
}

const selectIn = (state, tab) => {
  const selected = [...state.selected];
  selected[tab.pane] = tab.key;
  return { ...state, selected, focused: tab.pane };
};

export function useDock() {
  const [state, setState] = useState(INITIAL);
  const [requests, setRequests] = useState({});

  const open = useCallback((kind, target) => {
    const key = `${kind}:${target}`;
    setState((current) => {
      const existing = current.tabs.find((t) => t.key === key);
      if (existing) return selectIn(current, existing);
      const tab = { key, kind, target, pane: paneFor(current, kind) };
      return selectIn({ ...current, tabs: [...current.tabs, tab] }, tab);
    });
    setRequests((current) => ({ ...current, [key]: (current[key] ?? 0) + 1 }));
  }, []);

  const close = useCallback(
    (key) => setState((current) => normalize({ ...current, tabs: current.tabs.filter((t) => t.key !== key) })),
    [],
  );

  const select = useCallback(
    (key) =>
      setState((current) => {
        const tab = current.tabs.find((t) => t.key === key);
        return tab ? selectIn(current, tab) : current;
      }),
    [],
  );

  /** Place un onglet dans le volet donné (par défaut : l'autre volet) et l'y affiche. */
  const move = useCallback(
    (key, pane) =>
      setState((current) => {
        const tab = current.tabs.find((t) => t.key === key);
        if (!tab) return current;
        const moved = { ...tab, pane: pane ?? 1 - tab.pane };
        if (moved.pane === tab.pane) return selectIn(current, tab);
        const next = { ...current, tabs: current.tabs.map((t) => (t.key === key ? moved : t)) };
        // Le volet quitté pourrait être vide : normalize, puis on retrouve l'onglet à sa place finale
        const normalized = normalize(next);
        return selectIn(normalized, normalized.tabs.find((t) => t.key === key));
      }),
    [],
  );

  /** Ferme les onglets dont l'équipement (terminal) ou le câble (capture) a été supprimé. */
  const keepOnly = useCallback(
    (nodeIds, edgeIds) =>
      setState((current) => {
        const kept = current.tabs.filter((t) => (t.kind === 'terminal' ? nodeIds : edgeIds).has(t.target));
        return kept.length === current.tabs.length ? current : normalize({ ...current, tabs: kept });
      }),
    [],
  );

  return {
    tabs: state.tabs,
    activeKeys: activeKeysOf(state),
    split: state.tabs.some((t) => t.pane === 1),
    focusedPane: state.focused,
    requests,
    open,
    close,
    select,
    move,
    keepOnly,
  };
}
