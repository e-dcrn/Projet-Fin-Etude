import { useCallback, useState } from 'react';

/**
 * Action déclenchée par un bouton (appel au serveur) : `busy` est vrai pendant
 * l'appel (pour désactiver les boutons), et `error` reçoit le message d'échec à
 * afficher. `act(fn)` exécute la fonction asynchrone `fn` dans ce cadre.
 */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const act = useCallback(async (fn) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }, []);

  return { busy, error, act };
}

/** Copie de l'ensemble `set` où `id` a été ajouté s'il était absent, retiré sinon (cases à cocher). */
export function toggled(set, id) {
  const next = new Set(set);
  if (next.has(id)) next.delete(id);
  else next.add(id);
  return next;
}
