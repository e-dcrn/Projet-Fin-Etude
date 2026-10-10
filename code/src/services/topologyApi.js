/**
 * Couche d'accès au backend.
 *
 * Pour l'instant aucun backend n'existe : la topologie est simplement affichée
 * dans la console. Pour brancher l'API plus tard, il suffira de remplacer le
 * corps de submitTopology par un appel HTTP, par exemple :
 *
 *   const res = await fetch(`${API_BASE_URL}/topologies`, {
 *     method: 'POST',
 *     headers: { 'Content-Type': 'application/json' },
 *     body: JSON.stringify(topology),
 *   });
 *   if (!res.ok) throw new Error(`Erreur backend : ${res.status}`);
 *   return res.json();
 *
 * Les composants appelants n'auront pas à changer (la fonction est déjà asynchrone).
 */

// URL du futur backend, configurable via un fichier .env (VITE_API_BASE_URL=...)
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000/api';

/**
 * Soumet une topologie sérialisée.
 * @param {object} topology  objet produit par serializeTopology()
 * @param {string[]} warnings avertissements produits par validateTopology()
 */
export async function submitTopology(topology, warnings = []) {
  console.group(
    `%c[IDS Lab] Topologie validée : ${topology.nodes.length} équipement(s), ${topology.links.length} lien(s)`,
    'color:#2563eb;font-weight:bold',
  );
  if (warnings.length) console.warn('Avertissements :\n- ' + warnings.join('\n- '));
  console.log('Objet :', topology);
  console.log('JSON :\n' + JSON.stringify(topology, null, 2));
  console.groupEnd();

  return { ok: true };
}
