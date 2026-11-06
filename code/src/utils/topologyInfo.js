/**
 * Identité d'une topologie, enregistrée avec chaque dataset (voir backend/app/datasets.py,
 * topology_info) : un dataset n'est représentatif que du réseau sur lequel il a été généré.
 */

const isDevice = (n) => n.type === 'device';
const typeOf = (n) => n.data.deviceType;
const nameOf = (n) => n.data.properties.name;

/**
 * Empreinte d'une topologie : équipements (type, nom, adresses) et réseaux (sous-réseau).
 * Indépendante de la position des équipements sur le schéma ; deux topologies de même
 * empreinte décrivent le même réseau.
 */
export function topologySignature(nodes, edges) {
  const ips = new Map();
  edges.forEach((e) => e.data?.ip && ips.set(e.source, [...(ips.get(e.source) ?? []), e.data.ip]));
  return nodes
    .filter(isDevice)
    .map((n) =>
      typeOf(n) === 'switch'
        ? `switch:${nameOf(n)}:${n.data.properties.subnet ?? ''}`
        : `${typeOf(n)}:${nameOf(n)}:${(ips.get(n.id) ?? []).sort().join(',')}`,
    )
    .sort()
    .join('|');
}

/** Résumé lisible : « 5 équipements, 1 réseau ». */
export function topologySummary(nodes) {
  const devices = nodes.filter((n) => isDevice(n) && typeOf(n) !== 'switch').length;
  const networks = nodes.filter((n) => isDevice(n) && typeOf(n) === 'switch').length;
  return `${devices} équipement${devices > 1 ? 's' : ''}, ${networks} réseau${networks > 1 ? 'x' : ''}`;
}

/**
 * Description de la topologie affichée : { name, signature, summary }. `loaded` est
 * l'exemple chargé ({ name, signature }) : s'il a été modifié depuis, le nom le signale.
 */
export function describeTopology(nodes, edges, loaded) {
  const signature = topologySignature(nodes, edges);
  let name = 'Topologie personnalisée';
  if (loaded) name = loaded.signature === signature ? loaded.name : `${loaded.name} (modifiée)`;
  return { name, signature, summary: topologySummary(nodes) };
}
