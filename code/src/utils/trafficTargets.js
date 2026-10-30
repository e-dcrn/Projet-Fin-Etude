/**
 * Dérive, à partir de la topologie (nœuds + câbles), les informations dont la
 * génération de trafic a besoin : destinataires possibles et cibles du trafic
 * bénin, et sources / cibles des scénarios d'audit. Le serveur ne connaît ni la
 * topologie ni les IP : c'est l'interface qui les lui fournit (comme un fichier
 * de scénario ConCap).
 */

/** Première adresse IP d'un équipement (une interface peut en avoir plusieurs). */
export function deviceIp(edges, nodeId) {
  const link = edges.find((e) => e.source === nodeId && e.data.ip);
  return link?.data.ip ?? '';
}

const isDevice = (n) => n.type === 'device';
const typeOf = (n) => n.data.deviceType;
const nameOf = (n) => n.data.properties.name;
const REACHABLE = ['pc', 'server', 'router', 'ids'];

/** Services ouverts d'un serveur, normalisés pour le serveur (port numérique). */
function servicesOf(node) {
  return (node.data.properties.services ?? [])
    .map((s) => ({ port: Number(s.port), protocol: s.protocol || 'tcp', name: (s.name || '').trim() }))
    .filter((s) => s.port);
}

const withIp = (nodes, edges) => (node) => ({
  ip: deviceIp(edges, node.id),
  name: nameOf(node),
  services: servicesOf(node),
});

/** Équipements joignables depuis `sourceId` (tout sauf lui-même, dotés d'une IP). */
function reachableNodes(nodes, edges, sourceId) {
  return nodes.filter(
    (n) => isDevice(n) && REACHABLE.includes(typeOf(n)) && n.id !== sourceId && deviceIp(edges, n.id),
  );
}

/**
 * Tous les équipements qui peuvent être DESTINATAIRES de trafic bénin (dotés
 * d'une IP), pour les proposer en cases à cocher : { id, name, type, ip }.
 */
export function reachableDevices(nodes, edges) {
  return nodes
    .filter((n) => isDevice(n) && REACHABLE.includes(typeOf(n)) && deviceIp(edges, n.id))
    .map((n) => ({ id: n.id, name: nameOf(n), type: typeOf(n), ip: deviceIp(edges, n.id) }));
}

/**
 * Cibles concrètes (IP + services) depuis `sourceId` vers un ENSEMBLE d'ids de
 * destinataires (la source est exclue). Utilisé quand on coche plusieurs cibles.
 */
export function benignTargetsForDests(nodes, edges, sourceId, destIds) {
  const wanted = new Set(destIds);
  const make = withIp(nodes, edges);
  return reachableNodes(nodes, edges, sourceId)
    .filter((n) => wanted.has(n.id))
    .map(make)
    .filter((t) => t.ip);
}

/** Équipements pouvant être source de trafic (un PC ou un serveur allumé). */
export function trafficSources(nodes, onlineIds) {
  return nodes
    .filter((n) => isDevice(n) && ['pc', 'server'].includes(typeOf(n)) && onlineIds.has(n.id))
    .map((n) => ({ id: n.id, name: nameOf(n), type: typeOf(n) }));
}

/**
 * Cibles possibles d'un scénario :
 *   ip     → chaque équipement doté d'une adresse { label, value: ip }
 *   subnet → chaque switch doté d'un sous-réseau { label, value: cidr }
 */
export function scenarioTargets(nodes, edges, needs) {
  if (needs === 'subnet') {
    return nodes
      .filter((n) => typeOf(n) === 'switch' && n.data.properties.subnet)
      .map((n) => ({ label: `${nameOf(n)} (${n.data.properties.subnet})`, value: n.data.properties.subnet }));
  }
  return nodes
    .filter((n) => isDevice(n) && REACHABLE.includes(typeOf(n)))
    .map((n) => ({ node: n.id, label: nameOf(n), ip: deviceIp(edges, n.id) }))
    .filter((t) => t.ip)
    .map((t) => ({ label: `${t.label} (${t.ip})`, value: t.ip }));
}
