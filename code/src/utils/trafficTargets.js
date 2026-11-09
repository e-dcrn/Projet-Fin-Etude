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

/** Type d'un service (même correspondance nom/port que traffic_agent.service_kind). */
export function serviceKind(service) {
  const name = (service.name || '').trim().toLowerCase();
  const port = Number(service.port) || 0;
  if (['http', 'https', 'ssh', 'ftp', 'telnet', 'smtp', 'dns', 'mysql'].includes(name)) return name;
  if (name.startsWith('https') || [443, 8443].includes(port)) return 'https';
  if (name.startsWith('http') || [80, 8080].includes(port)) return 'http';
  const byPort = { 22: 'ssh', 21: 'ftp', 23: 'telnet', 25: 'smtp', 53: 'dns', 3306: 'mysql' };
  return name ? null : (byPort[port] ?? null);
}

// Types de trafic bénin, dans l'ordre d'affichage (identifiants de traffic_agent.py).
const BENIGN_KIND_LABELS = [
  ['icmp', 'Ping (ICMP)'],
  ['http', 'HTTP'],
  ['https', 'HTTPS'],
  ['ssh', 'SSH'],
  ['ftp', 'FTP'],
  ['smtp', 'SMTP'],
  ['mysql', 'MySQL'],
  ['telnet', 'Telnet'],
  ['dns', 'DNS'],
  ['tcp', 'Autres ports TCP'],
];

/**
 * Types de trafic bénin réellement possibles vers `destIds` : le ping dès qu'il y a
 * un destinataire, puis un type par service ouvert sur l'un d'eux (les services
 * UDP autres que le DNS ne sont pas joués par l'agent). Chaque type porte la
 * liste des équipements qui l'offrent : { id, label, hosts: [nom…] }.
 */
export function availableBenignKinds(nodes, edges, destIds) {
  const wanted = new Set(destIds);
  const hosts = new Map();
  const add = (kind, name) => {
    if (!hosts.has(kind)) hosts.set(kind, new Set());
    hosts.get(kind).add(name);
  };
  for (const node of nodes) {
    if (!wanted.has(node.id) || !deviceIp(edges, node.id)) continue;
    add('icmp', nameOf(node));
    for (const svc of servicesOf(node)) {
      const kind = serviceKind(svc) ?? 'tcp';
      if (svc.protocol === 'tcp' || kind === 'dns') add(kind, nameOf(node));
    }
  }
  return BENIGN_KIND_LABELS.filter(([id]) => hosts.has(id))
    .map(([id, label]) => ({ id, label, hosts: [...hosts.get(id)] }));
}
