/**
 * Les topologies disponibles, et ce que l'interface en déduit.
 *
 * Chaque topologie est un dossier de code/topologies/ :
 *   docker-compose.yml : ce que Docker lance (lu par le moteur, voir backend/app/lab.py) ;
 *   topology.json      : ce que l'interface dessine, lu ici.
 *
 * topology.json :
 *   {
 *     "name": "Petit LAN", "description": "…",
 *     "nodes": [{ "id": "pc-1", "type": "pc", "name": "PC-1", "x": 300, "y": 0 },
 *               { "id": "switch-1", "type": "switch", "name": "Switch-1", "subnet": "10.0.1.0/24", … }],
 *     "links": [{ "node": "pc-1", "switch": "switch-1", "ip": "10.0.1.11" }]   // un câble = une interface
 *   }
 *
 * Les identifiants (pc-1…) et les adresses IP sont les mêmes que dans le docker-compose.yml.
 */

const files = import.meta.glob('/topologies/*/topology.json', { eager: true, import: 'default' });

/** [{ id: "1-petit-lan", name, description, nodes, links }], dans l'ordre des noms de dossier. */
export const TOPOLOGIES = Object.entries(files)
  .map(([path, topology]) => ({ id: path.split('/')[2], ...topology }))
  .sort((a, b) => a.id.localeCompare(b.id));

/** Première adresse IP d'un équipement (un routeur en a une par réseau). */
export const ipOf = (topology, nodeId) => topology.links.find((l) => l.node === nodeId)?.ip ?? '';

/** Équipements d'un ou plusieurs types : devicesOf(topology, 'pc', 'server'). */
export const devicesOf = (topology, ...types) => topology.nodes.filter((n) => types.includes(n.type));

/** Adresse IP → nom de l'équipement (pour afficher « PC-1 → Serveur » au lieu des adresses). */
export const namesByIp = (topology) =>
  new Map(topology.links.map((l) => [l.ip, topology.nodes.find((n) => n.id === l.node)?.name ?? l.ip]));

/**
 * Destinations du trafic bénin depuis `sourceId` : toutes les autres machines
 * (sauf la sonde IDS). Un serveur offre HTTP, SSH et FTP ; les autres répondent au ping.
 */
export const benignTargets = (topology, sourceId) =>
  devicesOf(topology, 'pc', 'server', 'router')
    .filter((n) => n.id !== sourceId)
    .map((n) => ({ ip: ipOf(topology, n.id), server: n.type === 'server' }));

/**
 * Cibles possibles d'une attaque :
 *   needs = 'ip'     → chaque machine { label: "Serveur (10.0.1.10)", value: ip }
 *   needs = 'subnet' → chaque switch  { label: "Switch-1 (10.0.1.0/24)", value: sous-réseau }
 */
export function attackTargets(topology, needs) {
  if (needs === 'subnet') {
    return devicesOf(topology, 'switch').map((n) => ({ label: `${n.name} (${n.subnet})`, value: n.subnet }));
  }
  return devicesOf(topology, 'server', 'pc', 'router').map((n) => {
    const ip = ipOf(topology, n.id);
    return { label: `${n.name} (${ip})`, value: ip };
  });
}
