import { isNetworkType } from '../config/deviceTypes.js';

/**
 * Transforme l'état interne React Flow en un format JSON neutre,
 * indépendant de la bibliothèque d'affichage. C'est le contrat avec le
 * serveur (backend/app/models.py).
 *
 * {
 *   version: 2,
 *   generatedAt: "2026-10-10T09:00:00.000Z",
 *   nodes:    [{ id, type, name, position: {x, y}, config: {...} }],
 *   networks: [{ id, name, position: {x, y}, vlan, subnet }],    // les switches
 *   links:    [{ id, node, network, interface, port, ip, mask }] // nœud ↔ réseau (port : côté switch)
 * }
 *
 * `config` selon le type :
 *   pc     { gateway }
 *   server { gateway, services: [{ port, protocol, name }] }
 *   router { routes: [{ destination, gateway, interface }] }
 *   ids    { monitoredSegment }   (id du réseau surveillé)
 */
export const TOPOLOGY_FORMAT_VERSION = 2;

const CONFIG_KEYS = {
  pc: ['gateway'],
  server: ['gateway', 'services'],
  router: ['routes'],
  ids: ['monitoredSegment'],
};

const trim = (value) => (typeof value === 'string' ? value.trim() : value);

function roundPosition({ x, y }) {
  return { x: Math.round(x), y: Math.round(y) };
}

export function serializeTopology(nodes, edges) {
  const networks = nodes.filter((n) => isNetworkType(n.data.deviceType));
  const devices = nodes.filter((n) => !isNetworkType(n.data.deviceType));

  return {
    version: TOPOLOGY_FORMAT_VERSION,
    generatedAt: new Date().toISOString(),
    nodes: devices.map((node) => {
      const { deviceType, properties } = node.data;
      const config = {};
      for (const key of CONFIG_KEYS[deviceType] ?? []) config[key] = properties[key];
      if (config.gateway !== undefined) config.gateway = trim(config.gateway);
      if (config.services) {
        config.services = config.services.map((s) => ({ ...s, port: Number(s.port), name: trim(s.name) }));
      }
      if (config.routes) {
        config.routes = config.routes.map((r) => ({
          destination: trim(r.destination),
          gateway: trim(r.gateway),
          interface: r.interface,
        }));
      }
      return { id: node.id, type: deviceType, name: trim(properties.name), position: roundPosition(node.position), config };
    }),
    networks: networks.map((node) => {
      const vlan = String(node.data.properties.vlan ?? '').trim();
      return {
        id: node.id,
        name: trim(node.data.properties.name),
        position: roundPosition(node.position),
        vlan: vlan === '' ? null : Number(vlan),
        subnet: trim(node.data.properties.subnet ?? ''),
      };
    }),
    links: edges.map((edge) => ({
      id: edge.id,
      node: edge.source,
      network: edge.target,
      interface: edge.data.interface,
      port: edge.data.port ?? '',
      ip: trim(edge.data.ip),
      mask: trim(edge.data.mask),
    })),
  };
}
