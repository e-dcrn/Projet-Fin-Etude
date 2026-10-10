import { DEVICE_TYPES } from '../config/deviceTypes.js';
import { planIpam } from './ipam.js';
import { TOPOLOGY_FORMAT_VERSION } from './serializeTopology.js';

/**
 * Inverse de serializeTopology : format JSON neutre → état interne React Flow.
 * Lève une Error (message destiné à l'utilisateur) si le format n'est pas reconnu.
 *
 * Le format ne mémorise pas le mode automatique / manuel des champs gérés par
 * l'IPAM (adresses des interfaces, passerelles). Règle appliquée : un champ que
 * l'IPAM aurait laissé tel quel reste automatique ; un champ qu'il aurait modifié
 * (adresse choisie à la main, passerelle vers un autre routeur…) passe en manuel.
 * La topologie chargée est donc toujours identique au fichier, et reste gérée
 * par l'IPAM partout où c'est possible.
 */
export function deserializeTopology(topology) {
  if (topology?.version !== TOPOLOGY_FORMAT_VERSION) {
    throw new Error(`Format de topologie non reconnu (version ${topology?.version ?? '?'}, ${TOPOLOGY_FORMAT_VERSION} attendue).`);
  }

  const devices = (topology.nodes ?? []).map((node) => {
    const definition = DEVICE_TYPES[node.type];
    if (!definition || definition.isNetwork) throw new Error(`Type d'équipement inconnu : ${node.type}`);
    const properties = { ...definition.defaultProperties(), ...node.config, name: node.name };
    return toFlowNode(node, node.type, properties);
  });

  const networks = (topology.networks ?? []).map((network) =>
    toFlowNode(network, 'switch', {
      ...DEVICE_TYPES.switch.defaultProperties(),
      name: network.name,
      vlan: network.vlan == null ? '' : String(network.vlan),
      subnet: network.subnet ?? '',
    }),
  );

  const nodes = [...devices, ...networks];
  const edges = (topology.links ?? []).map((link) => ({
    id: link.id,
    source: link.node,
    target: link.network,
    data: { interface: link.interface, port: link.port ?? '', ip: link.ip ?? '', mask: link.mask ?? '', auto: true },
  }));

  // Tout ce que l'IPAM corrigerait est une saisie manuelle : on le fige
  const { links, gateways } = planIpam(nodes, edges);
  return {
    nodes: nodes.map((n) =>
      gateways.has(n.id) ? { ...n, data: { ...n.data, properties: { ...n.data.properties, gatewayAuto: false } } } : n,
    ),
    edges: edges.map((e) => (links.has(e.id) ? { ...e, data: { ...e.data, auto: false } } : e)),
  };
}

function toFlowNode(item, deviceType, properties) {
  const { x = 0, y = 0 } = item.position ?? {};
  return { id: item.id, type: 'device', position: { x, y }, data: { deviceType, properties } };
}
