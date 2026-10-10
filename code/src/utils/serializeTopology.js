/**
 * Transforme l'état interne React Flow en un format JSON neutre,
 * indépendant de la bibliothèque d'affichage.
 *
 * C'est ce format qui sera envoyé au backend pour instancier
 * les containers Docker et les liens réseau correspondants.
 *
 * {
 *   version: 1,
 *   generatedAt: "2026-10-10T09:00:00.000Z",
 *   nodes: [{ id, type, position: {x, y}, properties: { name, ip } }],
 *   links: [{ id, source, target }]
 * }
 */
export const TOPOLOGY_FORMAT_VERSION = 1;

export function serializeTopology(nodes, edges) {
  return {
    version: TOPOLOGY_FORMAT_VERSION,
    generatedAt: new Date().toISOString(),
    nodes: nodes.map((node) => ({
      id: node.id,
      type: node.data.deviceType,
      position: {
        x: Math.round(node.position.x),
        y: Math.round(node.position.y),
      },
      properties: { ...node.data.properties },
    })),
    links: edges.map((edge) => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
    })),
  };
}
