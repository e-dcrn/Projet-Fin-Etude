/**
 * Chemins dans la topologie pour l'animation des paquets (voir useSimulation /
 * SimulationLayer).
 *
 * À partir des nœuds et des câbles, on calcule le CHEMIN réel entre deux
 * équipements (suite de liens traversant switches et routeurs), le centre d'un
 * nœud (point de passage des boules) et, pour l'ARP, les hôtes d'un même domaine
 * de broadcast.
 */

import { NODE_ICON_CENTER_Y } from '../config/deviceTypes.js';

/** Centre de l'icône d'un nœud (origine [0.5, 0] : position = milieu du bord haut). */
export function nodeCenter(node) {
  return { x: node.position.x, y: node.position.y + NODE_ICON_CENTER_Y };
}

/**
 * Plus court chemin (liste d'identifiants de nœuds) entre deux équipements, en
 * traversant les câbles (donc les switches et routeurs). null si non reliés.
 */
export function findPath(nodes, edges, srcId, dstId) {
  if (srcId === dstId) return null;
  const neighbors = new Map(nodes.map((n) => [n.id, []]));
  for (const e of edges) {
    neighbors.get(e.source)?.push(e.target);
    neighbors.get(e.target)?.push(e.source);
  }
  const parent = new Map([[srcId, null]]);
  const queue = [srcId];
  while (queue.length) {
    const id = queue.shift();
    if (id === dstId) {
      const path = [];
      for (let p = id; p != null; p = parent.get(p)) path.unshift(p);
      return path;
    }
    for (const next of neighbors.get(id) ?? []) {
      if (!parent.has(next)) {
        parent.set(next, id);
        queue.push(next);
      }
    }
  }
  return null;
}

/**
 * Hôtes du même domaine de broadcast que `sourceId` : atteignables sans traverser
 * de routeur (un routeur borne le domaine). Tout ce qui a une IP (PC, serveurs,
 * interfaces de routeur) est un destinataire possible ; les switches ne sont que
 * des relais. Sert à animer une requête ARP (broadcast) en une boule par hôte.
 */
export function broadcastHosts(nodes, edges, sourceId) {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const neighbors = new Map(nodes.map((n) => [n.id, []]));
  for (const e of edges) {
    neighbors.get(e.source)?.push(e.target);
    neighbors.get(e.target)?.push(e.source);
  }
  const typeOf = (id) => byId.get(id)?.data.deviceType;
  const seen = new Set([sourceId]);
  const queue = [sourceId];
  const hosts = [];
  while (queue.length) {
    const id = queue.shift();
    // On n'explore pas AU-DELÀ d'un routeur (frontière du domaine de broadcast).
    if (id !== sourceId && typeOf(id) === 'router') continue;
    for (const next of neighbors.get(id) ?? []) {
      if (seen.has(next)) continue;
      seen.add(next);
      if (typeOf(next) !== 'switch') hosts.push(next);
      queue.push(next);
    }
  }
  return hosts;
}
