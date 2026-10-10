import { parseSubnet } from './ipv4.js';

/**
 * Lectures dérivées de l'état React Flow (nœuds + câbles), partagées par
 * le canvas et le panneau de propriétés.
 */

export const nodeName = (nodes, id) => nodes.find((n) => n.id === id)?.data.properties.name ?? id;

/** Câbles (interfaces) d'un équipement, triés eth0, eth1, … eth10. */
export function deviceLinks(edges, deviceId) {
  return edges
    .filter((e) => e.source === deviceId)
    .sort((a, b) => a.data.interface.localeCompare(b.data.interface, undefined, { numeric: true }));
}

/** Câbles arrivant sur un switch. */
export const networkLinks = (edges, networkId) => edges.filter((e) => e.target === networkId);

/**
 * Réseau d'un switch (propriété `subnet`, attribuée par l'IPAM et modifiable).
 * Retourne l'objet de parseSubnet (avec `cidr`), ou null s'il est invalide.
 */
export const networkSubnet = (nodes, networkId) => parseSubnet(nodes.find((n) => n.id === networkId)?.data.properties.subnet);
