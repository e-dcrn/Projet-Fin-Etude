import { DEVICE_TYPES } from '../config/deviceTypes.js';
import {
  MAX_PREFIX,
  formatIp,
  isValidIp,
  parseCidr,
  parseInterface,
  parseIp,
  parsePrefix,
  parseSubnet,
  subnetContains,
  subnetsOverlap,
} from './ipv4.js';

/* ==========================================================================
   Contrôles d'un champ isolé (affichés sous le champ, dans le panneau)
   ========================================================================== */

export const INTERFACE_NAME_REGEX = /^[a-z][a-z0-9]{0,14}$/;

export function ipFieldError(value, { required = false } = {}) {
  if (!value?.trim()) return required ? 'Adresse IP obligatoire' : null;
  return isValidIp(value) ? null : 'Format attendu : 192.168.1.10';
}

export function maskFieldError(value, { required = false } = {}) {
  if (!value?.trim()) return required ? 'Masque obligatoire' : null;
  const prefix = parsePrefix(value);
  if (prefix === null) return 'Format attendu : 255.255.255.0 ou /24';
  if (prefix > MAX_PREFIX) return `Masque trop restrictif (/${MAX_PREFIX} maximum)`;
  return null;
}

export function cidrFieldError(value) {
  if (!value?.trim()) return 'Destination obligatoire';
  return parseCidr(value) ? null : 'Format attendu : 10.0.2.0/24 (0.0.0.0/0 : route par défaut)';
}

/** Réseau d'un switch : adresse de réseau + masque (« 10.0.1.0/24 »). */
export function subnetFieldError(value) {
  if (!value?.trim()) return 'Réseau obligatoire';
  const parsed = parseCidr(value);
  if (!parsed) return 'Format attendu : 10.0.1.0/24';
  if (parsed.prefix > MAX_PREFIX) return `Réseau trop petit (/${MAX_PREFIX} maximum)`;
  if (parsed.hostBitsSet) return `Adresse de réseau attendue : ${formatIp(parsed.network)}/${parsed.prefix}`;
  return null;
}

export function portFieldError(value) {
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? null : 'Port entre 1 et 65535';
}

export function vlanFieldError(value) {
  if (String(value ?? '').trim() === '') return null;
  const vlan = Number(value);
  return Number.isInteger(vlan) && vlan >= 1 && vlan <= 4094 ? null : 'VLAN entre 1 et 4094';
}

export function interfaceNameError(value) {
  return INTERFACE_NAME_REGEX.test(value ?? '') ? null : 'Nom attendu : eth0, eth1…';
}

/* ==========================================================================
   Contrôles de cohérence de la topologie complète
   ========================================================================== */

/**
 * Analyse une topologie sérialisée (voir serializeTopology.js) et retourne
 * la liste des problèmes : { level: 'error' | 'warning', message, refs }.
 *
 * - error   : le réseau ne peut pas être créé tel quel (bloque le déploiement) ;
 * - warning : le réseau peut être créé mais risque de ne pas fonctionner comme prévu.
 * - refs    : identifiants des équipements / câbles concernés (pour le panneau).
 *
 * Les mêmes erreurs sont vérifiées par le serveur, qui fait foi.
 */
export function validateTopology(topology) {
  const issues = [];
  const error = (message, ...refs) => issues.push({ level: 'error', message, refs });
  const warning = (message, ...refs) => issues.push({ level: 'warning', message, refs });

  const items = [...topology.nodes, ...topology.networks];
  const nodesById = new Map(topology.nodes.map((n) => [n.id, n]));
  const networksById = new Map(topology.networks.map((n) => [n.id, n]));
  const nameOf = (id) => nodesById.get(id)?.name ?? networksById.get(id)?.name ?? id;

  // --- Noms -----------------------------------------------------------------
  const nameOwners = new Map();
  for (const item of items) {
    if (!item.name) error(`L'équipement ${item.id} n'a pas de nom.`, item.id);
    else if (nameOwners.has(item.name)) error(`Nom « ${item.name} » utilisé plusieurs fois.`, item.id, nameOwners.get(item.name));
    else nameOwners.set(item.name, item.id);
  }

  // --- Interfaces (portées par les câbles) -----------------------------------
  const linksByNode = new Map();
  const linksByNetwork = new Map();
  const addressOwners = new Map(); // ip (entier) → nom
  const parsedLinks = new Map(); // id du câble → interface parsée

  for (const link of topology.links) {
    const node = nodesById.get(link.node);
    if (!node || !networksById.has(link.network)) continue;
    linksByNode.set(node.id, [...(linksByNode.get(node.id) ?? []), link]);
    linksByNetwork.set(link.network, [...(linksByNetwork.get(link.network) ?? []), link]);
    const where = `${node.name} (${link.interface})`;

    if (interfaceNameError(link.interface)) error(`${node.name} : nom d'interface invalide « ${link.interface} ».`, node.id, link.id);
    else if (linksByNode.get(node.id).filter((l) => l.interface === link.interface).length === 2) {
      error(`${node.name} : l'interface ${link.interface} est utilisée deux fois.`, node.id);
    }

    if (!link.ip) {
      if (node.type !== 'ids') error(`${where} : adresse IP manquante.`, node.id, link.id);
      continue;
    }
    if (ipFieldError(link.ip)) {
      error(`${where} : adresse IP invalide « ${link.ip} ».`, node.id, link.id);
      continue;
    }
    if (maskFieldError(link.mask, { required: true })) {
      error(`${where} : masque invalide ou manquant.`, node.id, link.id);
      continue;
    }
    const iface = parseInterface(link.ip, link.mask);
    parsedLinks.set(link.id, iface);
    if (iface.ip === iface.network || iface.ip === iface.broadcast) {
      error(`${where} : ${link.ip} est l'adresse de réseau ou de diffusion de ${iface.cidr}.`, node.id, link.id);
    }
    if (addressOwners.has(iface.ip)) {
      error(`Adresse ${link.ip} attribuée à ${addressOwners.get(iface.ip)} et à ${node.name}.`, node.id, link.id);
    } else {
      addressOwners.set(iface.ip, node.name);
    }
  }

  // --- Réseaux : chaque switch déclare son réseau (attribué par l'IPAM) -----
  const subnets = new Map(); // id du switch → { cidr, network, broadcast, prefix }
  for (const network of topology.networks) {
    const links = linksByNetwork.get(network.id) ?? [];
    if (vlanFieldError(network.vlan)) error(`${network.name} : numéro de VLAN invalide.`, network.id);
    const subnetError = subnetFieldError(network.subnet);
    if (subnetError) {
      error(`${network.name} : réseau invalide (${subnetError.toLowerCase()}).`, network.id);
      continue;
    }
    subnets.set(network.id, parseSubnet(network.subnet));
    if (!links.length) {
      warning(`${network.name} n'est relié à aucun équipement.`, network.id);
      continue;
    }

    const declared = subnets.get(network.id);
    for (const link of links) {
      const iface = parsedLinks.get(link.id);
      if (iface && iface.cidr !== declared.cidr) {
        error(
          `${nameOf(link.node)} (${formatIp(iface.ip)}/${iface.prefix}) n'appartient pas au réseau de ` +
            `${network.name} (${declared.cidr}).`,
          network.id,
          link.node,
          link.id,
        );
      }
    }

    const subnet = subnets.get(network.id);
    if (subnet) {
      // Une adresse du réseau reste réservée au segment lui-même (voir planner.py)
      const hosts = subnet.broadcast - subnet.network - 1;
      // Interfaces qui ont (ou attendent) une adresse : une sonde sans adresse n'en consomme pas
      const needed = links.filter((l) => parsedLinks.has(l.id) || (!l.ip && nodesById.get(l.node)?.type !== 'ids')).length;
      if (needed >= hosts) error(`${network.name} : le sous-réseau ${subnet.cidr} est plein, élargissez le masque.`, network.id);
    }
  }

  const subnetEntries = [...subnets.entries()];
  subnetEntries.forEach(([idA, a], i) => {
    for (const [idB, b] of subnetEntries.slice(i + 1)) {
      if (subnetsOverlap(a, b)) {
        error(`${nameOf(idA)} (${a.cidr}) et ${nameOf(idB)} (${b.cidr}) ont des plages d'adresses qui se chevauchent.`, idA, idB);
      }
    }
  });

  // --- Configuration propre à chaque équipement -----------------------------
  for (const node of topology.nodes) {
    const links = linksByNode.get(node.id) ?? [];
    const label = DEVICE_TYPES[node.type]?.label ?? node.type;
    const ownIps = new Set(links.map((l) => parsedLinks.get(l.id)?.ip).filter((ip) => ip !== undefined));
    const connectedSubnets = links.map((l) => subnets.get(l.network)).filter(Boolean);
    const reachable = (ipInt) => connectedSubnets.some((s) => subnetContains(s, ipInt));

    if (!links.length) {
      warning(`${node.name} (${label}) n'est relié à aucun switch.`, node.id);
    }

    const { config } = node;

    if (node.type === 'pc' || node.type === 'server') {
      const gw = parseIp(config.gateway ?? '');
      if (!config.gateway) {
        if (topology.networks.length > 1) warning(`${node.name} n'a pas de passerelle : il ne pourra joindre que son propre réseau.`, node.id);
      } else if (gw === null) error(`${node.name} : passerelle invalide « ${config.gateway} ».`, node.id);
      else if (ownIps.has(gw)) error(`${node.name} : la passerelle ne peut pas être sa propre adresse.`, node.id);
      else if (connectedSubnets.length && !reachable(gw)) {
        error(`${node.name} : la passerelle ${config.gateway} n'appartient à aucun réseau auquel il est relié.`, node.id);
      }
    }

    if (node.type === 'server') {
      const seen = new Set();
      config.services.forEach((svc, i) => {
        if (portFieldError(svc.port)) error(`${node.name}, service n°${i + 1} : port invalide.`, node.id);
        const key = `${svc.port}/${svc.protocol}`;
        if (seen.has(key)) error(`${node.name} : le port ${key} est déclaré deux fois.`, node.id);
        seen.add(key);
      });
    }

    if (node.type === 'router') {
      if (links.length < 2) warning(`${node.name} est relié à moins de deux réseaux : il n'a rien à router.`, node.id);
      const interfaces = new Set(links.map((l) => l.interface));
      config.routes.forEach((route, i) => {
        const where = `${node.name}, route n°${i + 1}`;
        if (cidrFieldError(route.destination)) return error(`${where} : réseau de destination invalide.`, node.id);
        if (!route.gateway && !route.interface) return error(`${where} : indiquez une passerelle ou une interface de sortie.`, node.id);
        if (route.gateway) {
          const gw = parseIp(route.gateway);
          if (gw === null) return error(`${where} : passerelle invalide « ${route.gateway} ».`, node.id);
          if (connectedSubnets.length && !reachable(gw)) {
            return error(`${where} : la passerelle ${route.gateway} n'est joignable par aucune interface.`, node.id);
          }
        }
        if (route.interface && !interfaces.has(route.interface)) {
          return error(`${where} : l'interface ${route.interface} n'existe plus.`, node.id);
        }
        if (parseCidr(route.destination).hostBitsSet) {
          const { network, prefix } = parseCidr(route.destination);
          warning(`${where} : la destination sera interprétée comme ${formatIp(network)}/${prefix}.`, node.id);
        }
        return null;
      });
    }

    if (node.type === 'ids') {
      const segment = config.monitoredSegment;
      if (!segment) warning(`${node.name} ne surveille aucun segment.`, node.id);
      else if (!networksById.has(segment)) error(`${node.name} : le segment surveillé n'existe plus.`, node.id);
      else if (!links.some((l) => l.network === segment)) {
        error(`${node.name} doit être relié par un câble au switch qu'il surveille (${nameOf(segment)}).`, node.id);
      }
    }
  }

  return issues;
}

export const hasErrors = (issues) => issues.some((i) => i.level === 'error');
