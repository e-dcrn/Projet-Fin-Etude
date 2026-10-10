import { isNetworkType } from '../config/deviceTypes.js';
import { formatIp, parseIp, parseSubnet, prefixToMask, subnetsOverlap } from './ipv4.js';
import { deviceLinks } from './topologyQueries.js';

/**
 * IPAM : gestion automatique de l'adressage.
 *
 *   - chaque switch reçoit un réseau libre à sa création (10.0.1.0/24, 10.0.2.0/24…) ;
 *   - chaque interface créée par un câble est en mode automatique (`data.auto`) :
 *     elle reçoit une adresse libre du réseau du switch, les routeurs en tête de
 *     plage (.1, .2… : les passerelles), les autres équipements à partir de .10 ;
 *   - la passerelle d'un PC / serveur en mode automatique (`gatewayAuto`) est
 *     l'adresse du routeur relié au même switch.
 *
 * Les attributions sont stables : une adresse automatique est conservée tant
 * qu'elle reste valide (dans le réseau du switch, sans conflit) ; seules les
 * interfaces nouvelles ou devenues invalides sont (ré)adressées.
 * Saisir une valeur à la main fait passer le champ en mode manuel : l'IPAM ne
 * le touche plus, mais en tient compte (ses adresses ne sont jamais réattribuées).
 *
 * La dernière adresse de chaque réseau n'est jamais attribuée : le moteur de
 * simulation la réserve au segment lui-même (voir backend/app/planner.py).
 */

/** Réseaux proposés aux nouveaux switches : 10.0.1.0/24, 10.0.2.0/24… */
const POOL = { first: parseIp('10.0.1.0'), prefix: 24, size: 254 };

/** Premier rang (.10) attribué aux équipements autres que les routeurs. */
const HOST_OFFSET = 10;

/** Premier réseau du pool qui ne chevauche aucun réseau de switch existant. */
export function nextSubnet(nodes) {
  const taken = nodes
    .filter((n) => isNetworkType(n.data.deviceType))
    .map((n) => parseSubnet(n.data.properties.subnet))
    .filter(Boolean);
  const blockSize = 2 ** (32 - POOL.prefix);
  for (let i = 0; i < POOL.size; i += 1) {
    const network = POOL.first + i * blockSize;
    const candidate = { network, broadcast: network + blockSize - 1 };
    if (!taken.some((s) => subnetsOverlap(s, candidate))) return `${formatIp(network)}/${POOL.prefix}`;
  }
  return '';
}

/** Plage attribuable d'un réseau : de .1 à l'avant-dernière adresse. */
const assignableRange = (subnet) => ({ first: subnet.network + 1, last: subnet.broadcast - 2 });

function allocate(subnet, used, deviceType) {
  const { first, last } = assignableRange(subnet);
  const start = deviceType === 'router' || first + HOST_OFFSET - 1 > last ? first : subnet.network + HOST_OFFSET;
  for (let ip = start; ip <= last; ip += 1) if (!used.has(ip)) return ip;
  for (let ip = first; ip < start; ip += 1) if (!used.has(ip)) return ip;
  return null; // réseau plein
}

/**
 * Calcule les corrections d'adressage à appliquer (fonction pure).
 * @returns {{ links: Map<string, {ip, mask}>, gateways: Map<string, string> }}
 *          vides si tout est déjà à jour (l'opération est idempotente)
 */
export function planIpam(nodes, edges) {
  const nodesById = new Map(nodes.map((n) => [n.id, n]));
  const typeOf = (id) => nodesById.get(id)?.data.deviceType;
  const subnetOf = (switchId) => parseSubnet(nodesById.get(switchId)?.data.properties.subnet);

  // 1. Adresses occupées : interfaces manuelles, puis adresses automatiques encore valides
  const used = new Set();
  for (const edge of edges) {
    const ip = parseIp(edge.data.ip ?? '');
    if (!edge.data.auto && ip !== null) used.add(ip);
  }
  const kept = new Set();
  for (const edge of edges) {
    if (!edge.data.auto) continue;
    const subnet = subnetOf(edge.target);
    const ip = parseIp(edge.data.ip ?? '');
    if (ip === null) continue;
    if (!subnet) {
      used.add(ip); // réseau du switch en cours de saisie : on ne touche à rien
      continue;
    }
    const { first, last } = assignableRange(subnet);
    if (typeOf(edge.source) !== 'ids' && ip >= first && ip <= last && !used.has(ip)) {
      used.add(ip);
      kept.add(edge.id);
    }
  }

  // 2. Interfaces automatiques à (ré)adresser
  const links = new Map();
  const addresses = new Map(); // id du câble → adresse finale
  for (const edge of edges) {
    let { ip, mask } = edge.data;
    const subnet = edge.data.auto ? subnetOf(edge.target) : null;
    if (subnet) {
      mask = prefixToMask(subnet.prefix);
      if (typeOf(edge.source) === 'ids') {
        ip = ''; // la sonde écoute sans adresse fixe (attribuée par le moteur)
      } else if (!kept.has(edge.id)) {
        const allocated = allocate(subnet, used, typeOf(edge.source));
        if (allocated !== null) used.add(allocated);
        ip = allocated === null ? '' : formatIp(allocated);
      }
      if (ip !== edge.data.ip || mask !== edge.data.mask) links.set(edge.id, { ip, mask });
    }
    addresses.set(edge.id, ip);
  }

  // 3. Passerelles automatiques : premier routeur présent sur un switch de l'équipement
  const routerBySwitch = new Map();
  for (const edge of edges) {
    const ip = addresses.get(edge.id);
    if (typeOf(edge.source) === 'router' && parseIp(ip ?? '') !== null && !routerBySwitch.has(edge.target)) {
      routerBySwitch.set(edge.target, ip);
    }
  }
  const gateways = new Map();
  for (const node of nodes) {
    const { properties } = node.data;
    if (!('gateway' in properties) || properties.gatewayAuto === false) continue;
    const gateway = deviceLinks(edges, node.id).map((l) => routerBySwitch.get(l.target)).find(Boolean) ?? '';
    if (gateway !== properties.gateway) gateways.set(node.id, gateway);
  }

  return { links, gateways };
}
