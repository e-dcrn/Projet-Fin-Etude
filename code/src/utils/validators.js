import { DEVICE_TYPES } from '../config/deviceTypes.js';

// Un octet IPv4 : 0 à 255, sans zéro en tête
const OCTET = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const IPV4_REGEX = new RegExp(`^${OCTET}(\\.${OCTET}){3}$`);

/**
 * Vérifie une adresse IPv4, avec masque CIDR optionnel.
 * Exemples valides : « 10.0.0.1 », « 192.168.1.10/24 ».
 */
export function isValidIpAddress(value) {
  if (typeof value !== 'string') return false;
  const parts = value.trim().split('/');
  if (parts.length > 2) return false;

  const [ip, mask] = parts;
  if (!IPV4_REGEX.test(ip)) return false;
  if (mask === undefined) return true;
  return /^\d{1,2}$/.test(mask) && Number(mask) <= 32;
}

/** Retire le masque CIDR éventuel : « 10.0.0.1/24 » → « 10.0.0.1 ». */
export function stripMask(ip) {
  return ip.split('/')[0].trim();
}

/**
 * Contrôles de cohérence sur une topologie sérialisée.
 * Ne bloque pas la validation : retourne une liste d'avertissements lisibles.
 */
export function validateTopology(topology) {
  const warnings = [];
  const ipOwners = new Map();
  const nameOwners = new Map();
  const connected = new Set(topology.links.flatMap((l) => [l.source, l.target]));

  for (const node of topology.nodes) {
    const { name, ip } = node.properties;

    if (!name?.trim()) warnings.push(`L'équipement ${node.id} n'a pas de nom.`);
    else if (nameOwners.has(name)) warnings.push(`Nom « ${name} » en double.`);
    else nameOwners.set(name, node.id);

    if (ip) {
      if (!isValidIpAddress(ip)) {
        warnings.push(`${name} : adresse IP invalide « ${ip} ».`);
      } else {
        const bareIp = stripMask(ip);
        if (ipOwners.has(bareIp)) {
          warnings.push(`IP ${bareIp} utilisée par ${ipOwners.get(bareIp)} et ${name}.`);
        } else {
          ipOwners.set(bareIp, name);
        }
      }
    } else if (node.type !== 'switch') {
      // Un switch de niveau 2 peut ne pas avoir d'IP de management
      warnings.push(`${name} (${DEVICE_TYPES[node.type]?.label}) n'a pas d'adresse IP.`);
    }

    if (!connected.has(node.id)) warnings.push(`${name} n'est relié à aucun équipement.`);
  }

  return warnings;
}
