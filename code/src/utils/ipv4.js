/**
 * Calculs d'adressage IPv4 (adresses manipulées comme des entiers non signés 32 bits).
 * Mêmes règles que côté serveur (backend/app/planner.py).
 */

// Un octet IPv4 : 0 à 255, sans zéro en tête
const OCTET = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const IPV4_REGEX = new RegExp(`^${OCTET}(\\.${OCTET}){3}$`);

/** Masque le plus restrictif accepté : au-delà, plus d'adresse libre pour le segment. */
export const MAX_PREFIX = 30;

/** « 10.0.0.1 » → entier, ou null si invalide. */
export function parseIp(value) {
  if (typeof value !== 'string' || !IPV4_REGEX.test(value.trim())) return null;
  return value
    .trim()
    .split('.')
    .reduce((acc, octet) => ((acc << 8) | Number(octet)) >>> 0, 0);
}

export function formatIp(int) {
  return [24, 16, 8, 0].map((shift) => (int >>> shift) & 255).join('.');
}

export function isValidIp(value) {
  return parseIp(value) !== null;
}

function prefixToMaskInt(prefix) {
  return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

/**
 * Masque de sous-réseau → longueur de préfixe, ou null si invalide.
 * Accepte « 255.255.255.0 », « /24 » et « 24 ».
 */
export function parsePrefix(value) {
  if (typeof value !== 'string') return null;
  const mask = value.trim().replace(/^\//, '');
  if (/^\d{1,2}$/.test(mask)) return Number(mask) <= 32 ? Number(mask) : null;

  const int = parseIp(mask);
  if (int === null) return null;
  // Un masque valide est une suite de 1 puis une suite de 0
  const inverted = ~int >>> 0;
  if ((inverted & (inverted + 1)) !== 0) return null;
  return 32 - Math.log2(inverted + 1);
}

export function prefixToMask(prefix) {
  return formatIp(prefixToMaskInt(prefix));
}

/**
 * Interface (ip + masque) → { ip, prefix, network, broadcast, cidr }, ou null.
 * `cidr` est la notation du réseau : « 10.0.1.0/24 ».
 */
export function parseInterface(ip, mask) {
  const ipInt = parseIp(ip ?? '');
  const prefix = parsePrefix(mask ?? '');
  if (ipInt === null || prefix === null) return null;
  const maskInt = prefixToMaskInt(prefix);
  const network = (ipInt & maskInt) >>> 0;
  const broadcast = (network | (~maskInt >>> 0)) >>> 0;
  return { ip: ipInt, prefix, network, broadcast, cidr: `${formatIp(network)}/${prefix}` };
}

/** « 10.0.2.0/24 » ou « 10.0.2.0/255.255.255.0 » → { network, prefix, cidr }, ou null. */
export function parseCidr(value) {
  if (typeof value !== 'string') return null;
  const [ip, mask, ...rest] = value.trim().split('/');
  if (rest.length || mask === undefined) return null;
  const parsed = parseInterface(ip, mask);
  if (!parsed) return null;
  return { network: parsed.network, prefix: parsed.prefix, cidr: parsed.cidr, hostBitsSet: parsed.ip !== parsed.network };
}

export function subnetContains(subnet, ipInt) {
  return ipInt >= subnet.network && ipInt <= subnet.broadcast;
}

export function subnetsOverlap(a, b) {
  return a.network <= b.broadcast && b.network <= a.broadcast;
}

/** « 10.0.1.10 » + « 255.255.255.0 » → « 10.0.1.10/24 » (ou l'IP seule si le masque est invalide). */
export function formatInterface(ip, mask) {
  const prefix = parsePrefix(mask ?? '');
  return prefix === null ? ip : `${ip}/${prefix}`;
}

/**
 * Réseau déclaré sur un switch (« 10.0.1.0/24 ») → { network, broadcast, prefix, cidr },
 * ou null s'il est invalide, n'est pas une adresse de réseau ou dépasse /MAX_PREFIX.
 */
export function parseSubnet(value) {
  const parsed = parseCidr(value);
  if (!parsed || parsed.hostBitsSet || parsed.prefix > MAX_PREFIX) return null;
  const broadcast = (parsed.network | (~prefixToMaskInt(parsed.prefix) >>> 0)) >>> 0;
  return { network: parsed.network, broadcast, prefix: parsed.prefix, cidr: parsed.cidr };
}
