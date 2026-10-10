import { FILTER_FIELDS, FILTER_PROTOCOLS } from './packetDissector.js';
import { parseCidr, parseIp } from './ipv4.js';

/**
 * Filtres d'affichage, avec un sous-ensemble de la syntaxe de Wireshark :
 *
 *   icmp                         protocole présent
 *   ip.addr == 10.0.1.10         adresse source OU destination
 *   ip.src == 10.0.1.0/24        appartenance à un réseau
 *   tcp.port == 80 && !arp       combinaisons : && (and), || (or), ! (not), parenthèses
 *   tcp.flags.syn == 1 and tcp.flags.ack == 0
 *   frame.len > 1000             comparaisons : == != > < >= <=
 *   dns.qry.name contains "lab"  recherche de texte
 *
 * compileFilter(texte) → (packet) => boolean ; lève FilterError si le filtre est invalide.
 * Un filtre vide accepte tout. `packet.fields` vient de packetDissector.js.
 */

export class FilterError extends Error {}

const KNOWN = new Set([...FILTER_PROTOCOLS, ...FILTER_FIELDS]);
const KEYWORDS = { and: '&&', or: '||', not: '!', eq: '==', ne: '!=', gt: '>', lt: '<', ge: '>=', le: '<=' };
const COMPARATORS = new Set(['==', '!=', '>', '<', '>=', '<=', 'contains']);

function tokenize(text) {
  const tokens = [];
  const pattern = /\s*(?:(&&|\|\||==|!=|>=|<=|[()!<>])|"([^"]*)"|([^\s()!<>=&|"]+))/gy;
  let match;
  let index = 0;
  while (index < text.length) {
    pattern.lastIndex = index;
    match = pattern.exec(text);
    if (!match || match[0].length === 0) {
      if (/^\s*$/.test(text.slice(index))) break;
      throw new FilterError(`Caractère inattendu : « ${text.slice(index).trim()[0]} »`);
    }
    index = pattern.lastIndex;
    if (match[1]) tokens.push({ op: match[1] });
    else if (match[2] !== undefined) tokens.push({ word: match[2], quoted: true });
    else if (match[3]) {
      const lower = match[3].toLowerCase();
      if (KEYWORDS[lower]) tokens.push({ op: KEYWORDS[lower] });
      else if (lower === 'contains') tokens.push({ op: 'contains' });
      else tokens.push({ word: match[3] });
    }
  }
  return tokens;
}

/** Compare une valeur extraite d'un paquet à la valeur du filtre. */
function matches(actual, op, expected) {
  if (op === 'contains') return String(actual).toLowerCase().includes(expected.text.toLowerCase());
  if (expected.subnet && typeof actual === 'string') {
    const ip = parseIp(actual);
    const inside = ip !== null && ip >= expected.subnet.network && ip <= expected.subnet.broadcast;
    return op === '==' ? inside : op === '!=' ? !inside : false;
  }
  if (typeof actual === 'number' && expected.number !== null) {
    const a = actual;
    const b = expected.number;
    return { '==': a === b, '!=': a !== b, '>': a > b, '<': a < b, '>=': a >= b, '<=': a <= b }[op];
  }
  const a = String(actual).toLowerCase();
  const b = expected.text.toLowerCase();
  return { '==': a === b, '!=': a !== b, '>': a > b, '<': a < b, '>=': a >= b, '<=': a <= b }[op];
}

function parseValue(token) {
  const text = token.word;
  const cidr = !token.quoted && text.includes('/') ? parseCidr(text) : null;
  const subnet = cidr && { network: cidr.network, broadcast: (cidr.network + 2 ** (32 - cidr.prefix) - 1) >>> 0 };
  const number = !token.quoted && /^(0x[0-9a-f]+|\d+)$/i.test(text) ? Number(text) : null;
  return { text, number, subnet };
}

export function compileFilter(text) {
  if (!text.trim()) return () => true;
  const tokens = tokenize(text);
  let pos = 0;
  const peek = () => tokens[pos];
  const isOp = (op) => peek()?.op === op;

  function parseOr() {
    let left = parseAnd();
    while (isOp('||')) {
      pos += 1;
      const l = left;
      const r = parseAnd();
      left = (p) => l(p) || r(p);
    }
    return left;
  }

  function parseAnd() {
    let left = parseNot();
    while (isOp('&&')) {
      pos += 1;
      const l = left;
      const r = parseNot();
      left = (p) => l(p) && r(p);
    }
    return left;
  }

  function parseNot() {
    if (isOp('!')) {
      pos += 1;
      const inner = parseNot();
      return (p) => !inner(p);
    }
    return parsePrimary();
  }

  function parsePrimary() {
    const token = peek();
    if (!token) throw new FilterError('Filtre incomplet');
    if (token.op === '(') {
      pos += 1;
      const inner = parseOr();
      if (!isOp(')')) throw new FilterError('Parenthèse fermante manquante');
      pos += 1;
      return inner;
    }
    if (!token.word || token.quoted) throw new FilterError(`Champ attendu à la place de « ${token.op ?? token.word} »`);
    const field = token.word.toLowerCase();
    if (!KNOWN.has(field)) throw new FilterError(`Champ ou protocole inconnu : « ${token.word} »`);
    pos += 1;

    const op = peek()?.op;
    if (!COMPARATORS.has(op)) {
      return (p) => Boolean(p.fields[field]?.some((v) => v !== 0 && v !== false)); // présence
    }
    pos += 1;
    const valueToken = peek();
    if (!valueToken?.word && valueToken?.word !== '') throw new FilterError(`Valeur attendue après « ${op} »`);
    pos += 1;
    const expected = parseValue(valueToken);
    if (op === '!=') {
      // Comme Wireshark : vrai si AUCUNE valeur n'est égale (ip.addr != x exclut x en source comme en destination)
      return (p) => (p.fields[field] ?? []).every((v) => !matches(v, '==', expected));
    }
    return (p) => (p.fields[field] ?? []).some((v) => matches(v, op, expected));
  }

  const predicate = parseOr();
  if (pos < tokens.length) throw new FilterError(`Élément inattendu : « ${tokens[pos].op ?? tokens[pos].word} »`);
  return predicate;
}
