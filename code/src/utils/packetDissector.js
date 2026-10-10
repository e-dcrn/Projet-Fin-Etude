/**
 * Décodage des trames capturées, à la manière des dissecteurs de Wireshark.
 *
 * const dissect = createDissector();   // un par capture (numéros de séquence TCP relatifs)
 * dissect(bytes) → {
 *   src, dst, protocol, info,           // colonnes de la liste des paquets
 *   fields: { 'ip.src': [...], … },     // valeurs pour les filtres d'affichage (displayFilter.js)
 *   tree: [{ key, label, start, end, children: [...] }],  // détail par couche ;
 * }                                     // start/end : octets concernés (surlignés dans le dump)
 *
 * Couches gérées : Ethernet (+ VLAN 802.1Q), ARP, IPv4, IPv6, ICMP, ICMPv6, IGMP,
 * TCP, UDP, DNS, HTTP, TLS, SSH, et les protocoles texte des services simulés
 * (FTP, SMTP, POP, IMAP, Telnet).
 */

// ---------------------------------------------------------------- lecture

const u8 = (b, o) => b[o];
const u16 = (b, o) => (b[o] << 8) | b[o + 1];
const u32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const hex = (n, width) => `0x${n.toString(16).padStart(width, '0')}`;

export const formatMac = (b, o) => Array.from(b.subarray(o, o + 6), (x) => x.toString(16).padStart(2, '0')).join(':');
export const formatIpv4 = (b, o) => `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;

export function formatIpv6(b, o) {
  const groups = [];
  for (let i = 0; i < 8; i += 1) groups.push(u16(b, o + 2 * i));
  // Plus longue suite de groupes nuls remplacée par « :: »
  let best = { at: -1, len: 0 };
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) { i += 1; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j += 1;
    if (j - i > best.len && j - i > 1) best = { at: i, len: j - i };
    i = j;
  }
  const text = groups.map((g) => g.toString(16));
  if (best.at < 0) return text.join(':');
  return `${text.slice(0, best.at).join(':')}::${text.slice(best.at + best.len).join(':')}`;
}

const BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff';
const isPrintable = (b) => b.every((c) => c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127));
const ascii = (b) => Array.from(b, (c) => String.fromCharCode(c)).join('');
const firstLine = (b) => ascii(b.subarray(0, 300)).split(/\r?\n/)[0];

// ---------------------------------------------------------------- arbre

function node(key, label, start, end, children = []) {
  return { key, label, start, end, children };
}
const leaf = (label, start, length) => node(null, label, start, start + length);

// ---------------------------------------------------------------- tables

const ETHERTYPES = { 0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x8100: '802.1Q' };
const IP_PROTOCOLS = { 1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6', 89: 'OSPF', 0: 'Hop-by-Hop' };

const ICMP_TYPES = {
  0: 'Echo (ping) reply',
  3: 'Destination unreachable',
  5: 'Redirect',
  8: 'Echo (ping) request',
  11: 'Time-to-live exceeded',
};
const ICMP_UNREACHABLE = {
  0: 'Network unreachable',
  1: 'Host unreachable',
  2: 'Protocol unreachable',
  3: 'Port unreachable',
  4: 'Fragmentation needed',
  9: 'Network administratively prohibited',
  10: 'Host administratively prohibited',
  13: 'Communication administratively filtered',
};
const ICMPV6_TYPES = {
  1: 'Destination Unreachable',
  3: 'Time Exceeded',
  128: 'Echo (ping) request',
  129: 'Echo (ping) reply',
  133: 'Router Solicitation',
  134: 'Router Advertisement',
  135: 'Neighbor Solicitation',
  136: 'Neighbor Advertisement',
  143: 'Multicast Listener Report Message v2',
};
const IGMP_TYPES = { 0x11: 'Membership Query', 0x16: 'Membership Report v2', 0x17: 'Leave Group', 0x22: 'Membership Report v3' };
const DNS_TYPES = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY' };
const DNS_RCODES = { 0: 'No error', 1: 'Format error', 2: 'Server failure', 3: 'No such name', 4: 'Not implemented', 5: 'Refused' };
// Ordre d'affichage de Wireshark : [SYN, ACK], [FIN, ACK], [PSH, ACK]…
const TCP_FLAGS = [
  [0x01, 'FIN'],
  [0x02, 'SYN'],
  [0x04, 'RST'],
  [0x08, 'PSH'],
  [0x10, 'ACK'],
  [0x20, 'URG'],
  [0x40, 'ECE'],
  [0x80, 'CWR'],
  [0x100, 'NS'],
];

/** Protocoles texte reconnus par port (services simulés, voir backend/app/service_listener.py). */
const TEXT_PROTOCOLS = { 21: 'FTP', 23: 'TELNET', 25: 'SMTP', 110: 'POP', 143: 'IMAP' };
const HTTP_PORTS = new Set([80, 8000, 8080, 8888]);
const HTTP_START = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) \S+ HTTP\/\d|^HTTP\/\d\.\d \d{3}/;
const TLS_VERSIONS = { 0x0301: 'TLSv1.0', 0x0302: 'TLSv1.1', 0x0303: 'TLSv1.2', 0x0304: 'TLSv1.3' };
const TLS_CONTENT = { 20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data' };
const TLS_HANDSHAKE = { 1: 'Client Hello', 2: 'Server Hello', 4: 'New Session Ticket', 11: 'Certificate', 12: 'Server Key Exchange', 14: 'Server Hello Done', 16: 'Client Key Exchange', 20: 'Finished' };

/** Noms de protocole utilisables dans les filtres d'affichage (en minuscules). */
export const FILTER_PROTOCOLS = ['eth', 'vlan', 'arp', 'ip', 'ipv6', 'icmp', 'icmpv6', 'igmp', 'tcp', 'udp', 'dns', 'http', 'tls', 'ssh', 'ftp', 'smtp', 'pop', 'imap', 'telnet', 'data'];

/** Champs utilisables dans les filtres d'affichage (en plus des noms de protocole). */
export const FILTER_FIELDS = [
  'frame.len', 'eth.src', 'eth.dst', 'eth.addr', 'vlan.id', 'arp.opcode', 'arp.src.proto_ipv4', 'arp.dst.proto_ipv4',
  'ip.src', 'ip.dst', 'ip.addr', 'ip.ttl', 'ip.proto', 'ipv6.src', 'ipv6.dst', 'ipv6.addr',
  'icmp.type', 'icmp.code', 'tcp.srcport', 'tcp.dstport', 'tcp.port', 'tcp.len', 'tcp.flags.syn', 'tcp.flags.ack',
  'tcp.flags.fin', 'tcp.flags.reset', 'tcp.flags.push', 'udp.srcport', 'udp.dstport', 'udp.port',
  'dns.qry.name', 'dns.flags.response', 'http.request.method', 'http.response.code',
];

// ---------------------------------------------------------------- couches

function dissectEthernet(b, p) {
  if (b.length < 14) {
    p.protocol = 'Ethernet';
    p.info = 'Trame tronquée';
    return;
  }
  const dst = formatMac(b, 0);
  const src = formatMac(b, 6);
  let type = u16(b, 12);
  let offset = 14;
  p.src = src;
  p.dst = dst === BROADCAST_MAC ? 'Broadcast' : dst;
  p.add('eth', true);
  p.add('eth.src', src);
  p.add('eth.dst', dst);
  p.add('eth.addr', src, dst);

  const eth = node('eth', `Ethernet II, Src: ${src}, Dst: ${dst === BROADCAST_MAC ? `Broadcast (${dst})` : dst}`, 0, 14, [
    leaf(`Destination: ${dst}`, 0, 6),
    leaf(`Source: ${src}`, 6, 6),
    leaf(`Type: ${ETHERTYPES[type] ?? 'Inconnu'} (${hex(type, 4)})`, 12, 2),
  ]);
  p.tree.push(eth);

  while (type === 0x8100 && b.length >= offset + 4) {
    const tci = u16(b, offset);
    const vid = tci & 0x0fff;
    const inner = u16(b, offset + 2);
    p.add('vlan', true);
    p.add('vlan.id', vid);
    p.tree.push(
      node('vlan', `802.1Q Virtual LAN, PRI: ${tci >> 13}, ID: ${vid}`, offset, offset + 4, [
        leaf(`Priority: ${tci >> 13}`, offset, 2),
        leaf(`ID: ${vid}`, offset, 2),
        leaf(`Type: ${ETHERTYPES[inner] ?? 'Inconnu'} (${hex(inner, 4)})`, offset + 2, 2),
      ]),
    );
    type = inner;
    offset += 4;
  }

  p.protocol = ETHERTYPES[type] ?? 'Ethernet';
  p.info = `Ethertype ${hex(type, 4)}`;
  if (type === 0x0806) dissectArp(b, offset, p);
  else if (type === 0x0800) dissectIpv4(b, offset, p);
  else if (type === 0x86dd) dissectIpv6(b, offset, p);
}

function dissectArp(b, o, p) {
  if (b.length < o + 28) return;
  const op = u16(b, o + 6);
  const sha = formatMac(b, o + 8);
  const spa = formatIpv4(b, o + 14);
  const tha = formatMac(b, o + 18);
  const tpa = formatIpv4(b, o + 24);
  const opName = op === 1 ? 'request' : op === 2 ? 'reply' : `opcode ${op}`;
  p.protocol = 'ARP';
  p.add('arp', true);
  p.add('arp.opcode', op);
  p.add('arp.src.proto_ipv4', spa);
  p.add('arp.dst.proto_ipv4', tpa);
  if (op === 1) p.info = spa === tpa ? `ARP Announcement for ${spa}` : `Who has ${tpa}? Tell ${spa}`;
  else if (op === 2) p.info = `${spa} is at ${sha}`;
  else p.info = `ARP ${opName}`;
  p.tree.push(
    node('arp', `Address Resolution Protocol (${opName})`, o, o + 28, [
      leaf(`Hardware type: Ethernet (${u16(b, o)})`, o, 2),
      leaf(`Protocol type: IPv4 (${hex(u16(b, o + 2), 4)})`, o + 2, 2),
      leaf(`Hardware size: ${u8(b, o + 4)}`, o + 4, 1),
      leaf(`Protocol size: ${u8(b, o + 5)}`, o + 5, 1),
      leaf(`Opcode: ${opName} (${op})`, o + 6, 2),
      leaf(`Sender MAC address: ${sha}`, o + 8, 6),
      leaf(`Sender IP address: ${spa}`, o + 14, 4),
      leaf(`Target MAC address: ${tha}`, o + 18, 6),
      leaf(`Target IP address: ${tpa}`, o + 24, 4),
    ]),
  );
}

function dissectIpv4(b, o, p) {
  if (b.length < o + 20) return;
  const ihl = (u8(b, o) & 0x0f) * 4;
  const total = u16(b, o + 2);
  const flags = u16(b, o + 6);
  const fragOffset = (flags & 0x1fff) * 8;
  const ttl = u8(b, o + 8);
  const proto = u8(b, o + 9);
  const src = formatIpv4(b, o + 12);
  const dst = formatIpv4(b, o + 16);
  const end = Math.min(b.length, o + total); // sans le bourrage Ethernet
  p.src = src;
  p.dst = dst;
  p.ttl = ttl;
  p.protocol = IP_PROTOCOLS[proto] ?? 'IPv4';
  p.info = `Protocole ${proto}`;
  p.add('ip', true);
  p.add('ip.src', src);
  p.add('ip.dst', dst);
  p.add('ip.addr', src, dst);
  p.add('ip.ttl', ttl);
  p.add('ip.proto', proto);
  const flagNames = [flags & 0x4000 && "Don't fragment", flags & 0x2000 && 'More fragments'].filter(Boolean);
  p.tree.push(
    node('ip', `Internet Protocol Version 4, Src: ${src}, Dst: ${dst}`, o, o + ihl, [
      leaf(`Version: 4`, o, 1),
      leaf(`Header Length: ${ihl} bytes`, o, 1),
      leaf(`Differentiated Services Field: ${hex(u8(b, o + 1), 2)}`, o + 1, 1),
      leaf(`Total Length: ${total}`, o + 2, 2),
      leaf(`Identification: ${hex(u16(b, o + 4), 4)} (${u16(b, o + 4)})`, o + 4, 2),
      leaf(`Flags: ${hex(flags >> 13, 1)}${flagNames.length ? `, ${flagNames.join(', ')}` : ''}`, o + 6, 1),
      leaf(`Fragment Offset: ${fragOffset}`, o + 6, 2),
      leaf(`Time to Live: ${ttl}`, o + 8, 1),
      leaf(`Protocol: ${IP_PROTOCOLS[proto] ?? 'Inconnu'} (${proto})`, o + 9, 1),
      leaf(`Header Checksum: ${hex(u16(b, o + 10), 4)}`, o + 10, 2),
      leaf(`Source Address: ${src}`, o + 12, 4),
      leaf(`Destination Address: ${dst}`, o + 16, 4),
    ]),
  );
  if (fragOffset > 0) {
    p.protocol = 'IPv4';
    p.info = `Fragmented IP protocol (proto=${IP_PROTOCOLS[proto] ?? proto}, off=${fragOffset})`;
    return;
  }
  dissectTransport(b, o + ihl, end, proto, p);
}

function dissectIpv6(b, o, p) {
  if (b.length < o + 40) return;
  const payloadLength = u16(b, o + 4);
  const next = u8(b, o + 6);
  const hop = u8(b, o + 7);
  const src = formatIpv6(b, o + 8);
  const dst = formatIpv6(b, o + 24);
  p.src = src;
  p.dst = dst;
  p.protocol = IP_PROTOCOLS[next] ?? 'IPv6';
  p.info = `Next header ${next}`;
  p.add('ipv6', true);
  p.add('ipv6.src', src);
  p.add('ipv6.dst', dst);
  p.add('ipv6.addr', src, dst);
  p.tree.push(
    node('ipv6', `Internet Protocol Version 6, Src: ${src}, Dst: ${dst}`, o, o + 40, [
      leaf('Version: 6', o, 1),
      leaf(`Payload Length: ${payloadLength}`, o + 4, 2),
      leaf(`Next Header: ${IP_PROTOCOLS[next] ?? 'Inconnu'} (${next})`, o + 6, 1),
      leaf(`Hop Limit: ${hop}`, o + 7, 1),
      leaf(`Source Address: ${src}`, o + 8, 16),
      leaf(`Destination Address: ${dst}`, o + 24, 16),
    ]),
  );
  let proto = next;
  let offset = o + 40;
  const end = Math.min(b.length, offset + payloadLength);
  // En-tête d'extension Hop-by-Hop (rapports MLD) : on le saute
  if (proto === 0 && end >= offset + 8) {
    const length = (u8(b, offset + 1) + 1) * 8;
    p.tree.push(node('ipv6.hopopts', `IPv6 Hop-by-Hop Option`, offset, offset + length, []));
    proto = u8(b, offset);
    offset += length;
    p.protocol = IP_PROTOCOLS[proto] ?? 'IPv6';
  }
  dissectTransport(b, offset, end, proto, p);
}

function dissectTransport(b, o, end, proto, p) {
  if (proto === 1) dissectIcmp(b, o, end, p);
  else if (proto === 58) dissectIcmpv6(b, o, end, p);
  else if (proto === 2) dissectIgmp(b, o, end, p);
  else if (proto === 6) dissectTcp(b, o, end, p);
  else if (proto === 17) dissectUdp(b, o, end, p);
}

function dissectIcmp(b, o, end, p) {
  if (end < o + 4) return;
  const type = u8(b, o);
  const code = u8(b, o + 1);
  const name = ICMP_TYPES[type] ?? `Type ${type}`;
  p.add('icmp', true);
  p.add('icmp.type', type);
  p.add('icmp.code', code);
  const children = [
    leaf(`Type: ${type} (${name})`, o, 1),
    leaf(`Code: ${code}${type === 3 && ICMP_UNREACHABLE[code] ? ` (${ICMP_UNREACHABLE[code]})` : ''}`, o + 1, 1),
    leaf(`Checksum: ${hex(u16(b, o + 2), 4)}`, o + 2, 2),
  ];
  if ((type === 0 || type === 8) && end >= o + 8) {
    const id = u16(b, o + 4);
    const seq = u16(b, o + 6);
    children.push(leaf(`Identifier: ${id} (${hex(id, 4)})`, o + 4, 2), leaf(`Sequence Number: ${seq}`, o + 6, 2));
    if (end > o + 8) children.push(leaf(`Data (${end - o - 8} bytes)`, o + 8, end - o - 8));
    p.info = `${name}  id=${hex(id, 4)}, seq=${seq}, ttl=${p.ttl}`;
  } else if (type === 3) {
    p.info = `${name} (${ICMP_UNREACHABLE[code] ?? `code ${code}`})`;
  } else if (type === 11) {
    p.info = `${name} (${code === 0 ? 'in transit' : 'fragment reassembly'})`;
  } else {
    p.info = name;
  }
  p.tree.push(node('icmp', 'Internet Control Message Protocol', o, end, children));
}

function dissectIcmpv6(b, o, end, p) {
  if (end < o + 4) return;
  const type = u8(b, o);
  const name = ICMPV6_TYPES[type] ?? `Type ${type}`;
  p.add('icmpv6', true);
  let info = name;
  if ((type === 135 || type === 136) && end >= o + 24) info += ` for ${formatIpv6(b, o + 8)}`;
  p.info = info;
  p.tree.push(
    node('icmpv6', 'Internet Control Message Protocol v6', o, end, [
      leaf(`Type: ${name} (${type})`, o, 1),
      leaf(`Code: ${u8(b, o + 1)}`, o + 1, 1),
      leaf(`Checksum: ${hex(u16(b, o + 2), 4)}`, o + 2, 2),
    ]),
  );
}

function dissectIgmp(b, o, end, p) {
  if (end < o + 8) return;
  const type = u8(b, o);
  const name = IGMP_TYPES[type] ?? `Type ${hex(type, 2)}`;
  p.add('igmp', true);
  p.info = type === 0x22 ? name : `${name} ${formatIpv4(b, o + 4)}`;
  p.tree.push(
    node('igmp', 'Internet Group Management Protocol', o, end, [
      leaf(`Type: ${name} (${hex(type, 2)})`, o, 1),
      leaf(`Checksum: ${hex(u16(b, o + 2), 4)}`, o + 2, 2),
    ]),
  );
}

function dissectTcp(b, o, end, p) {
  if (end < o + 20) return;
  const sport = u16(b, o);
  const dport = u16(b, o + 2);
  const seq = u32(b, o + 4);
  const ack = u32(b, o + 8);
  const headerLength = (u8(b, o + 12) >> 4) * 4;
  const flags = u16(b, o + 12) & 0x1ff;
  const window = u16(b, o + 14);
  const payloadStart = o + headerLength;
  const length = Math.max(0, end - payloadStart);
  const flagNames = TCP_FLAGS.filter(([bit]) => flags & bit).map(([, n]) => n);

  // Numéros relatifs, comme Wireshark : 0 au premier segment de chaque sens
  const key = `${p.src}:${sport}>${p.dst}:${dport}`;
  const reverse = `${p.dst}:${dport}>${p.src}:${sport}`;
  if (!p.ctx.tcpBase.has(key) || flags & 0x02) p.ctx.tcpBase.set(key, seq);
  const relSeq = (seq - p.ctx.tcpBase.get(key)) >>> 0;
  const ackBase = p.ctx.tcpBase.get(reverse);
  const relAck = flags & 0x10 && ackBase !== undefined ? (ack - ackBase) >>> 0 : ack;

  p.add('tcp', true);
  p.add('tcp.srcport', sport);
  p.add('tcp.dstport', dport);
  p.add('tcp.port', sport, dport);
  p.add('tcp.len', length);
  p.add('tcp.flags.syn', flags & 0x02 ? 1 : 0);
  p.add('tcp.flags.ack', flags & 0x10 ? 1 : 0);
  p.add('tcp.flags.fin', flags & 0x01 ? 1 : 0);
  p.add('tcp.flags.reset', flags & 0x04 ? 1 : 0);
  p.add('tcp.flags.push', flags & 0x08 ? 1 : 0);
  p.tcpFlags = flags;
  p.protocol = 'TCP';
  p.info =
    `${sport} → ${dport} [${flagNames.join(', ')}] Seq=${relSeq}` +
    `${flags & 0x10 ? ` Ack=${relAck}` : ''} Win=${window} Len=${length}`;
  p.tree.push(
    node(
      'tcp',
      `Transmission Control Protocol, Src Port: ${sport}, Dst Port: ${dport}, Seq: ${relSeq}${flags & 0x10 ? `, Ack: ${relAck}` : ''}, Len: ${length}`,
      o,
      payloadStart,
      [
        leaf(`Source Port: ${sport}`, o, 2),
        leaf(`Destination Port: ${dport}`, o + 2, 2),
        leaf(`Sequence Number: ${relSeq}    (relative sequence number)`, o + 4, 4),
        leaf(`Sequence Number (raw): ${seq}`, o + 4, 4),
        leaf(`Acknowledgment Number: ${relAck}${flags & 0x10 ? '    (relative ack number)' : ''}`, o + 8, 4),
        leaf(`Header Length: ${headerLength} bytes`, o + 12, 1),
        leaf(`Flags: ${hex(flags, 3)} (${flagNames.join(', ') || 'aucun'})`, o + 12, 2),
        leaf(`Window: ${window}`, o + 14, 2),
        leaf(`Checksum: ${hex(u16(b, o + 16), 4)}`, o + 16, 2),
        leaf(`Urgent Pointer: ${u16(b, o + 18)}`, o + 18, 2),
        ...(headerLength > 20 ? [leaf(`Options: (${headerLength - 20} bytes)`, o + 20, headerLength - 20)] : []),
      ],
    ),
  );
  if (length > 0) dissectApplication(b, payloadStart, end, sport, dport, 'tcp', p);
}

function dissectUdp(b, o, end, p) {
  if (end < o + 8) return;
  const sport = u16(b, o);
  const dport = u16(b, o + 2);
  const length = u16(b, o + 4);
  p.add('udp', true);
  p.add('udp.srcport', sport);
  p.add('udp.dstport', dport);
  p.add('udp.port', sport, dport);
  p.protocol = 'UDP';
  p.info = `${sport} → ${dport} Len=${length - 8}`;
  p.tree.push(
    node('udp', `User Datagram Protocol, Src Port: ${sport}, Dst Port: ${dport}`, o, o + 8, [
      leaf(`Source Port: ${sport}`, o, 2),
      leaf(`Destination Port: ${dport}`, o + 2, 2),
      leaf(`Length: ${length}`, o + 4, 2),
      leaf(`Checksum: ${hex(u16(b, o + 6), 4)}`, o + 6, 2),
    ]),
  );
  const payloadEnd = Math.min(end, o + length);
  if (payloadEnd > o + 8) dissectApplication(b, o + 8, payloadEnd, sport, dport, 'udp', p);
}

// ---------------------------------------------------------------- applications

function dissectApplication(b, o, end, sport, dport, transport, p) {
  const payload = b.subarray(o, end);
  const has = (port) => sport === port || dport === port;

  if (has(53) && transport === 'udp' && dissectDns(b, o, end, p)) return;
  if ((HTTP_PORTS.has(sport) || HTTP_PORTS.has(dport) || HTTP_START.test(firstLine(payload))) && dissectHttp(b, o, end, p)) return;
  if (transport === 'tcp' && dissectTls(b, o, end, p)) return;
  if (ascii(payload.subarray(0, 4)) === 'SSH-' || has(22)) {
    dissectSsh(b, o, end, sport, p);
    return;
  }
  const textPort = [sport, dport].find((port) => TEXT_PROTOCOLS[port]);
  if (textPort && transport === 'tcp') {
    dissectText(b, o, end, TEXT_PROTOCOLS[textPort], sport === textPort, p);
    return;
  }
  p.add('data', true);
  p.tree.push(node('data', `Data (${end - o} bytes)`, o, end, [leaf(`Data: ${previewHex(payload)}`, o, end - o)]));
}

function previewHex(bytes) {
  const shown = Array.from(bytes.subarray(0, 24), (x) => x.toString(16).padStart(2, '0')).join('');
  return bytes.length > 24 ? `${shown}…` : shown;
}

function readDnsName(b, start, base) {
  const labels = [];
  let o = start;
  let next = null; // position après le nom (avant de suivre un pointeur de compression)
  for (let guard = 0; guard < 64 && o < b.length; guard += 1) {
    const len = b[o];
    if (len === 0) {
      o += 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (next === null) next = o + 2;
      o = base + (((len & 0x3f) << 8) | b[o + 1]);
      continue;
    }
    labels.push(ascii(b.subarray(o + 1, o + 1 + len)));
    o += 1 + len;
  }
  return { name: labels.join('.') || '<Root>', end: next ?? o };
}

function dissectDns(b, o, end, p) {
  if (end < o + 12) return false;
  const id = u16(b, o);
  const flags = u16(b, o + 2);
  const response = Boolean(flags & 0x8000);
  const rcode = flags & 0x0f;
  const counts = [u16(b, o + 4), u16(b, o + 6), u16(b, o + 8), u16(b, o + 10)];
  const children = [
    leaf(`Transaction ID: ${hex(id, 4)}`, o, 2),
    leaf(`Flags: ${hex(flags, 4)} ${response ? 'Standard query response' : 'Standard query'}${response ? `, ${DNS_RCODES[rcode] ?? `rcode ${rcode}`}` : ''}`, o + 2, 2),
    leaf(`Questions: ${counts[0]}`, o + 4, 2),
    leaf(`Answer RRs: ${counts[1]}`, o + 6, 2),
  ];
  let offset = o + 12;
  const queries = [];
  try {
    for (let i = 0; i < counts[0]; i += 1) {
      const { name, end: after } = readDnsName(b, offset, o);
      const type = u16(b, after);
      queries.push(`${DNS_TYPES[type] ?? type} ${name}`);
      children.push(leaf(`Query: ${name}: type ${DNS_TYPES[type] ?? type}`, offset, after + 4 - offset));
      p.add('dns.qry.name', name);
      offset = after + 4;
    }
    const answers = [];
    for (let i = 0; i < counts[1]; i += 1) {
      const { name, end: after } = readDnsName(b, offset, o);
      const type = u16(b, after);
      const rdLength = u16(b, after + 8);
      const rdata = after + 10;
      let value = `${rdLength} bytes`;
      if (type === 1 && rdLength === 4) value = formatIpv4(b, rdata);
      else if (type === 28 && rdLength === 16) value = formatIpv6(b, rdata);
      else if (type === 5 || type === 12 || type === 2) value = readDnsName(b, rdata, o).name;
      answers.push(`${DNS_TYPES[type] ?? type} ${value}`);
      children.push(leaf(`Answer: ${name}: type ${DNS_TYPES[type] ?? type}, ${value}`, offset, rdata + rdLength - offset));
      offset = rdata + rdLength;
    }
    p.info =
      `Standard query${response ? ' response' : ''} ${hex(id, 4)}` +
      `${response && rcode ? ` ${DNS_RCODES[rcode] ?? ''}` : ''} ${queries.join(' ')}${answers.length ? ` ${answers.join(' ')}` : ''}`;
  } catch {
    p.info = `Standard query${response ? ' response' : ''} ${hex(id, 4)} (malformé)`;
  }
  p.protocol = 'DNS';
  p.add('dns', true);
  p.add('dns.flags.response', response ? 1 : 0);
  p.tree.push(node('dns', `Domain Name System (${response ? 'response' : 'query'})`, o, end, children));
  return true;
}

function dissectHttp(b, o, end, p) {
  const text = ascii(b.subarray(o, Math.min(end, o + 4096)));
  const line = text.split(/\r?\n/)[0];
  if (!HTTP_START.test(line)) {
    if (!p.protocol || p.protocol === 'TCP') {
      p.add('http', true);
      p.protocol = 'HTTP';
      p.info = `Continuation (${end - o} bytes)`;
      p.tree.push(node('http', 'Hypertext Transfer Protocol (suite)', o, end, []));
      return true;
    }
    return false;
  }
  const headerEnd = text.indexOf('\r\n\r\n');
  const head = headerEnd >= 0 ? text.slice(0, headerEnd) : text;
  const children = [];
  let at = o;
  for (const header of head.split('\r\n')) {
    children.push(leaf(header, at, header.length + 2));
    at += header.length + 2;
  }
  if (headerEnd >= 0 && o + headerEnd + 4 < end) {
    const bodyStart = o + headerEnd + 4;
    children.push(leaf(`Corps : ${end - bodyStart} octets`, bodyStart, end - bodyStart));
  }
  const [method, code] = line.split(' ');
  if (line.startsWith('HTTP/')) p.add('http.response.code', Number(code));
  else p.add('http.request.method', method);
  p.add('http', true);
  p.protocol = 'HTTP';
  p.info = line;
  p.tree.push(node('http', 'Hypertext Transfer Protocol', o, end, children));
  return true;
}

function dissectTls(b, o, end, p) {
  if (end < o + 5) return false;
  const type = u8(b, o);
  const version = u16(b, o + 1);
  if (!TLS_CONTENT[type] || !TLS_VERSIONS[version]) return false;
  const records = [];
  const children = [];
  let offset = o;
  while (offset + 5 <= end) {
    const ctype = u8(b, offset);
    const length = u16(b, offset + 3);
    if (!TLS_CONTENT[ctype]) break;
    let label = TLS_CONTENT[ctype];
    if (ctype === 22 && offset + 5 < end) label = TLS_HANDSHAKE[u8(b, offset + 5)] ?? 'Handshake';
    records.push(label);
    children.push(leaf(`${TLS_VERSIONS[version]} Record Layer: ${TLS_CONTENT[ctype]} Protocol: ${label}`, offset, Math.min(5 + length, end - offset)));
    offset += 5 + length;
  }
  p.add('tls', true);
  p.protocol = TLS_VERSIONS[version];
  p.info = [...new Set(records)].join(', ');
  p.tree.push(node('tls', 'Transport Layer Security', o, end, children));
  return true;
}

function dissectSsh(b, o, end, sport, p) {
  const payload = b.subarray(o, end);
  const banner = ascii(payload.subarray(0, 4)) === 'SSH-';
  const side = sport === 22 ? 'Server' : 'Client';
  p.add('ssh', true);
  p.protocol = 'SSH';
  p.info = banner ? `${side}: Protocol (${firstLine(payload)})` : `${side}: Encrypted packet (len=${end - o})`;
  p.tree.push(node('ssh', 'SSH Protocol', o, end, [leaf(banner ? `Protocol: ${firstLine(payload)}` : `Encrypted Packet: ${previewHex(payload)}`, o, end - o)]));
}

function dissectText(b, o, end, protocol, fromServer, p) {
  const payload = b.subarray(o, end);
  const printable = isPrintable(payload);
  const line = printable ? firstLine(payload).trim() : '';
  p.add(protocol.toLowerCase(), true);
  p.protocol = protocol;
  p.info = printable ? `${fromServer ? 'Response' : 'Request'}: ${line || '(ligne vide)'}` : `${fromServer ? 'Response' : 'Request'} (${end - o} bytes)`;
  const lines = printable ? ascii(payload).split(/\r?\n/).filter(Boolean) : [];
  p.tree.push(
    node(
      protocol.toLowerCase(),
      protocol === 'TELNET' ? 'Telnet' : `${protocol} protocol`,
      o,
      end,
      lines.length ? lines.map((l) => leaf(l, o, end - o)) : [leaf(`Data: ${previewHex(payload)}`, o, end - o)],
    ),
  );
}

// ---------------------------------------------------------------- point d'entrée

/** Crée un décodeur pour une capture (garde l'état nécessaire aux numéros TCP relatifs). */
export function createDissector() {
  const ctx = { tcpBase: new Map() };
  return function dissect(bytes) {
    const p = {
      src: '',
      dst: '',
      protocol: '',
      info: '',
      tree: [],
      fields: {},
      ctx,
      add(name, ...values) {
        (this.fields[name] ??= []).push(...values);
      },
    };
    p.add('frame.len', bytes.length);
    try {
      dissectEthernet(bytes, p);
    } catch {
      p.info = p.info || 'Paquet malformé';
    }
    const { ctx: _ctx, add: _add, ttl: _ttl, ...result } = p;
    return result;
  };
}

/**
 * Couleur de la ligne, d'après les règles de coloration par défaut de Wireshark.
 * Retourne une classe CSS (voir app.css, .capture-row--*).
 */
export function colorRule(packet) {
  const f = packet.fields;
  if (f['tcp.flags.reset']?.[0]) return 'reset';
  if (f.tcp && (f['tcp.flags.syn']?.[0] || f['tcp.flags.fin']?.[0])) return 'syn-fin';
  if (f.icmp && [3, 4, 5, 11].includes(f['icmp.type']?.[0])) return 'icmp-error';
  if (f.http) return 'http';
  if (f.arp) return 'arp';
  if (f.icmp || f.icmpv6) return 'icmp';
  if (f.tcp) return 'tcp';
  if (f.udp) return 'udp';
  return 'other';
}
