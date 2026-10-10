/**
 * Fichier .pcap (format libpcap classique, Ethernet) à partir des paquets capturés :
 * s'ouvre dans le vrai Wireshark.
 *
 * @param packets [{ sec, usec, origLen, bytes: Uint8Array }]
 * @returns {Blob}
 */
export function buildPcap(packets) {
  const header = new DataView(new ArrayBuffer(24));
  header.setUint32(0, 0xa1b2c3d4, true); // nombre magique (microsecondes, little-endian)
  header.setUint16(4, 2, true); // version 2.4
  header.setUint16(6, 4, true);
  header.setUint32(16, 262144, true); // longueur maximale capturée
  header.setUint32(20, 1, true); // type de lien : Ethernet

  const parts = [header.buffer];
  for (const p of packets) {
    const record = new DataView(new ArrayBuffer(16));
    record.setUint32(0, p.sec, true);
    record.setUint32(4, p.usec, true);
    record.setUint32(8, p.bytes.length, true);
    record.setUint32(12, p.origLen, true);
    parts.push(record.buffer, p.bytes);
  }
  return new Blob(parts, { type: 'application/vnd.tcpdump.pcap' });
}

/** Découpe un message binaire du serveur (un ou plusieurs paquets, voir backend/app/capture.py). */
export function splitPackets(buffer) {
  const view = new DataView(buffer);
  const packets = [];
  let offset = 0;
  while (offset + 16 <= buffer.byteLength) {
    const captured = view.getUint32(offset + 8, true);
    packets.push({
      sec: view.getUint32(offset, true),
      usec: view.getUint32(offset + 4, true),
      origLen: view.getUint32(offset + 12, true),
      bytes: new Uint8Array(buffer, offset + 16, captured),
    });
    offset += 16 + captured;
  }
  return packets;
}
