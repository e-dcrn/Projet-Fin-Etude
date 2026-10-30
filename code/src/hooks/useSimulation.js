import { useCallback, useEffect, useRef, useState } from 'react';
import { simulationUrl } from '../services/topologyApi.js';
import { deviceIp } from '../utils/trafficTargets.js';
import { broadcastHosts, findPath, nodeCenter } from '../utils/trafficPaths.js';

/**
 * Visualisation « à la Packet Tracer » : chaque paquet réellement émis sur le
 * réseau (reçu par WebSocket depuis backend/app/simulation.py) devient une boule
 * qui parcourt son chemin source → destination (animation pilotée en JS dans
 * SimulationLayer, le long des points du tracé). Tout est à vitesse réelle (×1).
 *
 * Lecture SÉQUENCÉE pour rester lisible : les paquets IP sont joués l'un après
 * l'autre (une requête traverse entièrement, PUIS la réponse repart). Un ping =
 * UNE boule, déclenchée par l'echo request (elle part donc toujours de
 * l'émetteur et fait l'aller-retour ; l'echo reply est ignoré). Exception : une
 * requête ARP (broadcast) donne PLUSIEURS boules, une vers chaque hôte du segment.
 *
 * Les paquets sont joués dans l'ordre de leur HORODATAGE réel (ts), pas dans leur
 * ordre d'arrivée : la capture se fait par équipement (chacun ne voit que ses
 * départs), donc les deux sens arrivent en lots séparés. On les refusionne par ts
 * pour retrouver l'alternance réelle (SYN →, SYN-ACK ←, ACK →…), comme dans un
 * pcap pris sur le câble. Un court délai de garde laisse les paquets quasi
 * simultanés des deux hôtes se ranger avant de jouer le plus ancien.
 *
 * DÉBIT ADAPTATIF pour ne jamais accumuler de retard : trafic calme = une boule
 * posée à la fois (lisible, ~0,7 s l'aller-retour d'un ping, en phase avec un
 * ping par seconde) ; rafale (un curl ≈ 10 paquets, un scan des centaines) =
 * plusieurs boules en vol et départs groupés, pour rattraper. Au-delà de la file,
 * on garde les paquets les plus RÉCENTS (on reste « en direct »).
 */

const MAX_QUEUE = 64;   // profondeur de la file ; au-delà, on lâche les plus anciens (reste en direct)
const MAX_BALLS = 80;
const HOLD_MS = 160;    // délai de garde avant de jouer le plus ancien paquet (ré-ordonnancement)

// Durée d'UN trajet simple d'une boule (un aller-retour = × 2, voir makeBall).
const ONEWAY_MS = 340;

// Débit adaptatif selon la longueur de la file (voir plus haut).
const BURST_LEN = 6;            // au-delà : mode « rafale »
const BURST_CONCURRENT = 16;    // boules IP simultanées autorisées en rafale (1 sinon)
const BURST_PER_TICK = 6;       // départs max par tour en rafale (1 sinon)

const PROTO_CLASS = { tcp: 'tcp', icmp: 'icmp', udp: 'udp', arp: 'arp' };

export function useSimulation(active, nodes, edges) {
  const [balls, setBalls] = useState([]);

  const queue = useRef([]);
  const inFlight = useRef(0);            // boules IP en vol (limite de simultanéité)
  const idRef = useRef(0);
  const pendingArp = useRef(new Map());  // IP interrogée → IP du demandeur (pour la réponse ARP)
  const topoRef = useRef({ nodes, edges, byId: new Map(), ipToId: {} });

  // Index topologie (IP → nœud, id → nœud) recalculé à chaque changement.
  useEffect(() => {
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const ipToId = {};
    for (const n of nodes) {
      const ip = deviceIp(edges, n.id);
      if (ip) ipToId[ip] = n.id;
    }
    topoRef.current = { nodes, edges, byId, ipToId };
  }, [nodes, edges]);

  // Crée une boule le long du chemin srcId → dstId, ou null si non routable.
  // roundTrip : la boule va jusqu'au bout PUIS revient (un ping = un aller-retour,
  // une seule boule, qui part toujours de l'émetteur de la requête).
  const makeBall = useCallback((srcId, dstId, proto, roundTrip = false) => {
    const { nodes: ns, edges: es, byId } = topoRef.current;
    if (!srcId || !dstId || srcId === dstId) return null;
    const path = findPath(ns, es, srcId, dstId);
    if (!path || path.length < 2) return null;
    let points = path.map((id) => nodeCenter(byId.get(id)));
    let durMs = ONEWAY_MS;
    if (roundTrip) {
      points = [...points, ...points.slice(0, -1).reverse()];  // aller puis retour
      durMs *= 2;
    }
    return { id: (idRef.current += 1), points, proto, durMs };
  }, []);

  // Ajoute une boule et programme son retrait. `gated` : compte dans la limite de
  // boules IP simultanées (les boules ARP, par nature multiples, ne le sont pas).
  const addBall = useCallback((ball, gated) => {
    if (gated) inFlight.current += 1;
    setBalls((bs) => {
      const next = [...bs, ball];
      return next.length > MAX_BALLS ? next.slice(next.length - MAX_BALLS) : next;
    });
    setTimeout(() => {
      if (gated) inFlight.current = Math.max(0, inFlight.current - 1);
      setBalls((bs) => bs.filter((b) => b.id !== ball.id));
    }, ball.durMs + 50);
  }, []);

  // Un paquet IP → une boule (gérée par la limite). true si une boule a été créée.
  const releaseIp = useCallback((packet) => {
    const { ipToId } = topoRef.current;
    const roundTrip = packet.proto === 'icmp' && packet.icmp === 'request';
    const proto = PROTO_CLASS[packet.proto] ?? 'other';
    const ball = makeBall(ipToId[packet.src], ipToId[packet.dst], proto, roundTrip);
    if (!ball) return false;
    addBall(ball, true);
    return true;
  }, [makeBall, addBall]);

  // Un paquet ARP → plusieurs boules (requête : vers tout le segment) ou une
  // (réponse : vers le demandeur retrouvé), hors limite de simultanéité.
  const releaseArp = useCallback((packet) => {
    const { nodes: ns, edges: es, ipToId } = topoRef.current;
    const senderId = ipToId[packet.sender];
    if (!senderId) return;
    if (packet.arp === 'request') {
      for (const hostId of broadcastHosts(ns, es, senderId)) {
        const ball = makeBall(senderId, hostId, 'arp');
        if (ball) addBall(ball, false);
      }
    } else {
      const requester = pendingArp.current.get(packet.sender);
      const ball = requester && makeBall(senderId, ipToId[requester], 'arp');
      if (ball) addBall(ball, false);
    }
  }, [makeBall, addBall]);

  // WebSocket : empile les paquets récents (file courte pour rester en direct).
  useEffect(() => {
    if (!active) {
      queue.current = [];
      inFlight.current = 0;
      pendingArp.current.clear();
      setBalls([]);
      return undefined;
    }
    let closed = false;
    let retry = null;
    let socket = null;

    const connect = () => {
      socket = new WebSocket(simulationUrl());
      socket.onmessage = (event) => {
        const message = JSON.parse(event.data);
        if (message.type !== 'packet') return;
        if (message.proto === 'arp' && message.arp === 'request') {
          pendingArp.current.set(message.target, message.sender);  // qui demande quoi
        }
        message.recvAt = performance.now();  // pour le délai de garde du ré-ordonnancement
        const q = queue.current;
        q.push(message);
        if (q.length > MAX_QUEUE) q.splice(0, q.length - MAX_QUEUE);
      };
      socket.onclose = () => {
        if (!closed) retry = setTimeout(connect, 1500);
      };
      socket.onerror = () => socket.close();
    };
    connect();

    return () => {
      closed = true;
      clearTimeout(retry);
      socket?.close();
    };
  }, [active]);

  // Horloge d'affichage : libère les paquets de la file en boules animées.
  useEffect(() => {
    if (!active) return undefined;
    const timer = setInterval(() => {
      const q = queue.current;
      if (q.length === 0) return;
      q.sort((a, b) => a.ts - b.ts);  // ordre chronologique réel (fusionne les deux captures)
      const now = performance.now();
      // Débit adaptatif : file longue → mode rafale (plusieurs boules, départs groupés).
      const burst = q.length > BURST_LEN;
      const maxConcurrent = burst ? BURST_CONCURRENT : 1;
      let budget = burst ? BURST_PER_TICK : 1;
      while (q.length && budget > 0) {
        // On attend que les paquets quasi simultanés soient tous arrivés avant de
        // jouer le plus ancien, pour respecter l'alternance aller/retour.
        if (now - q[0].recvAt < HOLD_MS) break;
        if (q[0].proto === 'arp') {
          releaseArp(q.shift());  // déjà multi-boules : n'entame pas le budget
          continue;
        }
        if (q[0].proto === 'icmp' && q[0].icmp === 'reply') {  // ignoré : montré par l'aller-retour
          q.shift();
          continue;
        }
        if (inFlight.current < maxConcurrent) {
          if (releaseIp(q.shift())) budget -= 1;
        } else {
          break;
        }
      }
    }, 40);
    return () => clearInterval(timer);
  }, [active, releaseIp, releaseArp]);

  return { balls };
}
