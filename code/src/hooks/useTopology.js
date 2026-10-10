import { useCallback, useEffect, useRef } from 'react';
import { useNodesState, useEdgesState, useReactFlow } from '@xyflow/react';
import { DEVICE_TYPES, isNetworkType } from '../config/deviceTypes.js';
import { nextSubnet, planIpam } from '../utils/ipam.js';

/**
 * Hook central qui détient l'état de la topologie (nœuds + liens)
 * et expose toutes les actions métier.
 *
 * Les composants d'UI ne manipulent jamais directement setNodes/setEdges :
 * ils passent par ces actions. Le jour où l'état devra être synchronisé avec
 * un backend, c'est ici (et uniquement ici) qu'il faudra intervenir.
 *
 * Format d'un nœud React Flow :
 *   { id, type: 'device', position: {x, y},
 *     data: { deviceType: 'router', properties: { name, ...defaultProperties } } }
 *
 * Format d'un lien (câble) : il relie TOUJOURS un équipement (source) à un
 * switch (target) et porte la configuration de l'interface de l'équipement :
 *   { id, source: 'router-1', target: 'switch-1',
 *     data: { interface: 'eth0', port: 'Fa0/1', ip: '10.0.1.1', mask: '255.255.255.0', auto: true } }
 *   `interface` : interface de l'équipement ; `port` : port du switch où le câble est branché.
 *
 * Adressage : un switch reçoit un réseau libre à sa création, et l'IPAM
 * (utils/ipam.js) tient à jour les adresses et passerelles en mode automatique
 * après chaque modification de la topologie.
 */
export function useTopology() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const { deleteElements, fitBounds, getNodesBounds } = useReactFlow();

  // Compteur par type, pour générer des identifiants et noms lisibles (pc-1, PC-1…).
  // Il n'est jamais décrémenté : un identifiant supprimé n'est donc jamais réutilisé.
  const counters = useRef({});

  /** Ajoute un équipement du type donné à la position donnée (coordonnées du canvas). */
  const addDevice = useCallback(
    (deviceType, position) => {
      const definition = DEVICE_TYPES[deviceType];
      if (!definition) {
        console.warn(`Type d'équipement inconnu : ${deviceType}`);
        return null;
      }

      const index = (counters.current[deviceType] ?? 0) + 1;
      counters.current[deviceType] = index;

      const id = `${deviceType}-${index}`;
      setNodes((nds) => {
        const properties = { name: `${definition.namePrefix}-${index}`, ...definition.defaultProperties() };
        if (definition.isNetwork) properties.subnet = nextSubnet(nds);
        // type 'device' : correspond au composant DeviceNode enregistré dans nodeTypes
        return nds.concat({ id, type: 'device', position, data: { deviceType, properties } });
      });
      return id;
    },
    [setNodes],
  );

  /** Met à jour partiellement les propriétés d'un équipement. */
  const updateDeviceProperties = useCallback(
    (nodeId, patch) => {
      setNodes((nds) =>
        nds.map((node) =>
          node.id === nodeId
            ? {
                ...node,
                data: {
                  ...node.data,
                  properties: { ...node.data.properties, ...patch },
                },
              }
            : node,
        ),
      );
    },
    [setNodes],
  );

  /**
   * Crée un câble entre deux équipements, dans n'importe quel ordre de clic.
   * L'une des extrémités doit être un switch, l'autre non : le câble devient
   * une interface de l'équipement (eth0, puis eth1…).
   * Retourne null si le câble a été créé, sinon un message expliquant le refus.
   */
  const connectDevices = useCallback(
    (firstId, secondId) => {
      if (!firstId || !secondId || firstId === secondId) return null;

      // Les deux extrémités doivent toujours exister (l'une a pu être supprimée entre-temps)
      const first = nodes.find((n) => n.id === firstId);
      const second = nodes.find((n) => n.id === secondId);
      if (!first || !second) return null;

      const firstIsNetwork = isNetworkType(first.data.deviceType);
      const secondIsNetwork = isNetworkType(second.data.deviceType);
      if (firstIsNetwork && secondIsNetwork) return 'Deux switches ne peuvent pas être reliés entre eux : chaque switch est un réseau distinct, reliez-les par un routeur.';
      if (!firstIsNetwork && !secondIsNetwork) return 'Un équipement se relie à un switch : placez un switch entre les deux.';

      const device = firstIsNetwork ? second : first;
      const network = firstIsNetwork ? first : second;
      const deviceLinks = edges.filter((e) => e.source === device.id);
      if (deviceLinks.some((e) => e.target === network.id)) {
        return `${device.data.properties.name} est déjà relié à ${network.data.properties.name}.`;
      }

      setEdges((eds) =>
        eds.concat({
          id: `link-${device.id}-${network.id}`,
          source: device.id,
          target: network.id,
          data: {
            interface: nextInterfaceName(deviceLinks),
            port: nextPortName(edges.filter((e) => e.target === network.id)),
            ip: '', // adressé par l'IPAM
            mask: '',
            auto: true,
          },
        }),
      );

      // Une sonde surveille par défaut le premier switch auquel on la relie
      if (device.data.deviceType === 'ids' && !device.data.properties.monitoredSegment) {
        updateDeviceProperties(device.id, { monitoredSegment: network.id });
      }
      return null;
    },
    [nodes, edges, setEdges, updateDeviceProperties],
  );

  /**
   * Met à jour la configuration d'interface portée par un câble.
   * Renommer une interface de routeur met aussi à jour les routes qui l'utilisent.
   */
  const updateLink = useCallback(
    (edgeId, patch) => {
      const edge = edges.find((e) => e.id === edgeId);
      if (!edge) return;

      setEdges((eds) => eds.map((e) => (e.id === edgeId ? { ...e, data: { ...e.data, ...patch } } : e)));

      const renamedFrom = edge.data.interface;
      if (patch.interface === undefined || patch.interface === renamedFrom) return;
      setNodes((nds) =>
        nds.map((node) => {
          if (node.id !== edge.source || !node.data.properties.routes) return node;
          const routes = node.data.properties.routes.map((r) =>
            r.interface === renamedFrom ? { ...r, interface: patch.interface } : r,
          );
          return { ...node, data: { ...node.data, properties: { ...node.data.properties, routes } } };
        }),
      );
    },
    [edges, setEdges, setNodes],
  );

  /** Supprime un équipement ainsi que tous les câbles qui y sont reliés. */
  const deleteDevice = useCallback(
    (nodeId) => deleteElements({ nodes: [{ id: nodeId }] }),
    [deleteElements],
  );

  /** Supprime un câble. */
  const deleteLink = useCallback(
    (edgeId) => deleteElements({ edges: [{ id: edgeId }] }),
    [deleteElements],
  );

  /** Vide entièrement le canvas. */
  const clearTopology = useCallback(() => {
    setNodes([]);
    setEdges([]);
    counters.current = {};
  }, [setNodes, setEdges]);

  /**
   * Remplace tout le canvas par une topologie (nœuds et câbles au format React Flow,
   * voir deserializeTopology) et cadre la vue dessus.
   */
  const loadTopology = useCallback(
    (loaded) => {
      setNodes(loaded.nodes);
      setEdges(loaded.edges);
      counters.current = countersFor(loaded.nodes);
      pendingFit.current = true;
    },
    [setNodes, setEdges],
  );

  // Cadrage de la vue sur une topologie chargée, une fois tous ses nœuds mesurés
  // (avant, React Flow ne connaît pas leur taille et cadrerait mal)
  const pendingFit = useRef(false);
  useEffect(() => {
    if (!pendingFit.current || !nodes.length || !nodes.every((n) => n.measured?.width)) return;
    pendingFit.current = false;
    // fitBounds plutôt que fitView : appliqué tout de suite, sans dépendre de la file
    // interne de React Flow (où un fitView peut rester en attente indéfiniment)
    fitBounds(getNodesBounds(nodes), { padding: 0.15, duration: 300 });
  }, [nodes, fitBounds, getNodesBounds]);

  // IPAM : après chaque modification (câble, suppression, réseau d'un switch…),
  // adresse les interfaces automatiques et recalcule les passerelles automatiques.
  // planIpam est idempotent : une fois les corrections appliquées, il n'en propose plus.
  useEffect(() => {
    const { links, gateways } = planIpam(nodes, edges);
    if (links.size) {
      setEdges((eds) => eds.map((e) => (links.has(e.id) ? { ...e, data: { ...e.data, ...links.get(e.id) } } : e)));
    }
    if (gateways.size) {
      setNodes((nds) =>
        nds.map((n) =>
          gateways.has(n.id)
            ? { ...n, data: { ...n.data, properties: { ...n.data.properties, gateway: gateways.get(n.id) } } }
            : n,
        ),
      );
    }
  }, [nodes, edges, setNodes, setEdges]);

  return {
    nodes,
    edges,
    onNodesChange,
    onEdgesChange,
    addDevice,
    updateDeviceProperties,
    connectDevices,
    updateLink,
    deleteDevice,
    deleteLink,
    clearTopology,
    loadTopology,
  };
}

/**
 * Compteurs repris d'une topologie chargée : les équipements ajoutés ensuite ne
 * doivent réutiliser ni un identifiant (pc-3) ni un nom généré (PC-3) existant.
 */
function countersFor(nodes) {
  const counters = {};
  for (const { id, data } of nodes) {
    const { deviceType, properties } = data;
    const prefixes = [[deviceType, id], [DEVICE_TYPES[deviceType].namePrefix, properties.name]];
    for (const [prefix, value] of prefixes) {
      const match = new RegExp(`^${prefix}-(\\d+)$`).exec(value ?? '');
      if (match) counters[deviceType] = Math.max(counters[deviceType] ?? 0, Number(match[1]));
    }
  }
  return counters;
}

/** Premier port Fa0/N libre du switch (nommage des switches Cisco, comme dans Packet Tracer). */
function nextPortName(switchLinks) {
  const used = new Set(switchLinks.map((e) => e.data.port));
  let index = 1;
  while (used.has(`Fa0/${index}`)) index += 1;
  return `Fa0/${index}`;
}

/** Premier nom ethN libre parmi les interfaces existantes de l'équipement. */
function nextInterfaceName(deviceLinks) {
  const used = new Set(deviceLinks.map((e) => e.data.interface));
  let index = 0;
  while (used.has(`eth${index}`)) index += 1;
  return `eth${index}`;
}
