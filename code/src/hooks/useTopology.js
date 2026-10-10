import { useCallback, useRef } from 'react';
import { useNodesState, useEdgesState, useReactFlow } from '@xyflow/react';
import { DEVICE_TYPES } from '../config/deviceTypes.js';

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
 *     data: { deviceType: 'pc', properties: { name, ip } } }
 */
export function useTopology() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const { deleteElements } = useReactFlow();

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

      const newNode = {
        id: `${deviceType}-${index}`,
        type: 'device', // correspond au composant DeviceNode enregistré dans nodeTypes
        position,
        data: {
          deviceType,
          properties: {
            name: `${definition.namePrefix}-${index}`,
            ip: '',
          },
        },
      };

      setNodes((nds) => nds.concat(newNode));
      return newNode.id;
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
   * Crée un lien (câble) entre deux équipements.
   * Refuse les boucles sur soi-même et les doublons (dans un sens ou dans l'autre).
   * Retourne true si le lien a été créé.
   */
  const connectDevices = useCallback(
    (sourceId, targetId) => {
      if (!sourceId || !targetId || sourceId === targetId) return false;

      // Les deux extrémités doivent toujours exister (l'une a pu être supprimée entre-temps)
      const exists = (id) => nodes.some((n) => n.id === id);
      if (!exists(sourceId) || !exists(targetId)) return false;

      const alreadyLinked = edges.some(
        (e) =>
          (e.source === sourceId && e.target === targetId) ||
          (e.source === targetId && e.target === sourceId),
      );
      if (alreadyLinked) return false;

      setEdges((eds) =>
        eds.concat({
          id: `link-${sourceId}-${targetId}`,
          source: sourceId,
          target: targetId,
        }),
      );
      return true;
    },
    [nodes, edges, setEdges],
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

  return {
    nodes,
    edges,
    onNodesChange,
    onEdgesChange,
    addDevice,
    updateDeviceProperties,
    connectDevices,
    deleteDevice,
    deleteLink,
    clearTopology,
  };
}
