import { useCallback, useMemo } from 'react';
import { ReactFlow, Background, Controls, MiniMap, useReactFlow } from '@xyflow/react';
import DeviceNode from './DeviceNode.jsx';
import CableEdge from './CableEdge.jsx';
import SimulationLayer from './SimulationLayer.jsx';
import SimulationControls from './SimulationControls.jsx';
import { DEVICE_TYPES, DND_MIME_TYPE, NODE_ORIGIN, NODE_ICON_CENTER_Y } from '../config/deviceTypes.js';
import { formatInterface } from '../utils/ipv4.js';
import { deviceLinks } from '../utils/topologyQueries.js';

// Déclaré hors du composant : React Flow exige une référence stable
const nodeTypes = { device: DeviceNode };
const edgeTypes = { cable: CableEdge };

// Câbles : lignes droites de centre à centre, une étiquette à chaque extrémité
// (interface de l'équipement, port du switch : voir CableEdge)
const defaultEdgeOptions = { type: 'cable', className: 'cable' };

// Vue initiale du canvas (vide au démarrage, donc pas de fitView)
const defaultViewport = { x: 0, y: 0, zoom: 1.5 };

/** Lignes affichées sous le nom d'un équipement. */
function summarize(node, edges) {
  const { deviceType, properties } = node.data;
  if (deviceType === 'switch') {
    // Le réseau des équipements branchés sur le switch (un switch n'a pas d'adresse IP)
    return [properties.subnet && `réseau ${properties.subnet}`, properties.vlan && `VLAN ${properties.vlan}`].filter(Boolean);
  }
  const links = deviceLinks(edges, node.id);
  if (deviceType === 'router') {
    return links.length ? [`${links.length} interface${links.length > 1 ? 's' : ''}`] : [];
  }
  const addresses = links.filter((l) => l.data.ip).map((l) => formatInterface(l.data.ip, l.data.mask));
  return addresses.length > 2 ? [addresses[0], `+${addresses.length - 1} autres`] : addresses;
}

/**
 * Zone de travail React Flow.
 * Gère : le dépôt d'équipements depuis la palette, le déplacement,
 * la sélection, et transmet les clics sur les nœuds à l'outil câble.
 * Hors mode câble, un clic sur un PC ou un serveur allumé ouvre son terminal,
 * et un double-clic sur un câble dont l'équipement est allumé ouvre sa capture.
 */
export default function TopologyCanvas({
  nodes,
  edges,
  onNodesChange,
  onEdgesChange,
  onAddDevice,
  cableTool,
  onlineNodeIds,
  onOpenTerminal,
  onOpenCapture,
  capturedEdgeIds,
  balls = [],
  simActive = false,
}) {
  const { screenToFlowPosition } = useReactFlow();

  // Autorise le dépôt (sinon le navigateur refuse le drop)
  const onDragOver = useCallback((event) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
  }, []);

  // Dépôt d'un équipement : conversion des coordonnées écran → coordonnées du canvas
  const onDrop = useCallback(
    (event) => {
      event.preventDefault();
      const deviceType = event.dataTransfer.getData(DND_MIME_TYPE);
      if (!DEVICE_TYPES[deviceType]) return;

      const position = screenToFlowPosition({ x: event.clientX, y: event.clientY });
      onAddDevice(deviceType, { x: position.x, y: position.y - NODE_ICON_CENTER_Y });
    },
    [screenToFlowPosition, onAddDevice],
  );

  const onNodeClick = useCallback(
    (_event, node) => {
      if (cableTool.isActive) cableTool.handleNodeClick(node.id);
      else if (DEVICE_TYPES[node.data.deviceType].hasTerminal && onlineNodeIds.has(node.id)) onOpenTerminal(node.id);
    },
    [cableTool, onlineNodeIds, onOpenTerminal],
  );

  // Ajoute aux nœuds les informations dérivées (résumé, état) et met en surbrillance
  // l'extrémité de départ du câble en cours de création
  const displayedNodes = useMemo(
    () =>
      nodes.map((n) => ({
        ...n,
        className: n.id === cableTool.sourceId ? 'cable-source' : undefined,
        data: { ...n.data, summary: summarize(n, edges), online: onlineNodeIds.has(n.id) },
      })),
    [nodes, edges, cableTool.sourceId, onlineNodeIds],
  );

  const onEdgeDoubleClick = useCallback(
    (_event, edge) => {
      if (onlineNodeIds.has(edge.source)) onOpenCapture(edge.id);
    },
    [onlineNodeIds, onOpenCapture],
  );

  // Câbles dont le trafic est en cours de capture : animés (pastille).
  const displayedEdges = useMemo(
    () => edges.map((e) => (capturedEdgeIds.has(e.id) ? { ...e, className: 'cable cable--captured' } : e)),
    [edges, capturedEdgeIds],
  );

  return (
    <div className={`canvas${cableTool.isActive ? ' canvas--cable-mode' : ''}`}>
      <ReactFlow
        nodes={displayedNodes}
        edges={displayedEdges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        nodeOrigin={NODE_ORIGIN}
        defaultViewport={defaultViewport}
        defaultEdgeOptions={defaultEdgeOptions}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        onEdgeDoubleClick={onEdgeDoubleClick}
        onPaneClick={cableTool.cancel}
        onDragOver={onDragOver}
        onDrop={onDrop}
        nodesDraggable={!cableTool.isActive} // évite les déplacements involontaires pendant le câblage
        nodesConnectable={false} // les liens se créent uniquement via l'outil câble
        deleteKeyCode={['Delete', 'Backspace']}
        proOptions={{ hideAttribution: true }}
      >
        <SimulationLayer balls={balls} />
        <Background gap={20} />
        <Controls />
        <MiniMap position="top-right" pannable zoomable nodeColor={(n) => DEVICE_TYPES[n.data.deviceType]?.color ?? '#999'} />
      </ReactFlow>

      {simActive && <SimulationControls />}

      {cableTool.isActive && (
        <div className="canvas__banner">
          {cableTool.sourceId
            ? 'Cliquez sur le second équipement (Échap pour annuler)'
            : 'Mode câble : cliquez sur un premier équipement'}
        </div>
      )}
    </div>
  );
}
