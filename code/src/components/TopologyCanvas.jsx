import { useCallback, useMemo } from 'react';
import { ReactFlow, Background, Controls, MiniMap, useReactFlow } from '@xyflow/react';
import DeviceNode from './DeviceNode.jsx';
import { DEVICE_TYPES, DND_MIME_TYPE, NODE_ORIGIN, NODE_ICON_CENTER_Y } from '../config/deviceTypes.js';

// Déclaré hors du composant : React Flow exige une référence stable
const nodeTypes = { device: DeviceNode };

// Style par défaut des câbles : lignes droites de centre à centre
const defaultEdgeOptions = { type: 'straight', className: 'cable' };

// Vue initiale du canvas (vide au démarrage, donc pas de fitView)
const defaultViewport = { x: 0, y: 0, zoom: 1.5 };

/**
 * Zone de travail React Flow.
 * Gère : le dépôt d'équipements depuis la palette, le déplacement,
 * la sélection, et transmet les clics sur les nœuds à l'outil câble.
 */
export default function TopologyCanvas({
  nodes,
  edges,
  onNodesChange,
  onEdgesChange,
  onAddDevice,
  cableTool,
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

  const onNodeClick = useCallback((_event, node) => cableTool.handleNodeClick(node.id), [cableTool]);

  // Met en surbrillance l'extrémité de départ du câble en cours de création
  const displayedNodes = useMemo(
    () =>
      cableTool.sourceId
        ? nodes.map((n) => (n.id === cableTool.sourceId ? { ...n, className: 'cable-source' } : n))
        : nodes,
    [nodes, cableTool.sourceId],
  );

  return (
    <div className={`canvas${cableTool.isActive ? ' canvas--cable-mode' : ''}`}>
      <ReactFlow
        nodes={displayedNodes}
        edges={edges}
        nodeTypes={nodeTypes}
        nodeOrigin={NODE_ORIGIN}
        defaultViewport={defaultViewport}
        defaultEdgeOptions={defaultEdgeOptions}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        onPaneClick={cableTool.cancel}
        onDragOver={onDragOver}
        onDrop={onDrop}
        nodesDraggable={!cableTool.isActive} // évite les déplacements involontaires pendant le câblage
        nodesConnectable={false} // les liens se créent uniquement via l'outil câble
        deleteKeyCode={['Delete', 'Backspace']}
        proOptions={{ hideAttribution: true }}
      >
        <Background gap={20} />
        <Controls />
        <MiniMap position="top-right" pannable zoomable nodeColor={(n) => DEVICE_TYPES[n.data.deviceType]?.color ?? '#999'} />
      </ReactFlow>

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
