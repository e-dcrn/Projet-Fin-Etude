import { useEffect, useRef, useState } from 'react';
import { ReactFlow, Background, Controls } from '@xyflow/react';
import DeviceNode from './DeviceNode.jsx';
import TerminalPopup from './TerminalPopup.jsx';

// Déclaré hors du composant : React Flow exige une référence stable
const nodeTypes = { device: DeviceNode };

/** Lignes affichées sous le nom d'un équipement : son réseau (switch) ou ses adresses IP. */
function linesOf(topology, node) {
  if (node.type === 'switch') return [node.subnet];
  return topology.links.filter((l) => l.node === node.id).map((l) => l.ip);
}

/**
 * Schéma de la topologie (en lecture seule) : les équipements et les câbles.
 * `onlineIds` : identifiants des équipements allumés.
 *
 * Un clic sur un équipement (hors switch) ouvre une petite popup avec la commande
 * `docker exec` pour ouvrir un terminal dessus.
 */
export default function TopologyCanvas({ topology, onlineIds }) {
  const [selected, setSelected] = useState(null); // équipement cliqué, pour la popup terminal
  const flowRef = useRef(null);  // instance React Flow (pour recadrer)
  const wrapRef = useRef(null);  // conteneur, observé pour recadrer à chaque redimensionnement

  // Recentre la topologie quand le canvas change de taille (ex. ouverture d'un
  // panneau latéral) pour qu'elle ne finisse jamais cachée hors du cadre.
  useEffect(() => {
    const el = wrapRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return undefined;
    const observer = new ResizeObserver(() => flowRef.current?.fitView({ padding: 0.15 }));
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const nodes = topology.nodes.map((n) => ({
    id: n.id,
    type: 'device',
    position: { x: n.x, y: n.y },
    data: {
      type: n.type,
      name: n.name,
      lines: linesOf(topology, n),
      online: onlineIds.has(n.id),
    },
  }));
  const edges = topology.links.map((l) => ({
    id: `${l.node}-${l.switch}`,
    source: l.node,
    target: l.switch,
    type: 'straight',
    className: 'cable',
  }));

  // Un switch n'est pas un conteneur : pas de terminal à ouvrir dessus.
  const onNodeClick = (_event, node) => {
    const device = topology.nodes.find((n) => n.id === node.id);
    if (device && device.type !== 'switch') setSelected(device);
  };

  return (
    <div className="canvas" ref={wrapRef}>
      <ReactFlow
        key={topology.id} // nouvelle topologie : on recadre la vue
        onInit={(instance) => { flowRef.current = instance; }}
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        nodeOrigin={[0.5, 0]}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        onNodeClick={onNodeClick}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        minZoom={0.3}
        // On peut déplacer la topologie au glissement, mais on désactive le zoom à la
        // molette / au pincement / au double-clic : c'est lui qui la réduisait en un point
        // (« disparition »). Le zoom reste possible via les boutons +/- et le recentrage.
        zoomOnScroll={false}
        zoomOnPinch={false}
        zoomOnDoubleClick={false}
        preventScrolling={false}  // laisse la page défiler normalement
        proOptions={{ hideAttribution: true }}
      >
        <Background gap={20} />
        <Controls showInteractive={false} />
      </ReactFlow>

      {selected && <TerminalPopup device={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
