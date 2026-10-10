import { useCallback, useEffect, useState } from 'react';
import Toolbar from './Toolbar.jsx';
import Palette from './Palette.jsx';
import TopologyCanvas from './TopologyCanvas.jsx';
import PropertiesPanel from './PropertiesPanel.jsx';
import { useTopology } from '../hooks/useTopology.js';
import { useCableTool } from '../hooks/useCableTool.js';
import { serializeTopology } from '../utils/serializeTopology.js';
import { validateTopology } from '../utils/validators.js';
import { submitTopology } from '../services/topologyApi.js';

/**
 * Composant d'assemblage : relie l'état (hooks) aux composants d'affichage.
 * Aucune logique métier ici, seulement du « câblage » entre les briques.
 */
export default function TopologyEditor() {
  const topology = useTopology();
  const cableTool = useCableTool(topology.connectDevices);
  const [toast, setToast] = useState(null);

  // La sélection est portée par React Flow (propriété `selected` des nœuds/liens)
  const selectedNodes = topology.nodes.filter((n) => n.selected);
  const selectedNode = selectedNodes.length === 1 ? selectedNodes[0] : null;
  const selectedEdge = selectedNode ? null : topology.edges.find((e) => e.selected) ?? null;

  const handleValidate = useCallback(async () => {
    const data = serializeTopology(topology.nodes, topology.edges);
    const warnings = validateTopology(data);
    await submitTopology(data, warnings);
    setToast(
      warnings.length
        ? `Topologie sérialisée avec ${warnings.length} avertissement(s) — voir la console (F12)`
        : 'Topologie sérialisée — voir la console (F12)',
    );
  }, [topology.nodes, topology.edges]);

  const handleClear = useCallback(() => {
    if (window.confirm('Effacer toute la topologie ?')) {
      topology.clearTopology();
      cableTool.cancel();
    }
  }, [topology, cableTool]);

  // Masque automatiquement la notification après quelques secondes
  useEffect(() => {
    if (!toast) return undefined;
    const timer = setTimeout(() => setToast(null), 3500);
    return () => clearTimeout(timer);
  }, [toast]);

  return (
    <div className="app">
      <Toolbar
        cableModeActive={cableTool.isActive}
        onToggleCableMode={cableTool.toggle}
        onValidate={handleValidate}
        onClear={handleClear}
        nodeCount={topology.nodes.length}
        linkCount={topology.edges.length}
      />

      <main className="workspace">
        <Palette />
        <TopologyCanvas
          nodes={topology.nodes}
          edges={topology.edges}
          onNodesChange={topology.onNodesChange}
          onEdgesChange={topology.onEdgesChange}
          onAddDevice={topology.addDevice}
          cableTool={cableTool}
        />
        <PropertiesPanel
          selectedNode={selectedNode}
          selectedEdge={selectedEdge}
          nodes={topology.nodes}
          onUpdateProperties={topology.updateDeviceProperties}
          onDeleteDevice={topology.deleteDevice}
          onDeleteLink={topology.deleteLink}
        />
      </main>

      {toast && <div className="toast" role="status">{toast}</div>}
    </div>
  );
}
