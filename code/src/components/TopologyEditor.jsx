import { useCallback, useEffect, useMemo, useState } from 'react';
import Toolbar from './Toolbar.jsx';
import Palette from './Palette.jsx';
import TopologyCanvas from './TopologyCanvas.jsx';
import PropertiesPanel from './PropertiesPanel.jsx';
import DeployDialog from './DeployDialog.jsx';
import Dock from './Dock.jsx';
import TrafficPanel from './TrafficPanel.jsx';
import ScenarioPanel from './ScenarioPanel.jsx';
import { useTopology } from '../hooks/useTopology.js';
import { useCableTool } from '../hooks/useCableTool.js';
import { useDeployment } from '../hooks/useDeployment.js';
import { useDock } from '../hooks/useDock.js';
import { useTraffic } from '../hooks/useTraffic.js';
import { useSimulation } from '../hooks/useSimulation.js';
import { serializeTopology } from '../utils/serializeTopology.js';
import { deserializeTopology } from '../utils/deserializeTopology.js';
import { validateTopology } from '../utils/validators.js';

/**
 * Composant d'assemblage : relie l'état (hooks) aux composants d'affichage.
 * Aucune logique métier ici, seulement du « câblage » entre les briques.
 */
export default function TopologyEditor() {
  const topology = useTopology();
  const [toast, setToast] = useState(null);
  // Panneau de droite : 'traffic' (trafic bénin), 'scenario' (audit), ou null (propriétés).
  const [rightPanel, setRightPanel] = useState(null);
  const cableTool = useCableTool(topology.connectDevices, setToast);
  const deployment = useDeployment();
  const dock = useDock();
  const { keepOnly, open: openTab } = dock;

  // Génération et visualisation du trafic (actives seulement réseau allumé)
  const labRunning = deployment.lab.status === 'running';
  const traffic = useTraffic(labRunning);
  useEffect(() => {
    if (!labRunning) setRightPanel(null); // les panneaux se ferment à l'arrêt du réseau
  }, [labRunning]);
  const togglePanel = (panel) => setRightPanel((cur) => (cur === panel ? null : panel));

  // Visualisation des paquets : chaque paquet réel capturé devient une boule
  // animée le long de son chemin, en temps réel (voir useSimulation).
  const { balls } = useSimulation(labRunning, topology.nodes, topology.edges);

  // Un équipement (ou un câble) supprimé de la topologie emporte son terminal (ou sa capture)
  useEffect(
    () => keepOnly(new Set(topology.nodes.map((n) => n.id)), new Set(topology.edges.map((e) => e.id))),
    [topology.nodes, topology.edges, keepOnly],
  );
  const openTerminal = useCallback((nodeId) => openTab('terminal', nodeId), [openTab]);
  const openCapture = useCallback((edgeId) => openTab('capture', edgeId), [openTab]);
  const capturedEdgeIds = useMemo(
    () => new Set(dock.tabs.filter((t) => t.kind === 'capture').map((t) => t.target)),
    [dock.tabs],
  );

  // La sélection est portée par React Flow (propriété `selected` des nœuds/liens)
  const selectedNodes = topology.nodes.filter((n) => n.selected);
  const selectedNode = selectedNodes.length === 1 ? selectedNodes[0] : null;
  const selectedEdge = selectedNode ? null : topology.edges.find((e) => e.selected) ?? null;

  // Contrôles de cohérence recalculés à chaque modification : affichés dans le
  // panneau de l'élément concerné, et bilan complet au moment de valider
  const issues = useMemo(
    () => validateTopology(serializeTopology(topology.nodes, topology.edges)),
    [topology.nodes, topology.edges],
  );
  const errorCount = issues.filter((i) => i.level === 'error').length;

  const handleValidate = useCallback(() => {
    deployment.validate(serializeTopology(topology.nodes, topology.edges), issues);
  }, [deployment, topology.nodes, topology.edges, issues]);

  const handleClear = useCallback(() => {
    if (window.confirm('Effacer toute la topologie ?')) {
      topology.clearTopology();
      cableTool.cancel();
    }
  }, [topology, cableTool]);

  const handleLoadExample = useCallback(
    (example) => {
      if (topology.nodes.length && !window.confirm(`Remplacer la topologie actuelle par l'exemple « ${example.name} » ?`)) return;
      try {
        topology.loadTopology(deserializeTopology(example.topology));
        cableTool.cancel();
        setToast(`Exemple « ${example.name} » chargé`);
      } catch (err) {
        setToast(err.message);
      }
    },
    [topology, cableTool],
  );

  const handleStopLab = useCallback(async () => {
    if (!window.confirm('Arrêter le réseau ? Tous les équipements seront éteints.')) return;
    try {
      await deployment.stop();
      setToast('Réseau arrêté');
    } catch (err) {
      setToast(err.message);
    }
  }, [deployment]);

  // Masque automatiquement la notification après quelques secondes
  useEffect(() => {
    if (!toast) return undefined;
    const timer = setTimeout(() => setToast(null), 4000);
    return () => clearTimeout(timer);
  }, [toast]);

  return (
    <div className="app">
      <Toolbar
        cableModeActive={cableTool.isActive}
        onToggleCableMode={cableTool.toggle}
        onValidate={handleValidate}
        onClear={handleClear}
        onLoadExample={handleLoadExample}
        onStopLab={handleStopLab}
        onToggleTraffic={() => togglePanel('traffic')}
        trafficActive={rightPanel === 'traffic'}
        onToggleScenario={() => togglePanel('scenario')}
        scenarioActive={rightPanel === 'scenario'}
        nodeCount={topology.nodes.length}
        errorCount={errorCount}
        labStatus={deployment.lab.status}
        busy={deployment.run?.phase === 'running'}
      />

      <main className="workspace">
        <Palette />

        {/* Colonne centrale : le canvas, et le panneau du bas (terminaux / captures)
            glissé dessous — il reste donc entre la palette (gauche) et le panneau
            de droite, au lieu de passer sous eux. */}
        <div className="workspace__center">
          <TopologyCanvas
            nodes={topology.nodes}
            edges={topology.edges}
            onNodesChange={topology.onNodesChange}
            onEdgesChange={topology.onEdgesChange}
            onAddDevice={topology.addDevice}
            cableTool={cableTool}
            onlineNodeIds={deployment.lab.onlineIds}
            onOpenTerminal={openTerminal}
            onOpenCapture={openCapture}
            capturedEdgeIds={capturedEdgeIds}
            balls={balls}
            simActive={labRunning}
          />
          <Dock
            tabs={dock.tabs}
            activeKeys={dock.activeKeys}
            split={dock.split}
            focusedPane={dock.focusedPane}
            requests={dock.requests}
            nodes={topology.nodes}
            edges={topology.edges}
            onSelect={dock.select}
            onClose={dock.close}
            onMove={dock.move}
          />
        </div>

        {/* Panneau de droite : trafic bénin, scénarios d'audit, ou propriétés de la sélection. */}
        {rightPanel === 'traffic' && labRunning ? (
          <TrafficPanel
            traffic={traffic}
            nodes={topology.nodes}
            edges={topology.edges}
            onlineIds={deployment.lab.onlineIds}
            onClose={() => setRightPanel(null)}
          />
        ) : rightPanel === 'scenario' && labRunning ? (
          <ScenarioPanel
            traffic={traffic}
            nodes={topology.nodes}
            edges={topology.edges}
            onlineIds={deployment.lab.onlineIds}
            onClose={() => setRightPanel(null)}
          />
        ) : (
          <PropertiesPanel
            selectedNode={selectedNode}
            selectedEdge={selectedEdge}
            nodes={topology.nodes}
            edges={topology.edges}
            issues={issues}
            onUpdateProperties={topology.updateDeviceProperties}
            onUpdateLink={topology.updateLink}
            onDeleteDevice={topology.deleteDevice}
            onDeleteLink={topology.deleteLink}
            onlineNodeIds={deployment.lab.onlineIds}
            onOpenCapture={openCapture}
          />
        )}
      </main>

      <DeployDialog run={deployment.run} onConfirm={deployment.deploy} onClose={deployment.dismiss} />

      {toast && <div className="toast" role="status">{toast}</div>}
    </div>
  );
}
