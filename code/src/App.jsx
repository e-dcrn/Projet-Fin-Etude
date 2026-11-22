import { useState } from 'react';
import Toolbar from './components/Toolbar.jsx';
import TopologyCanvas from './components/TopologyCanvas.jsx';
import SimulationPanel from './components/SimulationPanel.jsx';
import DetectionPanel from './components/DetectionPanel.jsx';
import DatasetDialog from './components/DatasetDialog.jsx';
import ModelDialog from './components/ModelDialog.jsx';
import { useLab } from './hooks/useLab.js';
import { useTraffic } from './hooks/useTraffic.js';
import { useDatasets } from './hooks/useDatasets.js';
import { useModels } from './hooks/useModels.js';
import { useDetection } from './hooks/useDetection.js';
import { TOPOLOGIES } from './utils/topology.js';

/**
 * Racine de l'application : relie l'état (hooks) aux composants d'affichage.
 *
 * Parcours : choisir une topologie et la démarrer → générer du trafic et des
 * attaques (⚡ Simulation), des datasets (🗂) → entraîner un modèle (🧠) →
 * détection en direct (🛡).
 */
export default function App() {
  const lab = useLab();
  const running = lab.status === 'running';
  const online = lab.status !== 'offline';

  // Topologie affichée : celle qui tourne, sinon celle choisie dans la liste.
  const [chosenId, setChosenId] = useState(TOPOLOGIES[0].id);
  const topology = TOPOLOGIES.find((t) => t.id === (lab.topology ?? chosenId)) ?? TOPOLOGIES[0];

  const traffic = useTraffic(running);
  const datasets = useDatasets(online);
  const models = useModels(online);
  const detection = useDetection(running);

  const [panel, setPanel] = useState(null); // panneau de droite : 'simulation', 'detection' ou null
  const [datasetsOpen, setDatasetsOpen] = useState(false);
  const [modelsOpen, setModelsOpen] = useState(false);

  // Détection : équipements impliqués dans une alerte des 15 dernières secondes
  // (source et cible, entourés de rouge sur le schéma) et sonde en cours d'analyse.
  const nodeByIp = new Map(topology.links.map((l) => [l.ip, l.node]));
  const alertIds = new Set();
  for (const ev of detection.events) {
    if (ev.outcome === 'alert' && ev.time > Date.now() / 1000 - 15) {
      [ev.src, ev.dst].forEach((ip) => nodeByIp.has(ip) && alertIds.add(nodeByIp.get(ip)));
    }
  }
  const watchingIds = new Set(detection.running && detection.ids ? [detection.ids.node] : []);

  return (
    <div className="app">
      <Toolbar
        lab={lab}
        topologyId={topology.id}
        onChooseTopology={setChosenId}
        panel={panel}
        onTogglePanel={(name) => setPanel((current) => (current === name ? null : name))}
        active={{
          simulation: traffic.active,
          detection: detection.running,
          dataset: datasets.run?.phase === 'running',
          training: models.run?.phase === 'running',
        }}
        onOpenDatasets={() => setDatasetsOpen(true)}
        onOpenModels={() => setModelsOpen(true)}
      />

      {lab.error && <div className="lab-error" role="alert">{lab.error}</div>}

      <main className="workspace">
        <div className="workspace__center">
          <TopologyCanvas topology={topology} onlineIds={lab.onlineIds} alertIds={alertIds} watchingIds={watchingIds} />
          <p className="workspace__description">{topology.description}</p>
        </div>

        {running && panel === 'simulation' && (
          <SimulationPanel traffic={traffic} topology={topology} onClose={() => setPanel(null)} />
        )}
        {running && panel === 'detection' && (
          <DetectionPanel detection={detection} models={models.models} topology={topology} onClose={() => setPanel(null)} />
        )}
      </main>

      <DatasetDialog
        open={datasetsOpen}
        datasets={datasets}
        traffic={traffic}
        topology={topology}
        labRunning={running}
        onClose={() => setDatasetsOpen(false)}
      />
      <ModelDialog open={modelsOpen} models={models} datasets={datasets.datasets} onClose={() => setModelsOpen(false)} />
    </div>
  );
}
