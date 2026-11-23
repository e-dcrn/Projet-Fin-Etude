import { useState } from 'react';
import Toolbar from './components/Toolbar.jsx';
import TopologyCanvas from './components/TopologyCanvas.jsx';
import SimulationPanel from './components/SimulationPanel.jsx';
import DetectionPanel from './components/DetectionPanel.jsx';
import DatasetDialog from './components/DatasetDialog.jsx';
import ModelDialog from './components/ModelDialog.jsx';
import CompareDialog from './components/CompareDialog.jsx';
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
  const [compareOpen, setCompareOpen] = useState(false);

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
        onOpenCompare={() => setCompareOpen(true)}
      />

      {lab.error && <div className="lab-error" role="alert">{lab.error}</div>}

      <main className="workspace">
        <div className="workspace__center">
          <TopologyCanvas topology={topology} onlineIds={lab.onlineIds} />
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
      <CompareDialog open={compareOpen} datasets={datasets.datasets} models={models.models} onClose={() => setCompareOpen(false)} />
    </div>
  );
}
