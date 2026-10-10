import { ReactFlowProvider } from '@xyflow/react';
import TopologyEditor from './components/TopologyEditor.jsx';

/**
 * Racine de l'application.
 *
 * Le ReactFlowProvider doit englober tous les composants qui utilisent
 * les hooks React Flow (useReactFlow, etc.), y compris la palette, la barre d'outils
 * et le panneau de propriétés, qui sont rendus en dehors du canvas.
 */
export default function App() {
  return (
    <ReactFlowProvider>
      <TopologyEditor />
    </ReactFlowProvider>
  );
}
