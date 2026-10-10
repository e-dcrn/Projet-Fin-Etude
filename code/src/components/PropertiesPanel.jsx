import DeviceForm from './properties/DeviceForm.jsx';
import InterfaceCard from './properties/InterfaceCard.jsx';
import { IssuesList } from './properties/fields.jsx';
import { networkSubnet, nodeName } from '../utils/topologyQueries.js';

/**
 * Panneau de propriétés (colonne de droite).
 * Affiche le formulaire de l'équipement sélectionné, ou l'interface portée par le câble sélectionné.
 *
 * @param issues problèmes de cohérence de toute la topologie (validateTopology) ;
 *               seuls ceux qui concernent la sélection sont affichés.
 */
export default function PropertiesPanel({
  selectedNode,
  selectedEdge,
  nodes,
  edges,
  issues,
  onUpdateProperties,
  onUpdateLink,
  onDeleteDevice,
  onDeleteLink,
  onlineNodeIds,
  onOpenCapture,
}) {
  const issuesFor = (id) => issues.filter((issue) => issue.refs.includes(id));

  if (selectedNode) {
    return (
      <aside className="properties">
        <DeviceForm
          key={selectedNode.id}
          node={selectedNode}
          nodes={nodes}
          edges={edges}
          issues={issuesFor(selectedNode.id)}
          onChange={(patch) => onUpdateProperties(selectedNode.id, patch)}
          onUpdateLink={onUpdateLink}
          onDelete={() => onDeleteDevice(selectedNode.id)}
        />
      </aside>
    );
  }

  if (selectedEdge) {
    const deviceType = nodes.find((n) => n.id === selectedEdge.source)?.data.deviceType;
    return (
      <aside className="properties">
        <h2 className="panel-title">Câble</h2>
        <p className="properties__link">
          {nodeName(nodes, selectedEdge.source)} <span className="mono">{selectedEdge.data.interface}</span> ↔{' '}
          {nodeName(nodes, selectedEdge.target)} <span className="mono">{selectedEdge.data.port}</span>
        </p>
        <IssuesList issues={issuesFor(selectedEdge.id)} />
        <InterfaceCard
          edge={selectedEdge}
          networkName={nodeName(nodes, selectedEdge.target)}
          subnet={networkSubnet(nodes, selectedEdge.target)}
          editableName={deviceType === 'router'}
          ipOptional={deviceType === 'ids'}
          onChange={(patch) => onUpdateLink(selectedEdge.id, patch)}
        />
        <button
          type="button"
          className="btn btn--primary btn--block"
          disabled={!onlineNodeIds.has(selectedEdge.source)}
          onClick={() => onOpenCapture(selectedEdge.id)}
        >
          Capturer le trafic
        </button>
        <p className="panel-hint panel-hint--tight">
          {onlineNodeIds.has(selectedEdge.source)
            ? 'Observe en direct les paquets qui passent sur ce câble (double-clic sur le câble : même effet).'
            : 'Validez la topologie pour démarrer le réseau : la capture sera alors disponible.'}
        </p>
        <button type="button" className="btn btn--danger btn--block" onClick={() => onDeleteLink(selectedEdge.id)}>
          Supprimer le câble
        </button>
      </aside>
    );
  }

  return (
    <aside className="properties">
      <h2 className="panel-title">Propriétés</h2>
      <p className="panel-hint">Sélectionnez un équipement ou un câble pour l'éditer.</p>
      <ul className="panel-help">
        <li>Glisser depuis la palette : ajouter</li>
        <li>Glisser un équipement : déplacer</li>
        <li>🔌 Câble, puis clic A → clic B : relier un équipement à un switch</li>
        <li>Chaque câble crée une interface (eth0, eth1…) : son adresse IP et la passerelle sont attribuées automatiquement (modifiables)</li>
        <li>Suppr / Retour arrière : supprimer la sélection</li>
      </ul>
    </aside>
  );
}
