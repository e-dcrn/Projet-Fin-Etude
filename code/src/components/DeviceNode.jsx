import { memo } from 'react';
import { Handle, Position } from '@xyflow/react';
import { DEVICE_TYPES } from '../config/deviceTypes.js';

/**
 * Rendu personnalisé d'un équipement sur le canvas.
 *
 * Les liens sont créés par clic (outil câble), pas par glisser depuis une poignée.
 * On place donc deux poignées invisibles au centre de l'icône : React Flow en a
 * besoin pour calculer les extrémités des liens, et cela donne des câbles qui
 * partent du centre de l'équipement, comme dans Packet Tracer.
 *
 * `data.summary` (lignes affichées sous le nom : adresses, réseau…) et
 * `data.online` (équipement instancié et allumé) sont calculés par TopologyCanvas.
 * Un PC ou un serveur allumé s'ouvre dans un terminal au clic.
 */
function DeviceNode({ data, selected }) {
  const definition = DEVICE_TYPES[data.deviceType];
  const { Icon } = definition;
  const { name } = data.properties;
  const terminal = data.online && definition.hasTerminal;

  return (
    <div
      className={`device-node${selected ? ' device-node--selected' : ''}`}
      style={{ '--device-color': definition.color }}
      title={terminal ? `${definition.description} : cliquer pour ouvrir le terminal` : definition.description}
    >
      <div className="device-node__icon">
        <Icon />
        <Handle type="source" position={Position.Top} isConnectable={false} className="device-node__handle" />
        <Handle type="target" position={Position.Top} isConnectable={false} className="device-node__handle" />
        {data.online && <span className="device-node__status" title="En fonctionnement" />}
      </div>
      <div className="device-node__name">{name || '(sans nom)'}</div>
      {data.summary?.map((line) => (
        <div key={line} className="device-node__ip">
          {line}
        </div>
      ))}
    </div>
  );
}

// memo : évite de re-rendre tous les nœuds quand un seul est déplacé
export default memo(DeviceNode);
