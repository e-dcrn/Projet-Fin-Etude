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
 */
function DeviceNode({ data, selected }) {
  const definition = DEVICE_TYPES[data.deviceType];
  const { Icon } = definition;
  const { name, ip } = data.properties;

  return (
    <div
      className={`device-node${selected ? ' device-node--selected' : ''}`}
      style={{ '--device-color': definition.color }}
      title={definition.description}
    >
      <div className="device-node__icon">
        <Icon />
        <Handle type="source" position={Position.Top} isConnectable={false} className="device-node__handle" />
        <Handle type="target" position={Position.Top} isConnectable={false} className="device-node__handle" />
      </div>
      <div className="device-node__name">{name || '(sans nom)'}</div>
      {ip && <div className="device-node__ip">{ip}</div>}
    </div>
  );
}

// memo : évite de re-rendre tous les nœuds quand un seul est déplacé
export default memo(DeviceNode);
