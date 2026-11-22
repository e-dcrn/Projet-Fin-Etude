import { Handle, Position } from '@xyflow/react';
import { DEVICE_TYPES } from '../config/deviceTypes.js';

/**
 * Un équipement sur le schéma : icône, nom, adresses.
 *
 * React Flow a besoin de « poignées » pour savoir où attacher les câbles : on en
 * place deux, invisibles, au centre de l'icône.
 *
 * `data` (préparé par TopologyCanvas) : type, name, lines (adresses ou réseau),
 * online (conteneur allumé), alert (impliqué dans une alerte récente), watching
 * (sonde IDS en cours d'analyse).
 */
export default function DeviceNode({ data }) {
  const { color, Icon, description } = DEVICE_TYPES[data.type];

  return (
    <div
      className={`device-node${data.alert ? ' device-node--alert' : ''}${data.watching ? ' device-node--watching' : ''}`}
      style={{ '--device-color': color }}
      title={description}
    >
      <div className="device-node__icon">
        <Icon />
        <Handle type="source" position={Position.Top} isConnectable={false} className="device-node__handle" />
        <Handle type="target" position={Position.Top} isConnectable={false} className="device-node__handle" />
        {data.online && <span className="device-node__status" title="En fonctionnement" />}
      </div>
      <div className="device-node__name">{data.name}</div>
      {data.lines.map((line) => (
        <div key={line} className="device-node__ip">{line}</div>
      ))}
    </div>
  );
}
