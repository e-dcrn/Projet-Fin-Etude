import { BaseEdge, EdgeLabelRenderer, getStraightPath } from '@xyflow/react';

// Distance entre le centre d'un équipement et l'étiquette de son extrémité :
// juste au-delà de l'icône (52 px de côté), comme dans Packet Tracer
const LABEL_DISTANCE = 46;

/** Point situé à `distance` px de (fromX, fromY) en direction de (toX, toY). */
function pointAlong(fromX, fromY, toX, toY, distance) {
  const length = Math.hypot(toX - fromX, toY - fromY) || 1;
  const d = Math.min(distance, length * 0.4); // câble court : les deux étiquettes ne se chevauchent pas
  return { x: fromX + ((toX - fromX) * d) / length, y: fromY + ((toY - fromY) * d) / length };
}

function EndLabel({ point, text }) {
  if (!text) return null;
  return (
    <div className="cable-label" style={{ transform: `translate(-50%, -50%) translate(${point.x}px, ${point.y}px)` }}>
      {text}
    </div>
  );
}

/**
 * Câble : ligne droite de centre à centre, avec une étiquette à chaque extrémité :
 * l'interface de l'équipement (eth0…) côté équipement, le port (Fa0/1…) côté switch.
 * Un câble relie toujours un équipement (source) à un switch (target).
 */
export default function CableEdge({ id, sourceX, sourceY, targetX, targetY, data, style, interactionWidth }) {
  const [path] = getStraightPath({ sourceX, sourceY, targetX, targetY });

  return (
    <>
      <BaseEdge id={id} path={path} style={style} interactionWidth={interactionWidth} />
      <EdgeLabelRenderer>
        <EndLabel point={pointAlong(sourceX, sourceY, targetX, targetY, LABEL_DISTANCE)} text={data?.interface} />
        <EndLabel point={pointAlong(targetX, targetY, sourceX, sourceY, LABEL_DISTANCE)} text={data?.port} />
      </EdgeLabelRenderer>
    </>
  );
}
