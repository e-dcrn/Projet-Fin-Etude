import { useRef } from 'react';
import { useReactFlow } from '@xyflow/react';
import { DEVICE_TYPES, DND_MIME_TYPE, NODE_ICON_SIZE } from '../config/deviceTypes.js';

/**
 * Palette d'équipements (colonne de gauche).
 * Chaque élément est « draggable » via l'API HTML5 Drag & Drop :
 * le type d'équipement est transporté dans le dataTransfer et lu
 * par le canvas au moment du dépôt (voir TopologyCanvas.onDrop).
 *
 * Pendant le glisser, l'image fantôme est celle de l'équipement tel qu'il
 * apparaîtra sur le canvas (et non l'élément de la palette), au niveau de zoom
 * courant, et le curseur est placé au centre de l'icône : l'équipement
 * se pose exactement là où on le lâche.
 */
export default function Palette() {
  const { getZoom } = useReactFlow();
  // Une prévisualisation hors écran par type d'équipement, utilisée comme image de drag
  const previewRefs = useRef({});

  const onDragStart = (event, deviceType) => {
    event.dataTransfer.setData(DND_MIME_TYPE, deviceType);
    event.dataTransfer.effectAllowed = 'move';

    const preview = previewRefs.current[deviceType];
    if (preview) {
      const zoom = getZoom();
      preview.style.zoom = zoom; // même taille que sur le canvas
      const center = (NODE_ICON_SIZE * zoom) / 2;
      event.dataTransfer.setDragImage(preview, center, center);
    }
  };

  return (
    <aside className="palette">
      <h2 className="panel-title">Équipements</h2>
      <p className="panel-hint">Glissez un équipement sur le canvas.</p>

      <ul className="palette__list">
        {Object.entries(DEVICE_TYPES).map(([type, { label, color, Icon, description }]) => (
          <li
            key={type}
            className="palette__item"
            style={{ '--device-color': color }}
            draggable
            onDragStart={(event) => onDragStart(event, type)}
            title={description}
          >
            <span className="palette__icon">
              <Icon />
            </span>
            <span>{label}</span>
          </li>
        ))}
      </ul>

      {/* Prévisualisations invisibles (hors écran) servant d'image de drag.
          Elles doivent être rendues dans le DOM pour que setDragImage fonctionne. */}
      <div className="drag-previews" aria-hidden>
        {Object.entries(DEVICE_TYPES).map(([type, { color, Icon }]) => (
          <div
            key={type}
            ref={(el) => (previewRefs.current[type] = el)}
            className="device-node__icon"
            style={{ '--device-color': color }}
          >
            <Icon />
          </div>
        ))}
      </div>
    </aside>
  );
}
