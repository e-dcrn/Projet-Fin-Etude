import { useRef, useState } from 'react';
import TerminalView from './TerminalView.jsx';
import CaptureView from './CaptureView.jsx';
import { DEVICE_TYPES } from '../config/deviceTypes.js';
import { nodeName } from '../utils/topologyQueries.js';

const MIN_HEIGHT = 120;
const MIN_CANVAS_HEIGHT = 160; // hauteur minimale laissée au reste de l'interface

/**
 * Panneau du bas : un onglet par terminal d'équipement ou capture de lien (voir useDock).
 * Tous les onglets restent montés ; seul l'onglet actif est visible.
 * Le bord supérieur se glisse pour redimensionner le panneau.
 */
export default function Dock({ tabs, activeKey, requests, nodes, edges, onSelect, onClose }) {
  const [height, setHeight] = useState(Math.round(window.innerHeight * 0.5));
  const drag = useRef(null);

  if (tabs.length === 0) return null;

  const onPointerDown = (event) => {
    drag.current = { startY: event.clientY, startHeight: height };
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const onPointerMove = (event) => {
    if (!drag.current) return;
    const wanted = drag.current.startHeight + drag.current.startY - event.clientY;
    setHeight(Math.max(MIN_HEIGHT, Math.min(wanted, window.innerHeight - MIN_CANVAS_HEIGHT)));
  };
  const onPointerUp = () => {
    drag.current = null;
  };

  /** Libellé et couleur d'un onglet (calculés à chaque rendu : suivent les renommages). */
  const describe = (tab) => {
    if (tab.kind === 'terminal') {
      const node = nodes.find((n) => n.id === tab.target);
      return { title: nodeName(nodes, tab.target), color: DEVICE_TYPES[node?.data.deviceType]?.color };
    }
    const edge = edges.find((e) => e.id === tab.target);
    if (!edge) return { title: tab.target };
    return {
      title: `${nodeName(nodes, edge.source)} ${edge.data.interface} ↔ ${nodeName(nodes, edge.target)} ${edge.data.port ?? ''}`.trim(),
      capture: true,
    };
  };

  return (
    // nokey : les touches tapées dans le panneau ne doivent pas agir sur le canvas (Suppr…)
    <section className="terminal-dock nokey" style={{ height }} aria-label="Terminaux et captures">
      <div
        className="terminal-dock__resizer"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
      />
      <div className="terminal-dock__tabs" role="tablist">
        {tabs.map((tab) => {
          const { title, color, capture } = describe(tab);
          const active = tab.key === activeKey;
          return (
            <div key={tab.key} className={`terminal-tab${active ? ' terminal-tab--active' : ''}`} style={{ '--device-color': color }}>
              <button type="button" role="tab" aria-selected={active} className="terminal-tab__label" onClick={() => onSelect(tab.key)}>
                {capture ? <span className="terminal-tab__capture" aria-hidden="true" /> : <span className="terminal-tab__dot" />}
                {capture ? `Capture · ${title}` : title}
              </button>
              <button type="button" className="terminal-tab__close" title={`Fermer : ${title}`} onClick={() => onClose(tab.key)}>
                ×
              </button>
            </div>
          );
        })}
      </div>
      <div className="terminal-dock__body">
        {tabs.map((tab) => {
          const active = tab.key === activeKey;
          if (tab.kind === 'terminal') {
            return <TerminalView key={tab.key} nodeId={tab.target} active={active} openRequest={requests[tab.key]} />;
          }
          const edge = edges.find((e) => e.id === tab.target);
          if (!edge) return null; // câble supprimé : l'onglet va être fermé (useDock.keepOnly)
          return (
            <CaptureView
              key={tab.key}
              nodeId={edge.source}
              interfaceName={edge.data.interface}
              title={describe(tab).title}
              active={active}
              openRequest={requests[tab.key]}
            />
          );
        })}
      </div>
    </section>
  );
}
