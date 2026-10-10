import { useRef, useState } from 'react';
import TerminalView from './TerminalView.jsx';
import CaptureView from './CaptureView.jsx';
import { DEVICE_TYPES } from '../config/deviceTypes.js';
import { nodeName } from '../utils/topologyQueries.js';

const MIN_HEIGHT = 120;
const MIN_CANVAS_HEIGHT = 160; // hauteur minimale laissée au reste de l'interface
const MIN_PANE_RATIO = 0.2; // largeur minimale d'un volet (part du panneau)

// Type MIME du glisser-déposer d'un onglet vers l'autre volet
const TAB_MIME_TYPE = 'application/x-ids-dock-tab';

/**
 * Panneau du bas : un onglet par terminal d'équipement ou capture de lien (voir useDock),
 * répartis dans un ou deux volets côte à côte.
 * Tous les onglets restent montés dans le même conteneur, seule leur position change
 * selon leur volet : déplacer un onglet ne coupe donc pas sa session.
 * Le bord supérieur se glisse pour redimensionner le panneau, la séparation des volets
 * pour régler leur largeur ; un onglet se glisse d'un volet à l'autre.
 */
export default function Dock({ tabs, activeKeys, split, focusedPane, requests, nodes, edges, onSelect, onClose, onMove }) {
  const [height, setHeight] = useState(Math.round(window.innerHeight * 0.5));
  const [ratio, setRatio] = useState(0.5); // largeur du volet gauche
  const [dragging, setDragging] = useState(false); // un onglet est en cours de glisser-déposer
  const drag = useRef(null);
  const mainRef = useRef(null);

  if (tabs.length === 0) return null;

  // Redimensionnement : hauteur du panneau (bord supérieur) ou largeur des volets (séparation)
  const startResize = (kind) => (event) => {
    drag.current = { kind, startY: event.clientY, startHeight: height };
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const onPointerMove = (event) => {
    if (!drag.current) return;
    if (drag.current.kind === 'height') {
      const wanted = drag.current.startHeight + drag.current.startY - event.clientY;
      setHeight(Math.max(MIN_HEIGHT, Math.min(wanted, window.innerHeight - MIN_CANVAS_HEIGHT)));
    } else {
      const { left, width } = mainRef.current.getBoundingClientRect();
      setRatio(Math.max(MIN_PANE_RATIO, Math.min((event.clientX - left) / width, 1 - MIN_PANE_RATIO)));
    }
  };
  const onPointerUp = () => {
    drag.current = null;
  };
  const resizeHandlers = { onPointerMove, onPointerUp, onPointerCancel: onPointerUp };

  // Glisser-déposer d'un onglet sur une barre d'onglets (ou sur la moitié droite pour diviser)
  const dropTarget = (pane) => ({
    onDragOver: (event) => {
      if (!event.dataTransfer.types.includes(TAB_MIME_TYPE)) return;
      event.preventDefault();
      event.dataTransfer.dropEffect = 'move';
    },
    onDrop: (event) => {
      const key = event.dataTransfer.getData(TAB_MIME_TYPE);
      if (!key) return;
      event.preventDefault();
      setDragging(false);
      onMove(key, pane);
    },
  });

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

  // Position d'un volet dans le panneau
  const paneStyle = (pane) => {
    if (!split) return { left: 0, right: 0 };
    return pane === 0 ? { left: 0, width: `${ratio * 100}%` } : { left: `${ratio * 100}%`, right: 0 };
  };

  const tabBar = (pane) => {
    const paneTabs = tabs.filter((t) => t.pane === pane);
    const canSplit = !split && paneTabs.length > 1;
    return (
      <div
        className={`terminal-dock__tabs${split && focusedPane === pane ? ' terminal-dock__tabs--focused' : ''}`}
        style={split ? { flex: 'none', width: `${(pane === 0 ? ratio : 1 - ratio) * 100}%` } : undefined}
        role="tablist"
        {...dropTarget(pane)}
      >
        {paneTabs.map((tab) => {
          const { title, color, capture } = describe(tab);
          const active = tab.key === activeKeys[pane];
          return (
            <div
              key={tab.key}
              className={`terminal-tab${active ? ' terminal-tab--active' : ''}`}
              style={{ '--device-color': color }}
              draggable
              onDragStart={(event) => {
                event.dataTransfer.setData(TAB_MIME_TYPE, tab.key);
                event.dataTransfer.effectAllowed = 'move';
                setTimeout(() => setDragging(true)); // modifier le DOM pendant dragstart annulerait le glisser
              }}
              onDragEnd={() => setDragging(false)}
            >
              <button type="button" role="tab" aria-selected={active} className="terminal-tab__label" onClick={() => onSelect(tab.key)}>
                {capture ? <span className="terminal-tab__capture" aria-hidden="true" /> : <span className="terminal-tab__dot" />}
                {capture ? `Capture · ${title}` : title}
              </button>
              {split && (
                <button
                  type="button"
                  className="terminal-tab__close"
                  title={pane === 0 ? 'Déplacer dans le volet de droite' : 'Déplacer dans le volet de gauche'}
                  onClick={() => onMove(tab.key)}
                >
                  {pane === 0 ? '→' : '←'}
                </button>
              )}
              <button type="button" className="terminal-tab__close" title={`Fermer : ${title}`} onClick={() => onClose(tab.key)}>
                ×
              </button>
            </div>
          );
        })}
        {canSplit && (
          <button
            type="button"
            className="terminal-dock__split"
            title="Diviser : afficher l'onglet courant dans un volet à droite"
            onClick={() => onMove(activeKeys[0], 1)}
          >
            ◫ Diviser
          </button>
        )}
      </div>
    );
  };

  return (
    // nokey : les touches tapées dans le panneau ne doivent pas agir sur le canvas (Suppr…)
    <section className="terminal-dock nokey" style={{ height }} aria-label="Terminaux et captures">
      <div className="terminal-dock__resizer" onPointerDown={startResize('height')} {...resizeHandlers} />
      <div className="terminal-dock__main" ref={mainRef}>
        <div className="terminal-dock__header">
          {tabBar(0)}
          {split && tabBar(1)}
        </div>
        <div className="terminal-dock__body">
          {tabs.map((tab) => {
            const active = tab.key === activeKeys[tab.pane];
            let view;
            if (tab.kind === 'terminal') {
              view = <TerminalView nodeId={tab.target} active={active} openRequest={requests[tab.key]} />;
            } else {
              const edge = edges.find((e) => e.id === tab.target);
              if (!edge) return null; // câble supprimé : l'onglet va être fermé (useDock.keepOnly)
              view = (
                <CaptureView
                  nodeId={edge.source}
                  interfaceName={edge.data.interface}
                  title={describe(tab).title}
                  active={active}
                  openRequest={requests[tab.key]}
                />
              );
            }
            // Clé stable et parent commun : la vue n'est jamais remontée quand elle change de volet
            return (
              <div
                key={tab.key}
                className="terminal-dock__slot"
                style={paneStyle(tab.pane)}
                onPointerDown={active ? () => onSelect(tab.key) : undefined}
              >
                {view}
              </div>
            );
          })}
          {dragging && !split && (
            <div className="terminal-dock__dropzone" {...dropTarget(1)}>
              Déposer ici pour diviser
            </div>
          )}
        </div>
        {split && (
          <div
            className="terminal-dock__splitter"
            style={{ left: `${ratio * 100}%` }}
            onPointerDown={startResize('width')}
            {...resizeHandlers}
          />
        )}
      </div>
    </section>
  );
}
