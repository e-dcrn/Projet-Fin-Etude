import { useEffect, useRef, useState } from 'react';
import { TOPOLOGIES } from '../utils/topology.js';

/**
 * Menu de choix de la topologie : un bouton qui affiche la topologie courante et
 * déroule la liste des topologies, chacune avec une courte description. Désactivé
 * quand le réseau tourne (on arrête d'abord pour changer de topologie).
 */
export default function TopologyMenu({ topologyId, onChoose, disabled }) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef(null);
  const current = TOPOLOGIES.find((t) => t.id === topologyId) ?? TOPOLOGIES[0];

  useEffect(() => {
    if (!open) return undefined;
    const onClickOutside = (e) => { if (!rootRef.current?.contains(e.target)) setOpen(false); };
    const onEsc = (e) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('pointerdown', onClickOutside);
    document.addEventListener('keydown', onEsc);
    return () => {
      document.removeEventListener('pointerdown', onClickOutside);
      document.removeEventListener('keydown', onEsc);
    };
  }, [open]);

  const choose = (id) => { setOpen(false); onChoose(id); };

  return (
    <div className="topo-menu" ref={rootRef}>
      <button
        type="button"
        className={`btn${open ? ' btn--active' : ''}`}
        onClick={() => setOpen((o) => !o)}
        disabled={disabled}
        aria-haspopup="menu"
        aria-expanded={open}
        title={disabled ? 'Arrêtez le réseau pour changer de topologie' : 'Choisir la topologie'}
      >
        🌐 {current.name} ▼
      </button>

      {open && (
        <ul className="topo-menu__list" role="menu">
          {TOPOLOGIES.map((t) => (
            <li key={t.id} role="none">
              <button
                type="button"
                role="menuitem"
                className={`topo-menu__item${t.id === topologyId ? ' topo-menu__item--active' : ''}`}
                onClick={() => choose(t.id)}
              >
                <strong>{t.name}</strong>
                <span className="topo-menu__desc">{t.description}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
