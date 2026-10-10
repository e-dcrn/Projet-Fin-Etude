import { useEffect, useRef, useState } from 'react';
import { DIFFICULTIES, EXAMPLE_TOPOLOGIES } from '../config/exampleTopologies.js';

/**
 * Menu déroulant « Exemples de topologies » de la barre d'outils.
 * Se ferme au choix d'un exemple, sur Échap ou sur un clic à l'extérieur.
 */
export default function ExamplesMenu({ onLoad, disabled }) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (event) => {
      if (!rootRef.current?.contains(event.target)) setOpen(false);
    };
    const onKeyDown = (event) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  const choose = (example) => {
    setOpen(false);
    onLoad(example);
  };

  return (
    <div className="examples" ref={rootRef}>
      <button
        type="button"
        className={`btn${open ? ' btn--active' : ''}`}
        onClick={() => setOpen((o) => !o)}
        disabled={disabled || EXAMPLE_TOPOLOGIES.length === 0}
        aria-haspopup="menu"
        aria-expanded={open}
      >
        📂 Exemples de topologies ▾
      </button>

      {open && (
        <ul className="examples__menu" role="menu">
          {EXAMPLE_TOPOLOGIES.map((example) => {
            const difficulty = DIFFICULTIES[example.difficulty];
            return (
              <li key={example.id} role="none">
                <button type="button" role="menuitem" className="examples__item" onClick={() => choose(example)}>
                  <span className="examples__header">
                    <strong>{example.name}</strong>
                    {difficulty && <span className={`difficulty ${difficulty.className}`}>{difficulty.label}</span>}
                  </span>
                  {example.description && <span className="examples__description">{example.description}</span>}
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
