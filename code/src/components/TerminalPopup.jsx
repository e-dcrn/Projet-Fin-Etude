import { useState } from 'react';

// Nom du conteneur Docker d'un équipement : même schéma que Docker Compose,
// « idslab-<service>-1 », où le service porte l'identifiant du nœud (ex. pc-1).
const containerOf = (device) => `idslab-${device.id}-1`;

/**
 * Petite popup affichée au clic sur un équipement : la commande pour ouvrir un
 * terminal dessus, avec un bouton pour la copier.
 */
export default function TerminalPopup({ device, onClose }) {
  const [copied, setCopied] = useState(false);
  const command = `docker exec -it ${containerOf(device)} sh`;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* presse-papiers indisponible : l'utilisateur copie à la main */
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal--terminal" onClick={(e) => e.stopPropagation()}>
        <h2 className="modal__title">Terminal sur {device.name}</h2>
        <p className="modal__text">
          Ouvre un shell dans le conteneur. Colle cette commande dans un terminal de ta machine :
        </p>
        <code className="terminal-cmd">{command}</code>
        <div className="modal__actions">
          <button type="button" className="btn" onClick={onClose}>Fermer</button>
          <button type="button" className="btn btn--primary" onClick={copy}>
            {copied ? 'Copié ✓' : 'Copier la commande'}
          </button>
        </div>
      </div>
    </div>
  );
}
