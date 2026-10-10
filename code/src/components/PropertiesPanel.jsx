import { DEVICE_TYPES, PROPERTY_FIELDS } from '../config/deviceTypes.js';
import { isValidIpAddress } from '../utils/validators.js';

/**
 * Panneau de propriétés (colonne de droite).
 * Affiche le formulaire de l'équipement sélectionné, ou les infos du câble sélectionné.
 * Le formulaire est généré à partir de PROPERTY_FIELDS (config/deviceTypes.js).
 */
export default function PropertiesPanel({
  selectedNode,
  selectedEdge,
  nodes,
  onUpdateProperties,
  onDeleteDevice,
  onDeleteLink,
}) {
  if (selectedNode) {
    return (
      <aside className="properties">
        <DeviceForm
          node={selectedNode}
          onChange={(patch) => onUpdateProperties(selectedNode.id, patch)}
          onDelete={() => onDeleteDevice(selectedNode.id)}
        />
      </aside>
    );
  }

  if (selectedEdge) {
    const nameOf = (id) => nodes.find((n) => n.id === id)?.data.properties.name ?? id;
    return (
      <aside className="properties">
        <h2 className="panel-title">Câble</h2>
        <p className="properties__link">
          {nameOf(selectedEdge.source)} ↔ {nameOf(selectedEdge.target)}
        </p>
        <button type="button" className="btn btn--danger btn--block" onClick={() => onDeleteLink(selectedEdge.id)}>
          Supprimer le câble
        </button>
      </aside>
    );
  }

  return (
    <aside className="properties">
      <h2 className="panel-title">Propriétés</h2>
      <p className="panel-hint">Sélectionnez un équipement ou un câble pour l'éditer.</p>
      <ul className="panel-help">
        <li>Glisser depuis la palette : ajouter</li>
        <li>Glisser un équipement : déplacer</li>
        <li>🔌 Câble, puis clic A → clic B : relier</li>
        <li>Suppr / Retour arrière : supprimer la sélection</li>
      </ul>
    </aside>
  );
}

/** Formulaire d'édition d'un équipement. */
function DeviceForm({ node, onChange, onDelete }) {
  const definition = DEVICE_TYPES[node.data.deviceType];
  const { properties } = node.data;

  return (
    <>
      <h2 className="panel-title" style={{ '--device-color': definition.color }}>
        <span className="properties__type-dot" />
        {definition.label}
      </h2>
      <p className="panel-hint">Identifiant : {node.id}</p>

      {PROPERTY_FIELDS.map((field) => {
        const value = properties[field.key] ?? '';
        const error = getFieldError(field, value);
        return (
          <label key={field.key} className="field">
            <span className="field__label">{field.label}</span>
            <input
              className={`field__input${error ? ' field__input--error' : ''}`}
              value={value}
              placeholder={field.placeholder}
              spellCheck={false}
              onChange={(e) => onChange({ [field.key]: e.target.value })}
            />
            {error && <span className="field__error">{error}</span>}
          </label>
        );
      })}

      <button type="button" className="btn btn--danger btn--block" onClick={onDelete}>
        Supprimer l'équipement
      </button>
    </>
  );
}

/** Retourne un message d'erreur pour un champ, ou null s'il est valide. */
function getFieldError(field, value) {
  if (field.required && !value.trim()) return 'Champ obligatoire';
  if (field.type === 'ip' && value && !isValidIpAddress(value)) return 'Format attendu : 192.168.1.10 ou 192.168.1.10/24';
  return null;
}
