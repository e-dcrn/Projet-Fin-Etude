/**
 * Briques de formulaire communes au panneau de propriétés.
 */

/** Section repliable, avec un compteur optionnel dans le titre. */
export function Section({ title, count, children, defaultOpen = true }) {
  return (
    <details className="section" open={defaultOpen}>
      <summary className="section__title">
        {title}
        {count !== undefined && <span className="section__count">{count}</span>}
      </summary>
      <div className="section__body">{children}</div>
    </details>
  );
}

/** Champ texte avec libellé, erreur et aide éventuelles (error === true : bordure rouge seule). */
export function TextField({ label, value, onChange, error, hint, placeholder, mono = false, list, compact = false }) {
  return (
    <label className={`field${compact ? ' field--compact' : ''}`}>
      {label && <span className="field__label">{label}</span>}
      <input
        className={`field__input${mono ? ' field__input--mono' : ''}${error ? ' field__input--error' : ''}`}
        value={value ?? ''}
        placeholder={placeholder}
        spellCheck={false}
        autoComplete="off"
        list={list}
        onChange={(e) => onChange(e.target.value)}
      />
      {typeof error === 'string' ? <span className="field__error">{error}</span> : !error && hint && <span className="field__hint">{hint}</span>}
    </label>
  );
}

/** Réactive l'attribution automatique d'un champ saisi à la main. */
export function AutoButton({ onClick }) {
  return (
    <button type="button" className="auto-btn" onClick={onClick} title="Laisser l'IPAM choisir la valeur">
      ↺ Automatique
    </button>
  );
}

/** Liste déroulante ; `options` : [{ value, label }]. */
export function SelectField({ label, value, onChange, options, error, compact = false }) {
  return (
    <label className={`field${compact ? ' field--compact' : ''}`}>
      {label && <span className="field__label">{label}</span>}
      <select
        className={`field__input${error ? ' field__input--error' : ''}`}
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value)}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      {error && <span className="field__error">{error}</span>}
    </label>
  );
}

/** Problèmes de cohérence concernant l'élément affiché (issus de validateTopology). */
export function IssuesList({ issues }) {
  if (!issues.length) return null;
  return (
    <ul className="issues">
      {issues.map((issue, i) => (
        <li key={i} className={`issues__item issues__item--${issue.level}`}>
          {issue.message}
        </li>
      ))}
    </ul>
  );
}

/** Bouton icône de suppression d'une ligne. */
export function RemoveButton({ onClick, title }) {
  return (
    <button type="button" className="icon-btn" onClick={onClick} title={title} aria-label={title}>
      ✕
    </button>
  );
}
