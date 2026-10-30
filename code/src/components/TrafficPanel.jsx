import { useMemo, useState } from 'react';
import { benignTargetsForDests, reachableDevices, trafficSources } from '../utils/trafficTargets.js';

// Types de trafic bénin (cases à cocher) → `kinds` envoyé à l'agent.
const KINDS = [
  { id: 'icmp', label: 'Ping (ICMP)' },
  { id: 'http', label: 'Web (HTTP)' },
  { id: 'service', label: 'Services (SSH, FTP…)' },
];

// Presets : combinaisons prêtes à l'emploi (types + fréquence).
const PRESETS = [
  { id: 'web', label: 'Navigation web', kinds: { http: true }, profile: 'moderate' },
  { id: 'ping', label: 'Pings réseau', kinds: { icmp: true }, profile: 'steady' },
  { id: 'services', label: 'Connexions services', kinds: { service: true }, profile: 'slow' },
  { id: 'mixte', label: 'Mixte intense', kinds: { icmp: true, http: true, service: true }, profile: 'intense' },
];

const NO_KINDS = { icmp: false, http: false, service: false };

/** Liste de cases à cocher (émetteurs / destinataires), avec « tous / aucun ». */
function CheckList({ label, items, off, onToggle, onAll, onNone, empty }) {
  return (
    <div className="traffic-field">
      <div className="check-head">
        <span className="field__label">{label}</span>
        <span className="check-head__actions">
          <button type="button" className="link-btn" onClick={onAll}>tous</button>
          {' · '}
          <button type="button" className="link-btn" onClick={onNone}>aucun</button>
        </span>
      </div>
      {items.length === 0 ? (
        <p className="panel-hint panel-hint--tight">{empty}</p>
      ) : (
        <div className="check-list">
          {items.map((it) => (
            <label key={it.id} className="check">
              <input type="checkbox" checked={!off.has(it.id)} onChange={() => onToggle(it.id)} />
              <span>{it.name}</span>
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * Panneau de génération de trafic de fond « bénin » : on choisit les types
 * (ping / web / services), les émetteurs et les destinataires par cases à cocher,
 * ainsi que la fréquence. Le trafic « normal » de référence pour la sonde IDS.
 * Distinct des scénarios d'audit (voir ScenarioPanel).
 */
export default function TrafficPanel({ traffic, nodes, edges, onlineIds, onClose }) {
  const emitterList = useMemo(() => trafficSources(nodes, onlineIds), [nodes, onlineIds]);
  const destList = useMemo(() => reachableDevices(nodes, edges), [nodes, edges]);

  // Sélections stockées « à l'envers » (ids DÉcochés) : par défaut tout est coché,
  // et un nouvel équipement est coché d'office.
  const [kinds, setKinds] = useState({ icmp: true, http: false, service: false });
  const [profile, setProfile] = useState('moderate');
  const [emittersOff, setEmittersOff] = useState(() => new Set());
  const [destsOff, setDestsOff] = useState(() => new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const guard = async (fn) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError(err.messages ? err.messages.join('\n') : String(err));
    } finally {
      setBusy(false);
    }
  };

  const toggleOff = (setter) => (id) =>
    setter((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const selectedEmitters = emitterList.filter((e) => !emittersOff.has(e.id));
  const selectedDestIds = destList.filter((d) => !destsOff.has(d.id)).map((d) => d.id);
  const kindsArr = KINDS.map((k) => k.id).filter((id) => kinds[id]);

  const destLabel =
    selectedDestIds.length === destList.length ? 'tous'
      : selectedDestIds.length === 1 ? destList.find((d) => d.id === selectedDestIds[0])?.name ?? '1 cible'
        : `${selectedDestIds.length} cibles`;

  const applyPreset = (preset) => {
    setKinds({ ...NO_KINDS, ...preset.kinds });
    setProfile(preset.profile);
  };

  const canStart = selectedEmitters.length > 0 && selectedDestIds.length > 0 && kindsArr.length > 0 && !busy;

  const start = () =>
    guard(() =>
      Promise.all(
        selectedEmitters
          .map((em) => {
            const targets = benignTargetsForDests(nodes, edges, em.id, selectedDestIds);
            return targets.length ? traffic.startBenign(em.id, profile, targets, destLabel, kindsArr) : null;
          })
          .filter(Boolean),
      ),
    );

  const runningBenign = traffic.benignNodes.size;

  return (
    <aside className="traffic-panel nokey" aria-label="Génération de trafic">
      <header className="traffic-panel__head">
        <strong>📡 Génération de trafic</strong>
        <button type="button" className="icon-btn" title="Fermer" onClick={onClose}>×</button>
      </header>

      {error && <div className="traffic-error" role="alert">{error}</div>}

      <section className="traffic-section traffic-section--first">
        <p className="panel-hint panel-hint--tight">
          Choisissez quoi générer, depuis quelles machines et vers lesquelles. Le trafic « normal » de
          référence pour la sonde IDS.
        </p>

        <div className="traffic-field">
          <span className="field__label">Presets</span>
          <div className="traffic-presets">
            {PRESETS.map((p) => (
              <button key={p.id} type="button" className="preset-btn" onClick={() => applyPreset(p)}>
                {p.label}
              </button>
            ))}
          </div>
        </div>

        <div className="traffic-field">
          <span className="field__label">Type de trafic</span>
          <div className="check-row">
            {KINDS.map((k) => (
              <label key={k.id} className="check">
                <input
                  type="checkbox"
                  checked={kinds[k.id]}
                  onChange={() => setKinds((prev) => ({ ...prev, [k.id]: !prev[k.id] }))}
                />
                <span>{k.label}</span>
              </label>
            ))}
          </div>
        </div>

        <label className="field field--compact">
          <span className="field__label">Fréquence</span>
          <select className="field__input" value={profile} onChange={(e) => setProfile(e.target.value)}>
            {traffic.profiles.map((p) => (
              <option key={p.id} value={p.id}>{p.label}</option>
            ))}
          </select>
        </label>

        <CheckList
          label="Émetteurs"
          items={emitterList}
          off={emittersOff}
          onToggle={toggleOff(setEmittersOff)}
          onAll={() => setEmittersOff(new Set())}
          onNone={() => setEmittersOff(new Set(emitterList.map((e) => e.id)))}
          empty="Aucun équipement allumé."
        />

        <CheckList
          label="Destinataires"
          items={destList}
          off={destsOff}
          onToggle={toggleOff(setDestsOff)}
          onAll={() => setDestsOff(new Set())}
          onNone={() => setDestsOff(new Set(destList.map((d) => d.id)))}
          empty="Aucun équipement avec adresse IP."
        />

        <div className="traffic-actions">
          <button type="button" className="btn btn--primary" onClick={start} disabled={!canStart}>
            ▶ Démarrer
          </button>
          <button type="button" className="btn" onClick={() => guard(() => traffic.stopBenign())} disabled={busy || runningBenign === 0}>
            ■ Tout arrêter
          </button>
        </div>

        {traffic.benign.length > 0 && (
          <ul className="traffic-list">
            {traffic.benign.map((agent) => {
              const name = nodes.find((n) => n.id === agent.node)?.data.properties.name ?? agent.node;
              return (
                <li key={agent.node} className="traffic-list__row">
                  <span className="traffic-dot traffic-dot--on" />
                  <span className="traffic-list__name">
                    {name}
                    <span className="traffic-list__dest"> → {agent.dest}</span>
                  </span>
                  <button type="button" className="btn btn--light btn--xs" onClick={() => guard(() => traffic.stopBenign(agent.node))} disabled={busy}>
                    Arrêter
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </section>
    </aside>
  );
}
