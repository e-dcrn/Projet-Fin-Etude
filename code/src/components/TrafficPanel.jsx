import { useMemo, useState } from 'react';
import { availableBenignKinds, benignTargetsForDests, reachableDevices, trafficSources } from '../utils/trafficTargets.js';

// Types de trafic bénin : une case par service ouvert chez les destinataires
// (voir availableBenignKinds), identifiants de traffic_agent.py.
const WEB = ['http', 'https'];
const SERVICES = ['ssh', 'ftp', 'smtp', 'mysql', 'telnet', 'dns', 'tcp'];

// Presets : combinaisons prêtes à l'emploi (types + fréquence). Seuls les types
// disponibles chez les destinataires sont effectivement cochés.
const PRESETS = [
  { id: 'web', label: 'Navigation web', kinds: WEB, profile: 'moderate' },
  { id: 'ping', label: 'Pings réseau', kinds: ['icmp'], profile: 'steady' },
  { id: 'services', label: 'Connexions services', kinds: SERVICES, profile: 'slow' },
  { id: 'mixte', label: 'Mixte intense', kinds: ['icmp', ...WEB, ...SERVICES], profile: 'intense' },
];

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
 * (ping et un par service ouvert chez les destinataires), les émetteurs et les destinataires par cases à cocher,
 * ainsi que la fréquence. Le trafic « normal » de référence pour la sonde IDS.
 * Distinct des scénarios d'audit (voir ScenarioPanel).
 */
export default function TrafficPanel({ traffic, nodes, edges, onlineIds, onClose }) {
  const emitterList = useMemo(() => trafficSources(nodes, onlineIds), [nodes, onlineIds]);
  const destList = useMemo(() => reachableDevices(nodes, edges), [nodes, edges]);

  // Sélections stockées « à l'envers » (ids DÉcochés) : par défaut tout est coché,
  // et un nouvel équipement est coché d'office.
  const [kinds, setKinds] = useState(() => new Set(['icmp'])); // types cochés
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
  // Types proposés : seulement ceux des services ouverts chez les destinataires cochés.
  const kindList = availableBenignKinds(nodes, edges, selectedDestIds);
  const kindsArr = kindList.map((k) => k.id).filter((id) => kinds.has(id));

  const destLabel =
    selectedDestIds.length === destList.length ? 'tous'
      : selectedDestIds.length === 1 ? destList.find((d) => d.id === selectedDestIds[0])?.name ?? '1 cible'
        : `${selectedDestIds.length} cibles`;

  const applyPreset = (preset) => {
    setKinds(new Set(preset.kinds));
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
          <span className="field__label">Type de trafic (services ouverts chez les destinataires)</span>
          {kindList.length === 0 ? (
            <p className="panel-hint panel-hint--tight">Cochez au moins un destinataire.</p>
          ) : (
            <div className="check-row">
              {kindList.map((k) => (
                <label key={k.id} className="check" title={`Vers : ${k.hosts.join(', ')}`}>
                  <input type="checkbox" checked={kinds.has(k.id)} onChange={() => toggleOff(setKinds)(k.id)} />
                  <span>{k.label}</span>
                </label>
              ))}
            </div>
          )}
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
