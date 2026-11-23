import { useEffect, useMemo, useState } from 'react';
import { useAction } from '../hooks/useAction.js';
import { fetchScored } from '../services/topologyApi.js';
import { formatDate, formatDuration, formatPercent } from '../utils/format.js';

/*
 * Vue « Comparer deux runs » : on choisit deux datasets déjà enregistrés et un
 * modèle, puis on rejoue le modèle sur les flux stockés de chaque run
 * (GET /datasets/{id}/scored). L'intérêt pédagogique est de mettre face à face
 * une attaque *classique* et sa variante *furtive* — deux étiquettes différentes
 * (ex. ftp-patator vs ftp-patator-stealth), qu'on choisit **côté par côté**. Les
 * deux côtés peuvent viser le même run (s'il contient les deux attaques) ou deux
 * runs distincts. On voit alors *pourquoi* l'une est détectée et l'autre non, au
 * niveau des features que le modèle regarde.
 */

// Échelle log (les tailles / débits s'étalent sur plusieurs ordres de grandeur).
const log1p = (v) => Math.log10(1 + Math.max(0, v));

function sample(arr, max) {
  if (arr.length <= max) return arr;
  const step = arr.length / max;
  return Array.from({ length: max }, (_, i) => arr[Math.floor(i * step)]);
}

function median(nums) {
  if (!nums.length) return null;
  const s = [...nums].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

/** Étiquettes d'attaque d'un run scoré (Label != BENIGN). */
const attacksOf = (run) =>
  Object.entries(run.summary.byLabel).filter(([, v]) => v.isAttack).map(([k]) => k);

/** Attaque furtive par défaut d'un run : une variante « stealth », sinon ftp-patator, sinon la première. */
function defaultFocus(run, { preferStealth }) {
  const atk = attacksOf(run);
  if (preferStealth) return atk.find((k) => k.includes('stealth')) || atk.find((k) => k.includes('patator')) || atk[0] || '';
  return atk.find((k) => k.includes('patator') && !k.includes('stealth')) || atk.find((k) => !k.includes('stealth')) || atk[0] || '';
}

/** Nuage de points d'un run pour une attaque : bénin (gris) + flux d'attaque (rouge = détecté, vert = raté/évadé). */
function Scatter({ run, focus, domain, axes, tint }) {
  const W = 300, H = 230, pad = 34;
  const sx = (v) => pad + (domain.xmax > domain.xmin ? (log1p(v) - domain.xmin) / (domain.xmax - domain.xmin) : 0.5) * (W - 2 * pad);
  const sy = (v) => H - pad - (domain.ymax > domain.ymin ? (log1p(v) - domain.ymin) / (domain.ymax - domain.ymin) : 0.5) * (H - 2 * pad);

  const benign = sample(run.flows.filter((f) => f.label === 'BENIGN'), 250);
  const attack = run.flows.filter((f) => f.label === focus);
  const agg = run.summary.byLabel[focus] || { count: 0, detected: 0, recall: 0 };

  return (
    <figure className="compare-scatter">
      <figcaption>
        <strong className={`compare-tint compare-tint--${tint}`}>{focus || '—'}</strong>
        <span className="dataset__meta"> · {run.name} · {attack.length} flux · détectés {formatPercent(agg.recall)}</span>
      </figcaption>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Nuage de flux « ${focus} » du run ${run.name}`}>
        <rect x={pad} y={pad} width={W - 2 * pad} height={H - 2 * pad} className="compare-scatter__frame" />
        {benign.map((f, i) => <circle key={`b${i}`} cx={sx(f.x)} cy={sy(f.y)} r="2.2" className="compare-scatter__benign" />)}
        {attack.map((f, i) => (
          <circle key={`a${i}`} cx={sx(f.x)} cy={sy(f.y)} r="3.4"
            className={f.detected ? 'compare-scatter__detected' : 'compare-scatter__missed'}>
            <title>{`${focus} — ${f.detected ? 'détecté' : 'raté (évadé)'} · ${axes.x}=${Math.round(f.x)} · ${axes.y}=${Math.round(f.y)}`}</title>
          </circle>
        ))}
        <text x={W / 2} y={H - 6} className="compare-scatter__axis">{axes.x} →</text>
        <text x={10} y={H / 2} className="compare-scatter__axis" transform={`rotate(-90 10 ${H / 2})`}>{axes.y} →</text>
      </svg>
    </figure>
  );
}

/** Carte de synthèse d'un côté : rappel de l'attaque choisie, durée et vitesse du run. */
function RunCard({ run, focus, tint }) {
  const agg = run.summary.byLabel[focus] || { count: 0, detected: 0, recall: 0 };
  const att = run.attacks.find((a) => a.subcategory === focus);
  return (
    <div className={`kpi compare-card compare-card--${tint}`}>
      <span className="kpi__value">{formatPercent(agg.recall)}</span>
      <span className="kpi__label">détectés — {focus}</span>
      <span className="dataset__meta">
        {agg.detected}/{agg.count} flux{att?.speed ? ` · vitesse ${att.speed}` : ''}
        {run.durationSec != null ? ` · run ${formatDuration(run.durationSec)}` : ''}
      </span>
    </div>
  );
}

/** Détail d'un flux d'attaque représentatif (médian) de chaque côté : les features que le modèle regarde. */
function FlowDrilldown({ runA, focusA, runB, focusB, keyFeatures }) {
  const pick = (run, focus) => {
    const atk = run.flows.filter((f) => f.label === focus);
    if (!atk.length) return null;
    const mid = median(atk.map((f) => f.x));
    return atk.reduce((best, f) => (Math.abs(f.x - mid) < Math.abs(best.x - mid) ? f : best), atk[0]);
  };
  const a = pick(runA, focusA), b = pick(runB, focusB);
  if (!a || !b) return null;
  return (
    <table className="metrics-table compare-drill">
      <thead>
        <tr><th>Feature (par flux)</th><th>{focusA}</th><th>{focusB}</th></tr>
      </thead>
      <tbody>
        {keyFeatures.map((k) => (
          <tr key={k}>
            <td>{k}</td>
            <td>{Math.round(a.features[k]).toLocaleString('fr-FR')}</td>
            <td>{Math.round(b.features[k]).toLocaleString('fr-FR')}</td>
          </tr>
        ))}
        <tr className="compare-drill__verdict">
          <td>Verdict du modèle</td>
          <td className={a.detected ? 'verdict--attack' : 'verdict--benign'}>{a.detected ? 'ATTACK ✓' : 'BENIGN ✗'}</td>
          <td className={b.detected ? 'verdict--attack' : 'verdict--benign'}>{b.detected ? 'ATTACK ✓' : 'BENIGN ✗'}</td>
        </tr>
      </tbody>
    </table>
  );
}

/** Sélecteur d'attaque pour un côté. */
function AttackSelect({ label, value, options, tint, onChange }) {
  return (
    <label className="field field--compact">
      <span className="field__label">{label}</span>
      <select className={`field__input compare-select--${tint}`} value={value} onChange={(e) => onChange(e.target.value)}>
        {options.length === 0 && <option value="">(aucune attaque)</option>}
        {options.map((k) => <option key={k} value={k}>{k}</option>)}
      </select>
    </label>
  );
}

export default function CompareDialog({ open, datasets, models, onClose }) {
  const [runA, setRunA] = useState('');
  const [runB, setRunB] = useState('');
  const [modelId, setModelId] = useState('');
  const [data, setData] = useState(null);   // { a, b }
  const [focusA, setFocusA] = useState('');  // étiquette d'attaque du côté A
  const [focusB, setFocusB] = useState('');  // étiquette d'attaque du côté B
  const { busy, error, act } = useAction();

  // Datasets / modèles chargés de façon asynchrone : on fixe les défauts à l'arrivée.
  // Si un run contient à la fois une attaque classique et sa variante furtive, on
  // vise ce run des deux côtés (comparaison classique vs furtif immédiate).
  useEffect(() => {
    if (datasets.length) {
      const dual = datasets.find((d) => d.counts && Object.keys(d.counts).some((k) => k.includes('stealth'))
        && Object.keys(d.counts).some((k) => k.includes('patator') && !k.includes('stealth')));
      setRunA((v) => v || (dual ? dual.id : datasets[datasets.length - 1].id));
      setRunB((v) => v || (dual ? dual.id : datasets[0].id));
    }
    if (models.length) setModelId((v) => v || models[0].id);
  }, [datasets, models]);

  const compare = () =>
    act(async () => {
      const [a, b] = await Promise.all([fetchScored(runA, modelId), fetchScored(runB, modelId)]);
      setData({ a, b });
      setFocusA(defaultFocus(a, { preferStealth: false }));
      setFocusB(defaultFocus(b, { preferStealth: true }));
    });

  const attacksA = useMemo(() => (data ? attacksOf(data.a) : []), [data]);
  const attacksB = useMemo(() => (data ? attacksOf(data.b) : []), [data]);

  // Échelle partagée entre les deux nuages (positions comparables d'un côté à l'autre).
  const domain = useMemo(() => {
    if (!data || !focusA || !focusB) return null;
    const pts = [
      ...data.a.flows.filter((f) => f.label === 'BENIGN' || f.label === focusA),
      ...data.b.flows.filter((f) => f.label === 'BENIGN' || f.label === focusB),
    ];
    const xs = pts.map((f) => log1p(f.x)), ys = pts.map((f) => log1p(f.y));
    return { xmin: Math.min(...xs, 0), xmax: Math.max(...xs, 1), ymin: Math.min(...ys, 0), ymax: Math.max(...ys, 1) };
  }, [data, focusA, focusB]);

  if (!open) return null;
  const axes = data?.a.scatterAxes || { x: 'x', y: 'y' };
  const canCompare = runA && runB && modelId && !busy;
  const ready = data && focusA && focusB;

  return (
    <div className="modal-backdrop">
      <div className="modal modal--wide" role="dialog" aria-modal="true" aria-labelledby="compare-title">
        <h2 id="compare-title" className="modal__title">⚖ Comparer deux attaques</h2>
        <p className="modal__text">
          Rejoue un modèle sur les flux enregistrés de deux runs, puis met face à face l'attaque <strong>classique</strong>
          {' '}et sa variante <strong>furtive</strong> (on choisit l'attaque de chaque côté). On voit, au niveau des features,
          pourquoi l'une est détectée et l'autre évade le modèle. Les deux côtés peuvent viser le même run.
        </p>
        {error && <div className="traffic-error" role="alert">{error}</div>}

        <div className="compare-pick">
          <label className="field field--compact">
            <span className="field__label">Run A</span>
            <select className="field__input" value={runA} onChange={(e) => setRunA(e.target.value)}>
              {datasets.map((d) => <option key={d.id} value={d.id}>{d.name} · {formatDate(d.createdAt)}</option>)}
            </select>
          </label>
          <label className="field field--compact">
            <span className="field__label">Run B</span>
            <select className="field__input" value={runB} onChange={(e) => setRunB(e.target.value)}>
              {datasets.map((d) => <option key={d.id} value={d.id}>{d.name} · {formatDate(d.createdAt)}</option>)}
            </select>
          </label>
          <label className="field field--compact">
            <span className="field__label">Modèle</span>
            <select className="field__input" value={modelId} onChange={(e) => setModelId(e.target.value)}>
              {models.map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}
            </select>
          </label>
          <button type="button" className="btn btn--primary" onClick={compare} disabled={!canCompare}>
            {busy ? 'Calcul…' : 'Comparer'}
          </button>
        </div>

        {datasets.length < 1 && <p className="panel-hint">Aucun dataset enregistré.</p>}
        {models.length === 0 && <p className="panel-hint">Entraînez d'abord un modèle (🧠 IDS).</p>}

        {ready && (
          <div className="compare-result">
            <div className="compare-pick compare-attacks">
              <AttackSelect label="Attaque A (classique)" value={focusA} options={attacksA} tint="a" onChange={setFocusA} />
              <AttackSelect label="Attaque B (furtive)" value={focusB} options={attacksB} tint="b" onChange={setFocusB} />
            </div>

            <div className="kpis compare-band">
              <RunCard run={data.a} focus={focusA} tint="a" />
              <RunCard run={data.b} focus={focusB} tint="b" />
            </div>
            <p className="field__hint">
              Même attaque, costume différent : si la furtive échappe au modèle (rappel bas), l'évasion marche —
              au prix d'une durée plus longue (comparez les durées de run).
            </p>

            <div className="compare-scatters">
              {domain && <Scatter run={data.a} focus={focusA} domain={domain} axes={axes} tint="a" />}
              {domain && <Scatter run={data.b} focus={focusB} domain={domain} axes={axes} tint="b" />}
            </div>
            <p className="field__hint">
              <span className="compare-legend compare-legend--detected" /> détecté ·
              <span className="compare-legend compare-legend--missed" /> raté (évadé) ·
              <span className="compare-legend compare-legend--benign" /> flux bénins. Axes en échelle log.
              Les points d'attaque qui migrent dans le nuage bénin échappent au modèle.
            </p>

            <h3 className="traffic-section__title">Un flux représentatif de chaque attaque</h3>
            <FlowDrilldown runA={data.a} focusA={focusA} runB={data.b} focusB={focusB} keyFeatures={data.a.keyFeatures} />
          </div>
        )}

        <div className="modal__actions">
          <button type="button" className="btn btn--light" onClick={onClose}>Fermer</button>
        </div>
      </div>
    </div>
  );
}
