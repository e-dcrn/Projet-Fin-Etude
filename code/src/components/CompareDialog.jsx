import { useEffect, useMemo, useState } from 'react';
import { useAction } from '../hooks/useAction.js';
import { fetchScored } from '../services/topologyApi.js';
import { formatDate, formatDuration, formatPercent } from '../utils/format.js';

/*
 * Vue « Comparer deux runs » : on choisit deux datasets déjà enregistrés (par ex.
 * une attaque classique et sa variante furtive) et un modèle, puis on rejoue le
 * modèle sur les flux stockés de chaque run (GET /datasets/{id}/scored). On montre,
 * côte à côte, le rappel de l'attaque choisie, le nuage des flux (migration vers la
 * zone bénigne) et le détail d'un flux. Pédagogique : voir *pourquoi* une attaque
 * passe et l'autre non, au niveau des features que le modèle regarde.
 */

const COST_HINT = "L'évasion a un coût : comparez la durée des deux runs.";

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

/** Nuage de points d'un run : bénin (gris) + flux de l'attaque choisie (rouge = détecté, vert = raté/évadé). */
function Scatter({ run, focus, domain, axes }) {
  const W = 300, H = 230, pad = 34;
  const sx = (v) => pad + (domain.xmax > domain.xmin ? (log1p(v) - domain.xmin) / (domain.xmax - domain.xmin) : 0.5) * (W - 2 * pad);
  const sy = (v) => H - pad - (domain.ymax > domain.ymin ? (log1p(v) - domain.ymin) / (domain.ymax - domain.ymin) : 0.5) * (H - 2 * pad);

  const benign = sample(run.flows.filter((f) => f.label === 'BENIGN'), 250);
  const attack = run.flows.filter((f) => f.label === focus);
  const agg = run.summary.byLabel[focus] || { count: 0, detected: 0, recall: 0 };

  return (
    <figure className="compare-scatter">
      <figcaption>
        <strong>{run.name}</strong>
        <span className="dataset__meta"> · {attack.length} flux « {focus} » · détectés {formatPercent(agg.recall)}</span>
      </figcaption>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Nuage de flux du run ${run.name}`}>
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

/** Carte de synthèse d'un run pour l'attaque choisie : rappel, durée, vitesse. */
function RunCard({ run, focus }) {
  const agg = run.summary.byLabel[focus] || { count: 0, detected: 0, recall: 0 };
  const att = run.attacks.find((a) => a.subcategory === focus);
  return (
    <div className="kpi compare-card">
      <span className="kpi__value">{formatPercent(agg.recall)}</span>
      <span className="kpi__label">détectés — {run.name}</span>
      <span className="dataset__meta">
        {agg.detected}/{agg.count} flux{att?.speed ? ` · vitesse ${att.speed}` : ''}
        {run.durationSec != null ? ` · run ${formatDuration(run.durationSec)}` : ''}
      </span>
    </div>
  );
}

/** Détail d'un flux d'attaque représentatif (médian) de chaque run : les features que le modèle regarde. */
function FlowDrilldown({ runA, runB, focus, keyFeatures }) {
  const pick = (run) => {
    const atk = run.flows.filter((f) => f.label === focus);
    if (!atk.length) return null;
    const mid = median(atk.map((f) => f.x));
    return atk.reduce((best, f) => (Math.abs(f.x - mid) < Math.abs(best.x - mid) ? f : best), atk[0]);
  };
  const a = pick(runA), b = pick(runB);
  if (!a || !b) return null;
  return (
    <table className="metrics-table compare-drill">
      <thead>
        <tr><th>Feature (par flux)</th><th>{runA.name}</th><th>{runB.name}</th></tr>
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

export default function CompareDialog({ open, datasets, models, onClose }) {
  const [runA, setRunA] = useState('');
  const [runB, setRunB] = useState('');
  const [modelId, setModelId] = useState('');
  const [data, setData] = useState(null); // { a, b }
  const [focus, setFocus] = useState('');
  const { busy, error, act } = useAction();

  // Datasets et modèles arrivent de façon asynchrone : on fixe les défauts une
  // fois la liste chargée (Run A = le plus ancien, Run B = le plus récent).
  useEffect(() => {
    if (datasets.length) {
      setRunA((v) => v || datasets[datasets.length - 1].id);
      setRunB((v) => v || datasets[0].id);
    }
    if (models.length) setModelId((v) => v || models[0].id);
  }, [datasets, models]);

  const compare = () =>
    act(async () => {
      const [a, b] = await Promise.all([fetchScored(runA, modelId), fetchScored(runB, modelId)]);
      setData({ a, b });
      // Attaque par défaut : une sous-catégorie présente (comme attaque) dans les deux runs.
      const attacksOf = (r) => Object.entries(r.summary.byLabel).filter(([, v]) => v.isAttack).map(([k]) => k);
      const common = attacksOf(a).filter((k) => attacksOf(b).includes(k));
      setFocus(common.find((k) => k.includes('patator')) || common[0] || '');
    });

  const commonAttacks = useMemo(() => {
    if (!data) return [];
    const of = (r) => Object.entries(r.summary.byLabel).filter(([, v]) => v.isAttack).map(([k]) => k);
    return of(data.a).filter((k) => of(data.b).includes(k));
  }, [data]);

  // Échelle partagée entre les deux nuages (positions comparables d'un run à l'autre).
  const domain = useMemo(() => {
    if (!data || !focus) return null;
    const pts = [data.a, data.b].flatMap((r) => r.flows.filter((f) => f.label === 'BENIGN' || f.label === focus));
    const xs = pts.map((f) => log1p(f.x)), ys = pts.map((f) => log1p(f.y));
    return { xmin: Math.min(...xs, 0), xmax: Math.max(...xs, 1), ymin: Math.min(...ys, 0), ymax: Math.max(...ys, 1) };
  }, [data, focus]);

  if (!open) return null;
  const axes = data?.a.scatterAxes || { x: 'x', y: 'y' };
  const canCompare = runA && runB && modelId && runA !== runB && !busy;

  return (
    <div className="modal-backdrop">
      <div className="modal modal--wide" role="dialog" aria-modal="true" aria-labelledby="compare-title">
        <h2 id="compare-title" className="modal__title">⚖ Comparer deux runs</h2>
        <p className="modal__text">
          Rejoue un modèle sur les flux enregistrés de deux runs — par exemple une attaque classique et sa variante
          furtive — pour voir, au niveau des features, pourquoi l'une est détectée et l'autre non.
        </p>
        {error && <div className="traffic-error" role="alert">{error}</div>}

        <div className="compare-pick">
          <label className="field field--compact">
            <span className="field__label">Run A (classique)</span>
            <select className="field__input" value={runA} onChange={(e) => setRunA(e.target.value)}>
              {datasets.map((d) => <option key={d.id} value={d.id}>{d.name} · {formatDate(d.createdAt)}</option>)}
            </select>
          </label>
          <label className="field field--compact">
            <span className="field__label">Run B (furtif)</span>
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

        {datasets.length < 2 && <p className="panel-hint">Il faut au moins deux datasets enregistrés.</p>}
        {models.length === 0 && <p className="panel-hint">Entraînez d'abord un modèle (🧠 IDS).</p>}

        {data && focus && (
          <div className="compare-result">
            {commonAttacks.length > 1 && (
              <label className="field field--compact compare-focus">
                <span className="field__label">Attaque comparée</span>
                <select className="field__input" value={focus} onChange={(e) => setFocus(e.target.value)}>
                  {commonAttacks.map((k) => <option key={k} value={k}>{k}</option>)}
                </select>
              </label>
            )}

            <div className="kpis compare-band">
              <RunCard run={data.a} focus={focus} />
              <RunCard run={data.b} focus={focus} />
            </div>
            <p className="field__hint">{COST_HINT}</p>

            <div className="compare-scatters">
              {domain && <Scatter run={data.a} focus={focus} domain={domain} axes={axes} />}
              {domain && <Scatter run={data.b} focus={focus} domain={domain} axes={axes} />}
            </div>
            <p className="field__hint">
              <span className="compare-legend compare-legend--detected" /> détecté ·
              <span className="compare-legend compare-legend--missed" /> raté (évadé) ·
              <span className="compare-legend compare-legend--benign" /> flux bénins. Axes en échelle log.
              Les points d'attaque qui migrent dans le nuage bénin échappent au modèle.
            </p>

            <h3 className="traffic-section__title">Un flux représentatif de chaque run</h3>
            <FlowDrilldown runA={data.a} runB={data.b} focus={focus} keyFeatures={data.a.keyFeatures} />
          </div>
        )}

        <div className="modal__actions">
          <button type="button" className="btn btn--light" onClick={onClose}>Fermer</button>
        </div>
      </div>
    </div>
  );
}
