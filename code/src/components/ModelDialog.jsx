import { useState } from 'react';
import JobProgress from './JobProgress.jsx';
import { FlowCounts, GroupInfo } from './DatasetDialog.jsx';
import { formatDate, formatDuration, formatPercent } from '../utils/format.js';

const MODE_SHORT = { binary: 'binaire', multiclass: 'multiclasse' };

/** Indicateurs clés d'un modèle, vus « comme un IDS » (détection / fausses alertes). */
function Kpis({ metrics }) {
  const tiles = [
    { label: 'Attaques détectées', value: metrics.detectionRate, hint: 'Part des flux d\'attaque signalés (rappel attaque).' },
    { label: 'Fausses alertes', value: metrics.falsePositiveRate, hint: 'Part des flux bénins signalés à tort comme attaque.' },
    { label: 'Exactitude', value: metrics.accuracy, hint: 'Part des flux bien classés.' },
    { label: 'F1 macro', value: metrics.macroF1, hint: 'Moyenne des F1 par classe : sensible aux classes minoritaires.' },
  ];
  return (
    <div className="kpis">
      {tiles.map((t) => (
        <div key={t.label} className="kpi" title={t.hint}>
          <span className="kpi__value">{formatPercent(t.value)}</span>
          <span className="kpi__label">{t.label}</span>
        </div>
      ))}
    </div>
  );
}

/** Matrice de confusion : lignes = vraie classe, colonnes = classe prédite ; intensité = part de la ligne. */
function ConfusionMatrix({ classes, matrix }) {
  return (
    <table className="confusion">
      <thead>
        <tr>
          <th className="confusion__corner">vraie ↓ / prédite →</th>
          {classes.map((c) => <th key={c} scope="col">{c}</th>)}
        </tr>
      </thead>
      <tbody>
        {matrix.map((row, i) => {
          const total = row.reduce((a, b) => a + b, 0);
          return (
            <tr key={classes[i]}>
              <th scope="row">{classes[i]}</th>
              {row.map((n, j) => {
                const share = total ? n / total : 0;
                return (
                  <td
                    key={classes[j]}
                    className={`confusion__cell${i === j ? ' confusion__cell--diag' : ''}${share > 0.55 ? ' confusion__cell--strong' : ''}`}
                    style={{ '--share': share }}
                    title={`${n} flux « ${classes[i]} » classés « ${classes[j]} » (${formatPercent(share)} de la ligne)`}
                  >
                    {n}
                  </td>
                );
              })}
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

/** Métriques par classe. */
function PerClass({ rows }) {
  return (
    <table className="metrics-table">
      <thead>
        <tr><th>Classe</th><th>Précision</th><th>Rappel</th><th>F1</th><th>Flux (test)</th></tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.label}>
            <td>{r.label}</td>
            <td>{formatPercent(r.precision)}</td>
            <td>{formatPercent(r.recall)}</td>
            <td>{formatPercent(r.f1)}</td>
            <td>{r.support}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** Features les plus utilisées par le modèle (importance random forest), en barres horizontales. */
function TopFeatures({ features }) {
  const max = Math.max(...features.map((f) => f.importance), 1e-9);
  return (
    <ul className="feature-bars">
      {features.map((f) => (
        <li key={f.name} className="feature-bars__row" title={`${f.name} : importance ${formatPercent(f.importance)}`}>
          <span className="feature-bars__name">{f.name}</span>
          <span className="feature-bars__track">
            <span className="feature-bars__bar" style={{ width: `${(f.importance / max) * 100}%` }} />
          </span>
          <span className="feature-bars__value">{formatPercent(f.importance)}</span>
        </li>
      ))}
    </ul>
  );
}

/** Résultats sur chaque dataset de test : un modèle peut réussir une variante et en rater une autre. */
function ByDataset({ rows }) {
  return (
    <section>
      <h3 className="traffic-section__title">Résultats par dataset de test</h3>
      <table className="metrics-table">
        <thead>
          <tr><th>Dataset</th><th>Flux</th><th>Attaques détectées</th><th>Fausses alertes</th><th>Exactitude</th></tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td>{r.name}</td>
              <td>{r.rows}</td>
              <td>{formatPercent(r.detectionRate)}</td>
              <td>{formatPercent(r.falsePositiveRate)}</td>
              <td>{formatPercent(r.accuracy)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

/** Rapport complet d'un modèle : indicateurs, matrice de confusion, métriques par classe, features. */
function ModelReport({ model }) {
  const { metrics, train, test } = model;
  const names = (list) => list.map((d) => d.name).join(', ');
  return (
    <div className="model-report">
      <Kpis metrics={metrics} />
      <p className="field__hint">
        Entraîné sur {names(train.datasets)} ({train.rows} flux) · testé sur{' '}
        {model.params.split === 'temporal'
          ? `les ${formatPercent(model.params.testFraction)} les plus récents de ce même jeu`
          : names(test.datasets)}{' '}
        ({test.rows} flux jamais vus) · {model.featureCount} features
        {model.params.excludePort ? ' (Dst Port exclu)' : ''}.
        {model.trainSeconds != null && (
          <>
            {' '}Calcul de l'entraînement : {model.params.nEstimators} arbres construits sur {train.rows} flux ×{' '}
            {model.featureCount} features en {model.trainSeconds.toLocaleString('fr-FR', { maximumFractionDigits: 2 })} s.
          </>
        )}
      </p>
      {metrics.byDataset?.length > 1 && <ByDataset rows={metrics.byDataset} />}
      <p className="field__hint">
        Topologie : {model.topologies?.length ? model.topologies.map((t) => t.name).join(', ') : 'inconnue'} · flux
        {model.flowWindowSec ? ` découpés en fenêtres de ${model.flowWindowSec} s (comme en détection)` : ' non découpés (ancien format : à réentraîner pour la détection en direct)'}.
      </p>
      {metrics.unseenClasses?.length > 0 && (
        <div className="issue-group issue-group--warning">
          Classes du test absentes de l'entraînement : {metrics.unseenClasses.join(', ')} (le modèle ne peut pas les reconnaître sous leur nom).
        </div>
      )}
      <div className="model-report__grid">
        <section>
          <h3 className="traffic-section__title">Matrice de confusion (test)</h3>
          <ConfusionMatrix classes={metrics.classes} matrix={metrics.confusion} />
          <h3 className="traffic-section__title">Par classe</h3>
          <PerClass rows={metrics.perClass} />
        </section>
        <section>
          <h3 className="traffic-section__title">Features les plus utiles</h3>
          <TopFeatures features={model.topFeatures} />
        </section>
      </div>
    </div>
  );
}

function DownloadLinks({ id, fileUrl }) {
  return (
    <span className="dataset__files">
      <a className="btn btn--light btn--xs" href={fileUrl(id, 'model.joblib')} download>⤓ modèle</a>
      <a className="btn btn--light btn--xs" href={fileUrl(id, 'meta.json')} download>⤓ métriques</a>
    </span>
  );
}

/**
 * Boîte de dialogue des modèles ML-IDS (voir useModels et backend/app/training.py) :
 *   list → modèles entraînés (indicateurs, rapport détaillé, téléchargement)
 *   form → entraînement d'un nouveau modèle sur les datasets sauvegardés
 *   et, pendant / après un entraînement, sa progression puis son rapport.
 */
export default function ModelDialog({ open, models, datasets, onClose }) {
  const [view, setView] = useState('list');
  if (!open) return null;

  const { run } = models;
  return (
    <div className="modal-backdrop">
      <div className="modal modal--wide" role="dialog" aria-modal="true" aria-labelledby="model-title">
        {run ? (
          <JobProgress
            run={run}
            titleId="model-title"
            titles={{ running: 'Entraînement…', done: 'Modèle entraîné', failed: 'Échec de l\'entraînement', cancelled: 'Entraînement annulé' }}
            doneCaption={run.result ? `${run.result.name} · ${formatDuration(run.result.durationSec)}` : ''}
            onCancel={models.cancel}
            onHide={onClose}
            onDone={() => { models.dismissRun(); setView('list'); }}
            doneLabel="Voir les modèles"
          >
            {run.result && <ModelReport model={run.result} />}
          </JobProgress>
        ) : view === 'form' ? (
          <FormContent models={models} datasets={datasets} onBack={() => setView('list')} />
        ) : (
          <ListContent models={models} hasDatasets={datasets.length > 0} onNew={() => setView('form')} onClose={onClose} />
        )}
      </div>
    </div>
  );
}

function ListContent({ models, hasDatasets, onNew, onClose }) {
  const [open, setOpen] = useState(null);
  const [error, setError] = useState(null);
  const remove = async (m) => {
    if (!window.confirm(`Supprimer le modèle « ${m.name} » ?`)) return;
    try {
      await models.remove(m.id);
    } catch (err) {
      setError(err.messages ? err.messages.join('\n') : String(err));
    }
  };

  return (
    <>
      <h2 id="model-title" className="modal__title">🧠 Modèles ML-IDS</h2>
      <p className="modal__text">
        Un modèle apprend, sur des datasets étiquetés, à distinguer les flux bénins des attaques. Il est toujours
        évalué sur des flux qu'il n'a jamais vus.
      </p>
      {(error || models.error) && <div className="traffic-error" role="alert">{error || models.error}</div>}

      {models.models.length === 0 ? (
        <p className="panel-hint">Aucun modèle pour le moment.</p>
      ) : (
        <ul className="dataset-list">
          {models.models.map((m) => (
            <li key={m.id} className="dataset">
              <div className="dataset__line">
                <strong className="dataset__name">{m.name}</strong>
                <span className="dataset__meta">
                  {formatDate(m.createdAt)} · {MODE_SHORT[m.mode]} · {m.topologies?.map((t) => t.name).join(', ') || 'topologie inconnue'}
                  {!m.flowWindowSec && ' · ancien format'} · détection {formatPercent(m.metrics.detectionRate)} ·
                  fausses alertes {formatPercent(m.metrics.falsePositiveRate)}
                </span>
              </div>
              <div className="dataset__actions">
                <button type="button" className="btn btn--light btn--xs" onClick={() => setOpen(open === m.id ? null : m.id)}>
                  {open === m.id ? 'Masquer le rapport' : 'Voir le rapport'}
                </button>
                <DownloadLinks id={m.id} fileUrl={models.fileUrl} />
                <button type="button" className="btn btn--light btn--xs dataset__delete" onClick={() => remove(m)}>
                  Supprimer
                </button>
              </div>
              {open === m.id && <ModelReport model={m} />}
            </li>
          ))}
        </ul>
      )}

      <div className="modal__actions">
        {!hasDatasets && <span className="modal__hint">Générez d'abord un dataset (🗂 Datasets).</span>}
        <button type="button" className="btn btn--light" onClick={onClose}>Fermer</button>
        <button type="button" className="btn btn--primary" onClick={onNew} disabled={!hasDatasets}>
          + Entraîner un modèle
        </button>
      </div>
    </>
  );
}

/** Sélection initiale du formulaire d'entraînement (datasets triés du plus récent au plus ancien). */
function defaultSelection(datasets) {
  const base = datasets.find((d) => d.group?.role === 'base');
  const variants = base ? datasets.filter((d) => d.group?.role === 'variant' && d.group.of === base.id) : [];
  if (base && variants.length) return { train: [base.id], test: variants.map((d) => d.id) };
  if (datasets.length > 1) return { train: [datasets[datasets.length - 1].id], test: [datasets[0].id] };
  return { train: datasets.map((d) => d.id), test: [] };
}

/** Liste de datasets à cocher ; `disabled` : ids non sélectionnables (déjà pris de l'autre côté). */
function DatasetChecklist({ datasets, selected, disabled, onToggle }) {
  return (
    <div className="check-list check-list--datasets">
      {datasets.map((ds) => (
        <label key={ds.id} className={`check check--dataset${disabled.has(ds.id) ? ' check--disabled' : ''}`}>
          <input type="checkbox" checked={selected.has(ds.id)} disabled={disabled.has(ds.id)} onChange={() => onToggle(ds.id)} />
          <span className="check__body">
            <span>{ds.name} <span className="dataset__meta">· {formatDate(ds.createdAt)} · {ds.total} flux</span></span>
            <GroupInfo dataset={ds} />
            <FlowCounts counts={ds.counts} />
          </span>
        </label>
      ))}
    </div>
  );
}

function FormContent({ models, datasets, onBack }) {
  const { options } = models;
  const [name, setName] = useState('');
  // Par défaut : le dernier dataset de base pour l'entraînement et ses variantes pour le test ;
  // sinon le plus ancien dataset pour l'entraînement et le plus récent pour le test.
  const [defaults] = useState(() => defaultSelection(datasets));
  const [train, setTrain] = useState(() => new Set(defaults.train));
  const [test, setTest] = useState(() => new Set(defaults.test));
  const [split, setSplit] = useState(defaults.test.length ? 'dataset' : 'temporal');
  const [testFraction, setTestFraction] = useState(30);
  const [mode, setMode] = useState('binary');
  const [model, setModel] = useState('random-forest');
  const [nEstimators, setNEstimators] = useState(100);
  const [maxDepth, setMaxDepth] = useState('');
  const [excludePort, setExcludePort] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const toggle = (setter) => (id) =>
    setter((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const canStart = train.size > 0 && (split === 'temporal' || test.size > 0) && !busy;

  // Datasets choisis venant de réseaux différents, ou préparés différemment (flux découpés ou non).
  const chosen = datasets.filter((d) => train.has(d.id) || (split === 'dataset' && test.has(d.id)));
  const topologyNames = [...new Set(chosen.map((d) => d.topology?.name ?? 'topologie inconnue'))];
  const mixedTopologies = new Set(chosen.map((d) => d.topology?.signature ?? '')).size > 1;
  const mixedWindows = new Set(chosen.map((d) => d.flowWindowSec ?? 0)).size > 1;

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await models.train({
        name,
        train: [...train],
        test: split === 'dataset' ? [...test] : [],
        split,
        testFraction: testFraction / 100,
        mode,
        model,
        nEstimators: Number(nEstimators),
        maxDepth: maxDepth ? Number(maxDepth) : null,
        excludePort,
      });
    } catch (err) {
      setError(err.messages ? err.messages.join('\n') : String(err));
      setBusy(false);
    }
  };

  return (
    <>
      <h2 id="model-title" className="modal__title">Entraîner un modèle</h2>
      {error && <div className="traffic-error" role="alert">{error}</div>}

      <div className="dataset-form">
        <label className="field field--compact">
          <span className="field__label">Nom</span>
          <input className="field__input" value={name} maxLength={80} placeholder="ex. RF binaire, scans petit LAN"
            onChange={(e) => setName(e.target.value)} />
        </label>

        {mixedTopologies && (
          <div className="issue-group issue-group--warning">
            Ces datasets viennent de topologies différentes ({topologyNames.join(', ')}) : le trafic n'y a pas les mêmes
            caractéristiques, le modèle ne vaudra pour aucune en particulier.
          </div>
        )}
        {mixedWindows && (
          <div className="issue-group issue-group--error">
            Ces datasets n'ont pas été préparés de la même façon (flux découpés en fenêtres ou non) : régénérez les plus
            anciens.
          </div>
        )}

        <h3 className="traffic-section__title">Données d'entraînement</h3>
        <DatasetChecklist datasets={datasets} selected={train} disabled={split === 'dataset' ? test : new Set()} onToggle={toggle(setTrain)} />

        <h3 className="traffic-section__title">Données de test (jamais vues à l'entraînement)</h3>
        <div className="check-row">
          {options.splits.map((s) => (
            <label key={s.id} className="check">
              <input type="radio" name="split" checked={split === s.id} onChange={() => setSplit(s.id)} />
              <span>{s.label}</span>
            </label>
          ))}
        </div>
        {split === 'dataset' ? (
          <DatasetChecklist datasets={datasets} selected={test} disabled={train} onToggle={toggle(setTest)} />
        ) : (
          <label className="field field--compact field--inline">
            <span className="field__label">Part gardée pour le test : {testFraction} % (les flux les plus récents)</span>
            <input type="range" min={10} max={50} step={5} value={testFraction} onChange={(e) => setTestFraction(Number(e.target.value))} />
          </label>
        )}
        <p className="field__hint">
          Un dataset de test séparé est l'évaluation la plus honnête. Le découpage temporel garde la fin du jeu pour le
          test ; attention, une attaque jouée une seule fois peut alors manquer d'un côté.
        </p>

        <h3 className="traffic-section__title">Modèle</h3>
        <div className="dataset-form__durations">
          <label className="field field--compact">
            <span className="field__label">Algorithme</span>
            <select className="field__input" value={model} onChange={(e) => setModel(e.target.value)}>
              {options.models.map((m) => <option key={m.id} value={m.id}>{m.label}</option>)}
            </select>
          </label>
          <label className="field field--compact">
            <span className="field__label">Classes</span>
            <select className="field__input" value={mode} onChange={(e) => setMode(e.target.value)}>
              {options.modes.map((m) => <option key={m.id} value={m.id}>{m.label}</option>)}
            </select>
          </label>
          <label className="field field--compact">
            <span className="field__label">Nombre d'arbres</span>
            <input className="field__input" type="number" min={10} max={500} value={nEstimators} onChange={(e) => setNEstimators(e.target.value)} />
          </label>
          <label className="field field--compact">
            <span className="field__label">Profondeur max.</span>
            <input className="field__input" type="number" min={2} max={100} value={maxDepth} placeholder="illimitée"
              onChange={(e) => setMaxDepth(e.target.value)} />
          </label>
        </div>
        <label className="check">
          <input type="checkbox" checked={excludePort} onChange={() => setExcludePort((v) => !v)} />
          <span>Exclure le port de destination (Dst Port)</span>
        </label>
        <p className="field__hint">
          Les IP, ports source, Flow ID et horodatage ne sont jamais utilisés : ils feraient apprendre « telle machine
          = attaque » au lieu d'un comportement. Dans un petit lab, le port de destination pose le même problème.
        </p>
      </div>

      <div className="modal__actions">
        <button type="button" className="btn btn--light" onClick={onBack} disabled={busy}>Retour</button>
        <button type="button" className="btn btn--primary" onClick={submit} disabled={!canStart}>▶ Entraîner</button>
      </div>
    </>
  );
}
