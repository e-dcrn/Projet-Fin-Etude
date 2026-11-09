import { useMemo, useState } from 'react';
import JobProgress from './JobProgress.jsx';
import { formatDate, formatDuration } from '../utils/format.js';
import { availableBenignKinds, benignTargetsForDests, deviceIp, reachableDevices, scenarioTargets, trafficSources } from '../utils/trafficTargets.js';

// Durées du programme (secondes) : bornes identiques à DatasetRequest (backend/app/main.py).
const DURATIONS = [
  { id: 'warmup', label: 'Bénin seul au début', min: 0, max: 600 },
  { id: 'gap', label: 'Bénin entre deux attaques', min: 0, max: 600 },
  { id: 'cooldown', label: 'Bénin seul à la fin', min: 0, max: 600 },
  { id: 'maxAttack', label: 'Durée max. d\'une attaque', min: 5, max: 600 },
];

let rowKey = 0;
const newRow = (fields) => ({ key: ++rowKey, attack: '', source: '', target: '', speed: 'fast', repeat: 2, ...fields });


/** Décompte des flux par étiquette (pastilles rouges pour les attaques). */
export function FlowCounts({ counts }) {
  return (
    <div className="flow-counts">
      {Object.entries(counts ?? {}).map(([label, n]) => (
        <span key={label} className={`flow-chip${label === 'BENIGN' ? '' : ' flow-chip--attack'}`}>
          {label} : {n}
        </span>
      ))}
    </div>
  );
}

/** Rôle d'un dataset dans un groupe : programme de base (avec N variantes) ou variante (et ce qui a changé). */
export function GroupInfo({ dataset }) {
  const group = dataset.group;
  if (!group) return null;
  if (group.role === 'base') {
    return <span className="dataset__group">Base · {group.variants} variante(s) de test générée(s)</span>;
  }
  return (
    <span className="dataset__group dataset__group--variant" title={group.changes?.join('\n')}>
      Variante {group.index} de test · {group.changes?.join(' ; ')}
    </span>
  );
}

function DownloadLinks({ id, fileUrl }) {
  return (
    <span className="dataset__files">
      <a className="btn btn--light btn--xs" href={fileUrl(id, 'flows.csv')} download>⤓ CSV</a>
      <a className="btn btn--light btn--xs" href={fileUrl(id, 'capture.pcap')} download>⤓ pcap</a>
      <a className="btn btn--light btn--xs" href={fileUrl(id, 'meta.json')} download>⤓ méta</a>
    </span>
  );
}

/**
 * Boîte de dialogue des datasets étiquetés (voir useDatasets et backend/app/datasets.py) :
 *   list → datasets sauvegardés (téléchargement, suppression)
 *   form → programme d'un nouveau dataset : sonde, trafic bénin, attaques, durées
 *   et, pendant / après une génération, sa progression.
 */
export default function DatasetDialog({ open, datasets, traffic, nodes, edges, onlineIds, labRunning, topology, onClose }) {
  const [view, setView] = useState('list');
  if (!open) return null;

  const { run } = datasets;
  return (
    <div className="modal-backdrop">
      <div className="modal modal--wide" role="dialog" aria-modal="true" aria-labelledby="dataset-title">
        {run ? (
          <RunContent
            run={run}
            datasets={datasets}
            onClose={onClose}
            onDone={() => { datasets.dismissRun(); setView('list'); }}
          />
        ) : view === 'form' ? (
          <FormContent
            topology={topology}
            datasets={datasets}
            traffic={traffic}
            nodes={nodes}
            edges={edges}
            onlineIds={onlineIds}
            onBack={() => setView('list')}
          />
        ) : (
          <ListContent datasets={datasets} labRunning={labRunning} hasIds={idsProbes(nodes, onlineIds).length > 0}
            onNew={() => setView('form')} onClose={onClose} />
        )}
      </div>
    </div>
  );
}

/** Sondes IDS allumées : le seul point de capture possible d'un dataset. */
function idsProbes(nodes, onlineIds) {
  return nodes.filter((n) => n.data?.deviceType === 'ids' && onlineIds.has(n.id))
    .map((n) => ({ id: n.id, name: n.data.properties.name }));
}

function ListContent({ datasets, labRunning, hasIds, onNew, onClose }) {
  const [error, setError] = useState(null);
  const remove = async (ds) => {
    if (!window.confirm(`Supprimer le dataset « ${ds.name} » ?`)) return;
    try {
      await datasets.remove(ds.id);
    } catch (err) {
      setError(err.messages ? err.messages.join('\n') : String(err));
    }
  };

  return (
    <>
      <h2 id="dataset-title" className="modal__title">🗂 Datasets étiquetés</h2>
      <p className="modal__text">
        Un dataset est produit en jouant un programme sur le réseau : trafic bénin en continu, attaques
        enchaînées, capture par une sonde, puis flux CICFlowMeter étiquetés (attaque / BENIGN).
      </p>
      {(error || datasets.error) && <div className="traffic-error" role="alert">{error || datasets.error}</div>}

      {datasets.datasets.length === 0 ? (
        <p className="panel-hint">Aucun dataset pour le moment.</p>
      ) : (
        <ul className="dataset-list">
          {datasets.datasets.map((ds) => (
            <li key={ds.id} className="dataset">
              <div className="dataset__line">
                <strong className="dataset__name">{ds.name}</strong>
                <span className="dataset__meta">
                  {formatDate(ds.createdAt)} · {formatDuration(ds.durationSec)} · {ds.total} flux · sonde {ds.probe?.name}
                  {' '}· topologie {ds.topology?.name ?? 'inconnue'}
                  {!ds.flowWindowSec && ' · ancien format (flux non découpés)'}
                </span>
              </div>
              <GroupInfo dataset={ds} />
              <FlowCounts counts={ds.counts} />
              <div className="dataset__actions">
                <DownloadLinks id={ds.id} fileUrl={datasets.fileUrl} />
                <button type="button" className="btn btn--light btn--xs dataset__delete" onClick={() => remove(ds)}>
                  Supprimer
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}

      <div className="modal__actions">
        {!labRunning ? (
          <span className="modal__hint">Démarrez le réseau pour générer un dataset.</span>
        ) : !hasIds && (
          <span className="modal__hint">
            Pas de dataset possible : la topologie n'a aucune Sonde IDS, donc aucun point de capture.
          </span>
        )}
        <button type="button" className="btn btn--light" onClick={onClose}>Fermer</button>
        <button type="button" className="btn btn--primary" onClick={onNew} disabled={!labRunning || !hasIds}>
          + Nouveau dataset
        </button>
      </div>
    </>
  );
}

function FormContent({ datasets, traffic, nodes, edges, onlineIds, topology, onBack }) {
  const sources = useMemo(() => trafficSources(nodes, onlineIds), [nodes, onlineIds]);
  // Point de capture : toujours une Sonde IDS (tout le segment, comme la détection en direct).
  const probes = useMemo(() => idsProbes(nodes, onlineIds), [nodes, onlineIds]);
  const dests = useMemo(() => reachableDevices(nodes, edges), [nodes, edges]);
  // Types de trafic bénin proposés : seulement ceux des services ouverts dans la topologie.
  const kindList = useMemo(() => availableBenignKinds(nodes, edges, dests.map((d) => d.id)), [nodes, edges, dests]);
  const ipTargets = useMemo(() => scenarioTargets(nodes, edges, 'ip'), [nodes, edges]);
  const subnetTargets = useMemo(() => scenarioTargets(nodes, edges, 'subnet'), [nodes, edges]);

  // Valeurs par défaut : la première Sonde IDS, les PC comme émetteurs de trafic
  // bénin, et un premier scan du premier serveur depuis un PC.
  const [probeChoice, setProbe] = useState('');
  const probe = probes.some((p) => p.id === probeChoice) ? probeChoice : (probes[0]?.id ?? '');
  const serverIp = deviceIp(edges, sources.find((s) => s.type === 'server')?.id ?? '');
  const defaultTarget = () => serverIp || ipTargets[0]?.value || '';
  const [name, setName] = useState('');
  const [emittersOff, setEmittersOff] = useState(() => new Set(sources.filter((s) => s.type !== 'pc').map((s) => s.id)));
  const [kindsOff, setKindsOff] = useState(() => new Set()); // types décochés (un type disponible est coché d'office)
  const [profile, setProfile] = useState('moderate');
  const [rows, setRows] = useState(() => {
    const pc = sources.find((s) => s.type === 'pc');
    return [newRow({ attack: 'tcp-connect-scan', source: pc?.id ?? '', target: defaultTarget() })];
  });
  const [durations, setDurations] = useState({ warmup: 30, gap: 10, cooldown: 20, maxAttack: 60 });
  const [variants, setVariants] = useState(2);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const attackOf = (id) => traffic.attacks.find((a) => a.id === id);
  const updateRow = (key, fields) => setRows((prev) => prev.map((r) => (r.key === key ? { ...r, ...fields } : r)));
  const toggleEmitter = (id) =>
    setEmittersOff((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const emitters = sources.filter((s) => !emittersOff.has(s.id));
  const kindsArr = kindList.map((k) => k.id).filter((id) => !kindsOff.has(id));
  const toggleKind = (id) =>
    setKindsOff((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const runCount = rows.reduce((n, r) => n + Number(r.repeat || 0), 0);
  // Pire cas : chaque attaque va jusqu'à sa durée maximale (+ ~30 s d'extraction des flux).
  const maxSeconds = (durations.warmup + runCount * durations.maxAttack + Math.max(runCount - 1, 0) * durations.gap
    + durations.cooldown + 30) * (1 + variants);
  const rowsValid = rows.length > 0 && rows.every((r) => r.attack && r.source && r.target && r.repeat >= 1);
  const canStart = probe && rowsValid && (emitters.length === 0 || kindsArr.length > 0) && !busy;

  const submit = async () => {
    setBusy(true);
    setError(null);
    const allDestIds = dests.map((d) => d.id);
    try {
      await datasets.generate({
        name,
        topology,
        probe,
        kinds: kindsArr,
        profile,
        benign: emitters.map((em) => ({ node: em.id, targets: benignTargetsForDests(nodes, edges, em.id, allDestIds) })),
        attacks: rows.map(({ attack, source, target, speed, repeat }) => ({ attack, source, target, speed, repeat: Number(repeat) })),
        ...durations,
        variants,
      });
    } catch (err) {
      setError(err.messages ? err.messages.join('\n') : String(err));
      setBusy(false);
    }
  };

  return (
    <>
      <h2 id="dataset-title" className="modal__title">Nouveau dataset</h2>
      <p className="modal__text">
        Sur la topologie <strong>{topology.name}</strong> ({topology.summary}) : un modèle entraîné sur ce dataset ne
        vaudra que pour ce réseau.
      </p>
      {error && <div className="traffic-error" role="alert">{error}</div>}
      {probes.length === 0 && (
        <div className="traffic-error" role="alert">
          Pas de dataset possible : aucune Sonde IDS allumée, donc aucun point de capture. Ajoutez une Sonde IDS reliée
          au switch à surveiller, puis validez la topologie.
        </div>
      )}
      {sources.length === 0 && (
        <div className="traffic-error" role="alert">
          Aucun équipement allumé dans la topologie affichée : chargez la topologie du réseau en cours (ou validez-la
          pour la démarrer).
        </div>
      )}

      <div className="dataset-form">
        <div className="dataset-form__grid">
          <label className="field field--compact">
            <span className="field__label">Nom</span>
            <input className="field__input" value={name} placeholder="ex. Scans + force brute, petit LAN"
              onChange={(e) => setName(e.target.value)} maxLength={80} />
          </label>
          {probes.length > 1 ? (
            <label className="field field--compact">
              <span className="field__label">Sonde IDS (point de capture)</span>
              <select className="field__input" value={probe} onChange={(e) => setProbe(e.target.value)}>
                {probes.map((s) => (
                  <option key={s.id} value={s.id}>{s.name}</option>
                ))}
              </select>
            </label>
          ) : (
            <div className="field field--compact">
              <span className="field__label">Point de capture</span>
              <span className="field__input field__input--static">{probes[0]?.name ?? 'aucune Sonde IDS'}</span>
            </div>
          )}
        </div>
        <p className="field__hint">
          La capture se fait toujours sur la Sonde IDS : elle reçoit une copie de tout le trafic du switch qu'elle
          surveille, le même point de vue que la détection en direct.
        </p>

        <h3 className="traffic-section__title">Trafic bénin (en continu)</h3>
        <div className="dataset-form__grid">
          <div className="traffic-field">
            <span className="field__label">Émetteurs</span>
            <div className="check-row">
              {sources.map((s) => (
                <label key={s.id} className="check">
                  <input type="checkbox" checked={!emittersOff.has(s.id)} onChange={() => toggleEmitter(s.id)} />
                  <span>{s.name}</span>
                </label>
              ))}
            </div>
          </div>
          <label className="field field--compact">
            <span className="field__label">Fréquence (par émetteur)</span>
            <select className="field__input" value={profile} onChange={(e) => setProfile(e.target.value)}>
              {traffic.profiles.map((p) => (
                <option key={p.id} value={p.id}>{p.label}</option>
              ))}
            </select>
          </label>
        </div>
        <div className="traffic-field">
          <span className="field__label">Types (services ouverts dans la topologie)</span>
          <div className="check-row">
            {kindList.map((k) => (
              <label key={k.id} className="check" title={`Vers : ${k.hosts.join(', ')}`}>
                <input type="checkbox" checked={!kindsOff.has(k.id)} onChange={() => toggleKind(k.id)} />
                <span>{k.label}</span>
              </label>
            ))}
          </div>
          {kindList.some((k) => k.id === 'dns') && (
            <p className="field__hint">Le DNS n'est pas une session à part : ce sont des résolutions de noms avant les autres sessions.</p>
          )}
        </div>

        <h3 className="traffic-section__title">Attaques (jouées l'une après l'autre)</h3>
        <table className="attack-table">
          <thead>
            <tr>
              <th>Attaque</th><th>Depuis</th><th>Cible</th><th>Vitesse</th><th>Fois</th><th aria-label="Retirer" />
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const attack = attackOf(r.attack);
              const targets = attack?.needs === 'subnet' ? subnetTargets : ipTargets;
              return (
                <tr key={r.key}>
                  <td>
                    <select className="field__input" value={r.attack} aria-label="Attaque" title={attack?.volume}
                      onChange={(e) => {
                        const next = attackOf(e.target.value);
                        updateRow(r.key, { attack: e.target.value, target: next?.needs === 'subnet' ? (subnetTargets[0]?.value ?? '') : defaultTarget() });
                      }}>
                      <option value="" disabled>Choisir…</option>
                      {traffic.attacks.map((a) => (
                        <option key={a.id} value={a.id}>{a.name}</option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <select className="field__input" value={r.source} aria-label="Source" onChange={(e) => updateRow(r.key, { source: e.target.value })}>
                      <option value="" disabled>Choisir…</option>
                      {sources.map((s) => (
                        <option key={s.id} value={s.id}>{s.name}</option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <select className="field__input" value={r.target} aria-label="Cible" onChange={(e) => updateRow(r.key, { target: e.target.value })}>
                      <option value="" disabled>Choisir…</option>
                      {targets.map((t) => (
                        <option key={t.value} value={t.value}>{t.label}</option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <select className="field__input" value={r.speed} aria-label="Vitesse"
                      title={traffic.speeds.find((s) => s.id === r.speed)?.cadence?.[attack?.tool]} onChange={(e) => updateRow(r.key, { speed: e.target.value })}>
                      {traffic.speeds.map((s) => (
                        <option key={s.id} value={s.id}>{s.label}</option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <input className="field__input attack-table__repeat" type="number" min={1} max={10} value={r.repeat}
                      aria-label="Répétitions" onChange={(e) => updateRow(r.key, { repeat: e.target.value })} />
                  </td>
                  <td>
                    <button type="button" className="icon-btn" title="Retirer"
                      onClick={() => setRows((prev) => prev.filter((x) => x.key !== r.key))}>×</button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <button type="button" className="btn btn--light btn--xs"
          onClick={() => setRows((prev) => [...prev, newRow({ source: prev[prev.length - 1]?.source ?? '', target: defaultTarget() })])}>
          + Ajouter une attaque
        </button>

        <h3 className="traffic-section__title">Durées (secondes)</h3>
        <div className="dataset-form__durations">
          {DURATIONS.map((d) => (
            <label key={d.id} className="field field--compact">
              <span className="field__label">{d.label}</span>
              <input className="field__input" type="number" min={d.min} max={d.max} value={durations[d.id]}
                onChange={(e) => setDurations((prev) => ({ ...prev, [d.id]: Math.min(d.max, Math.max(d.min, Number(e.target.value) || 0)) }))} />
            </label>
          ))}
        </div>
        <h3 className="traffic-section__title">Datasets de test</h3>
        <label className="field field--compact field--inline-row">
          <span className="field__label">Variantes générées automatiquement après ce dataset</span>
          <input className="field__input" type="number" min={0} max={5} value={variants}
            onChange={(e) => setVariants(Math.min(5, Math.max(0, Number(e.target.value) || 0)))} />
        </label>
        <p className="field__hint">
          Chaque variante rejoue ce programme avec les mêmes attaques et les mêmes cibles, mais lancées depuis d'autres
          machines, à d'autres vitesses, avec un trafic bénin d'une autre intensité. Elles servent de datasets de test :
          le modèle est entraîné sur ce dataset et évalué sur ses variantes, qu'il n'a jamais vues.
        </p>

        <p className="field__hint">
          {runCount} attaque(s) au programme{variants > 0 ? `, ${1 + variants} datasets au total` : ''} · durée maximale ≈ {formatDuration(maxSeconds)}. Une attaque plus longue
          que sa durée maximale est interrompue. Le trafic bénin déjà en cours est remplacé par celui du programme.
        </p>
      </div>

      <div className="modal__actions">
        <button type="button" className="btn btn--light" onClick={onBack} disabled={busy}>Retour</button>
        <button type="button" className="btn btn--primary" onClick={submit} disabled={!canStart}>
          ▶ Générer le dataset
        </button>
      </div>
    </>
  );
}

function RunContent({ run, datasets, onClose, onDone }) {
  const dataset = run.result;
  const produced = run.done?.datasets ?? (dataset ? [dataset] : []);
  return (
    <JobProgress
      run={run}
      titleId="dataset-title"
      titles={{ running: 'Génération du dataset…', done: produced.length > 1 ? 'Datasets prêts' : 'Dataset prêt', failed: 'Échec de la génération', cancelled: 'Génération annulée' }}
      doneCaption={produced.length > 1 ? `${produced.length} datasets générés` : `${dataset?.total ?? 0} flux étiquetés`}
      onCancel={datasets.cancel}
      onHide={onClose}
      onDone={onDone}
      doneLabel="Voir les datasets"
    >
      {produced.map((ds) => (
        <div key={ds.id} className="dataset dataset--result">
          <div className="dataset__line">
            <strong className="dataset__name">{ds.name}</strong>
            <span className="dataset__meta">
              {formatDuration(ds.durationSec)} · sonde {ds.probe?.name}
            </span>
          </div>
          <GroupInfo dataset={ds} />
          <FlowCounts counts={ds.counts} />
          <div className="dataset__actions">
            <DownloadLinks id={ds.id} fileUrl={datasets.fileUrl} />
          </div>
        </div>
      ))}
    </JobProgress>
  );
}
