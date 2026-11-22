/**
 * Couche d'accès au moteur de simulation (backend/, voir README).
 *
 * Les tâches longues (génération d'un dataset, entraînement) renvoient un
 * identifiant, puis l'interface redemande leur état toutes les secondes
 * (GET /jobs/{id}, voir followJob).
 */

// URL du moteur de simulation (backend/), lancé sur le port 8000
const API_BASE_URL = 'http://localhost:8000/api';

const UNREACHABLE = 'Le moteur de simulation est injoignable : vérifiez qu\'il est lancé (voir README).';

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers: { 'Content-Type': 'application/json', ...options.headers },
    });
  } catch {
    throw new Error(UNREACHABLE);
  }
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    // Erreur prévue (HTTPException) : { detail: "message" } ; requête mal formée (422) : detail est une liste.
    throw new Error(typeof body.detail === 'string' ? body.detail : `Le serveur a refusé la requête (code ${response.status}).`);
  }
  return body;
}

/** État du réseau : { running, topology: "1-petit-lan" ou null, devices: [{ id, running }] } */
export const fetchLabStatus = () => request('/lab');

/** Démarre une topologie (docker compose up) → nouvel état du réseau. */
export const startLab = (topology) => request('/lab', { method: 'POST', body: JSON.stringify({ topology }) });

/** Arrête le réseau (docker compose down) → nouvel état du réseau. */
export const stopLab = () => request('/lab', { method: 'DELETE' });

// --- Génération de trafic (voir backend/app/traffic.py) --------------------

/**
 * Activité de trafic et catalogues :
 * { benign: [{ node, profile }], scenarios: [...], profiles: [...], attacks: [...] }
 */
export const fetchTraffic = () => request('/lab/traffic');

/** Démarre le trafic de fond (bénin) sur un équipement. `targets` : [{ ip, server }] ;
 *  `kinds` : types de trafic (« icmp », « http », « ssh », « ftp ») ; `dest` : libellé d'affichage. */
export const startBenign = (node, profile, targets, dest = 'all', kinds = ['icmp']) =>
  request('/lab/traffic/benign', { method: 'POST', body: JSON.stringify({ node, profile, dest, kinds, targets }) });

/** Arrête le trafic de fond : un équipement (node) ou tous (node omis). */
export const stopBenign = (node) =>
  request(`/lab/traffic/benign${node ? `?node=${encodeURIComponent(node)}` : ''}`, { method: 'DELETE' });

/** Lance un scénario d'audit (une fois) depuis `source` vers `target`, à la vitesse `speed` → description du scénario. */
export const runScenario = (source, attack, target, speed = 'fast') =>
  request('/lab/scenarios', { method: 'POST', body: JSON.stringify({ source, attack, target, speed }) });

/** Résultat (sortie) d'un scénario terminé ou en cours. */
export const fetchScenarioLogs = (id) => request(`/lab/scenarios/${encodeURIComponent(id)}/logs`);

/** Interrompt un scénario en cours (id), ou tous les scénarios en cours (sans id). */
export const stopScenarios = (id) =>
  request(`/lab/scenarios/stop${id ? `?id=${encodeURIComponent(id)}` : ''}`, { method: 'POST' });

/** Supprime les scénarios terminés. */
export const clearScenarios = () => request('/lab/scenarios', { method: 'DELETE' });

// --- Détection en direct (voir backend/app/detection.py) -------------------

/**
 * État de la détection : { running, ids, model, startedAt, lastWindowAt, windowSec, error,
 * stats: { flows, alerts, missed, benign }, byAttack, events: [...] }
 */
export const fetchDetection = () => request('/lab/detection');

/** Démarre la détection : la Sonde IDS `ids` analyse le trafic avec le modèle `model`. */
export const startDetection = (ids, model) => request('/lab/detection', { method: 'POST', body: JSON.stringify({ ids, model }) });

/** Arrête la détection (le dernier bilan reste consultable). */
export const stopDetection = () => request('/lab/detection', { method: 'DELETE' });

/** Efface le bilan et les événements (la détection en cours continue, repartie de zéro). */
export const resetDetection = () => request('/lab/detection/reset', { method: 'POST' });

/**
 * Suit une tâche de fond du serveur (dataset, entraînement : voir
 * backend/app/jobs.py) : redemande son état toutes les secondes (polling).
 * `onUpdate` reçoit l'état : { status: 'running' | 'done' | 'failed', total, steps, warnings, error, result }.
 * Retourne une fonction qui interrompt le suivi.
 */
export function followJob(id, onUpdate) {
  const timer = setInterval(async () => {
    try {
      const job = await request(`/jobs/${encodeURIComponent(id)}`);
      onUpdate(job);
      if (job.status !== 'running') clearInterval(timer);
    } catch (err) {
      clearInterval(timer);
      onUpdate({ status: 'failed', error: err.message, steps: [], warnings: [] });
    }
  }, 1000);
  return () => clearInterval(timer);
}

/** Annule une tâche de fond (rien n'est sauvegardé). */
export const cancelJob = (id) => request(`/jobs/${encodeURIComponent(id)}/cancel`, { method: 'POST' });

// --- Datasets étiquetés (voir backend/app/datasets.py) ---------------------

/** Datasets sauvegardés : { datasets: [meta…], job: id de la génération en cours ou null } */
export const fetchDatasets = () => request('/datasets');

/** Lance la génération d'un dataset (programme : sonde, trafic bénin, attaques, durées) → { id } */
export const startDataset = (spec) => request('/datasets', { method: 'POST', body: JSON.stringify(spec) });

/** Supprime un dataset sauvegardé. */
export const deleteDataset = (id) => request(`/datasets/${encodeURIComponent(id)}`, { method: 'DELETE' });

/** URL de téléchargement d'un fichier d'un dataset (flows.csv, capture.pcap, meta.json). */
export const datasetFileUrl = (id, name) => `${API_BASE_URL}/datasets/${encodeURIComponent(id)}/files/${name}`;

// --- Modèles ML-IDS (voir backend/app/training.py) -------------------------

/** Modèles entraînés : { models: [meta…], job: id de l'entraînement en cours ou null } */
export const fetchModels = () => request('/models');

/** Lance l'entraînement d'un modèle (datasets d'entraînement et de test, hyperparamètres) → { id } */
export const startTraining = (spec) => request('/models', { method: 'POST', body: JSON.stringify(spec) });

/** Supprime un modèle entraîné. */
export const deleteModel = (id) => request(`/models/${encodeURIComponent(id)}`, { method: 'DELETE' });

/** URL de téléchargement d'un fichier d'un modèle (model.joblib, meta.json). */
export const modelFileUrl = (id, name) => `${API_BASE_URL}/models/${encodeURIComponent(id)}/files/${name}`;
