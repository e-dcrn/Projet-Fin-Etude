/**
 * Couche d'accès au moteur de simulation (backend/, voir README).
 *
 * L'instanciation d'une topologie est longue : POST /deployments démarre une
 * tâche et renvoie son identifiant, puis la progression est suivie en temps
 * réel via Server-Sent Events (GET /deployments/{id}/events, EventSource).
 *
 * Le terminal d'un équipement et la capture du trafic d'un lien passent par
 * des WebSockets (terminalUrl / captureUrl, voir TerminalView et CaptureView).
 */

// URL du backend, configurable via un fichier .env (VITE_API_BASE_URL=...)
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000/api';

/** Erreur renvoyée par le serveur : `messages` est une liste de textes affichables. */
export class ApiError extends Error {
  constructor(messages, status = 0) {
    super(messages.join('\n'));
    this.messages = messages;
    this.status = status;
  }
}

const UNREACHABLE = 'Le moteur de simulation est injoignable : vérifiez qu\'il est lancé (voir README).';

/**
 * Fermeture d'une WebSocket (terminal, capture) sans explication du serveur.
 * Refusée avant même d'être établie : moteur arrêté, ou version qui ne connaît
 * pas encore cette fonction (lancé avant une mise à jour du code, sans --reload).
 */
export function websocketFailure(opened) {
  return opened
    ? 'Connexion avec le moteur de simulation perdue.'
    : 'Le moteur de simulation a refusé la connexion : s\'il est lancé, redémarrez-le pour qu\'il prenne en compte la dernière version du code (voir README).';
}

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers: { 'Content-Type': 'application/json', ...options.headers },
    });
  } catch {
    throw new ApiError([UNREACHABLE]);
  }
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    // 400 / 409 / 503 : { errors: [...] } ; 422 (format invalide) : { detail: [...] }
    const messages = body.errors ?? [`Le serveur a refusé la requête (code ${response.status}).`];
    throw new ApiError(messages, response.status);
  }
  return body;
}

/** État du réseau instancié : { running, deploying, devices: [{ id, name, running }], networks: [id] } */
export const fetchLabStatus = () => request('/lab');

/** Arrête et supprime le réseau instancié. */
export const stopLab = () => request('/lab', { method: 'DELETE' });

// --- Génération de trafic (voir backend/app/traffic.py) --------------------

/**
 * Activité de trafic et catalogues :
 * { benign: [{ node, profile }], scenarios: [...], profiles: [...], attacks: [...] }
 */
export const fetchTraffic = () => request('/lab/traffic');

/** Démarre le trafic de fond (bénin) sur un équipement. `kinds` : types de trafic
 *  à générer (« icmp », « http », « service ») ; `dest` : libellé d'affichage. */
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

/** URL de téléchargement du CSV des flux étiquetés d'un scénario (voir backend/app/traffic.py). */
export const scenarioFlowsUrl = (id) => `${API_BASE_URL}/lab/scenarios/${encodeURIComponent(id)}/flows`;

/** Supprime les scénarios terminés. */
/** Interrompt un scénario en cours (id), ou tous les scénarios en cours (sans id). */
export const stopScenarios = (id) =>
  request(`/lab/scenarios/stop${id ? `?id=${encodeURIComponent(id)}` : ''}`, { method: 'POST' });

export const clearScenarios = () => request('/lab/scenarios', { method: 'DELETE' });

// --- Détection en direct (voir backend/app/detection.py) -------------------

/**
 * État de la détection : { running, ids, model, startedAt, lastWindowAt, windowSec, error,
 * stats: { flows, alerts, detected, missed, falseAlarms, benign }, events: [...] }
 */
export const fetchDetection = () => request('/lab/detection');

/** Démarre la détection : la Sonde IDS `ids` analyse le trafic avec le modèle `model`. */
export const startDetection = (ids, model) => request('/lab/detection', { method: 'POST', body: JSON.stringify({ ids, model }) });

/** Arrête la détection (le dernier bilan reste consultable). */
export const stopDetection = () => request('/lab/detection', { method: 'DELETE' });

/** Efface le bilan et les événements (la détection en cours continue, repartie de zéro). */
export const resetDetection = () => request('/lab/detection/reset', { method: 'POST' });


/**
 * Lance l'instanciation d'une topologie sérialisée (serializeTopology()).
 * @returns {Promise<{ id: string }>}
 */
export const startDeployment = (topology) =>
  request('/deployments', { method: 'POST', body: JSON.stringify(topology) });

/**
 * Suit la progression d'un déploiement. `onEvent` reçoit chaque événement :
 *   { type: 'progress', step, total, label } | { type: 'warning', message }
 *   { type: 'done', total } | { type: 'error', message }
 * Retourne une fonction qui interrompt le suivi.
 */
export const followDeployment = (id, onEvent) => followJob(`/deployments/${id}/events`, onEvent);

/** Suit les événements d'une tâche de fond du serveur (Server-Sent Events, voir backend/app/jobs.py). */
function followJob(path, onEvent) {
  const source = new EventSource(`${API_BASE_URL}${path}`);
  source.onmessage = (message) => {
    const event = JSON.parse(message.data);
    onEvent(event);
    if (event.type === 'done' || event.type === 'error') source.close();
  };
  // En cas de coupure, EventSource se reconnecte seul et reprend au dernier événement
  // reçu (Last-Event-ID) ; on n'abandonne que si la connexion est définitivement fermée.
  source.onerror = () => {
    if (source.readyState === EventSource.CLOSED) onEvent({ type: 'error', message: UNREACHABLE });
  };
  return () => source.close();
}

// --- Datasets étiquetés (voir backend/app/datasets.py) ---------------------

/** Datasets sauvegardés : { datasets: [meta…], job: id de la génération en cours ou null } */
export const fetchDatasets = () => request('/datasets');

/** Lance la génération d'un dataset (programme : sonde, trafic bénin, attaques, durées) → { id } */
export const startDataset = (spec) => request('/datasets', { method: 'POST', body: JSON.stringify(spec) });

/** Suit la génération d'un dataset : mêmes événements qu'un déploiement ; `done` porte { dataset }. */
export const followDatasetJob = (id, onEvent) => followJob(`/datasets/jobs/${id}/events`, onEvent);

/** Annule la génération en cours (rien n'est sauvegardé). */
export const cancelDatasetJob = (id) => request(`/datasets/jobs/${encodeURIComponent(id)}/cancel`, { method: 'POST' });

/** Supprime un dataset sauvegardé. */
export const deleteDataset = (id) => request(`/datasets/${encodeURIComponent(id)}`, { method: 'DELETE' });

/** URL de téléchargement d'un fichier d'un dataset (flows.csv, capture.pcap, meta.json). */
export const datasetFileUrl = (id, name) => `${API_BASE_URL}/datasets/${encodeURIComponent(id)}/files/${name}`;

// --- Modèles ML-IDS (voir backend/app/training.py) -------------------------

/** Modèles entraînés : { models: [meta…], job, options: { models, splits } } */
export const fetchModels = () => request('/models');

/** Lance l'entraînement d'un modèle (datasets, découpage, hyperparamètres) → { id } */
export const startTraining = (spec) => request('/models', { method: 'POST', body: JSON.stringify(spec) });

/** Suit un entraînement : mêmes événements qu'un déploiement ; `done` porte { model }. */
export const followTrainingJob = (id, onEvent) => followJob(`/models/jobs/${id}/events`, onEvent);

/** Annule l'entraînement en cours (rien n'est sauvegardé). */
export const cancelTrainingJob = (id) => request(`/models/jobs/${encodeURIComponent(id)}/cancel`, { method: 'POST' });

/** Supprime un modèle entraîné. */
export const deleteModel = (id) => request(`/models/${encodeURIComponent(id)}`, { method: 'DELETE' });

/** URL de téléchargement d'un fichier d'un modèle (model.joblib, meta.json). */
export const modelFileUrl = (id, name) => `${API_BASE_URL}/models/${encodeURIComponent(id)}/files/${name}`;

/**
 * URL WebSocket du terminal d'un équipement (PC ou serveur allumé).
 * Protocole : voir backend/app/terminal.py.
 */
export function terminalUrl(nodeId, { cols, rows }) {
  return websocketUrl(`/devices/${encodeURIComponent(nodeId)}/terminal`, { cols, rows });
}

/**
 * URL WebSocket de la capture du trafic d'un lien (interface d'un équipement allumé).
 * Protocole : voir backend/app/capture.py.
 */
export function captureUrl(nodeId, interfaceName) {
  return websocketUrl(`/devices/${encodeURIComponent(nodeId)}/interfaces/${encodeURIComponent(interfaceName)}/capture`);
}

function websocketUrl(path, params = {}) {
  const url = new URL(`${API_BASE_URL}${path}`, window.location.href);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.search = new URLSearchParams(params).toString();
  return url.toString();
}
