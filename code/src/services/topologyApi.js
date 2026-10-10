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
export function followDeployment(id, onEvent) {
  const source = new EventSource(`${API_BASE_URL}/deployments/${id}/events`);
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
