import { useCallback, useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { terminalUrl, websocketFailure } from '../services/topologyApi.js';

const OPTIONS = {
  cursorBlink: true,
  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
  fontSize: 13,
  scrollback: 5000,
  theme: { background: '#0f172a', foreground: '#e2e8f0', cursor: '#e2e8f0', selectionBackground: '#334155' },
};

/** Message de l'interface, affiché dans le terminal (distinct de la sortie de la machine). */
function notice(term, message, isError) {
  term.write(`\r\n\x1b[${isError ? '31' : '2'}m[${message}]\x1b[0m\r\n`);
}

/**
 * Terminal d'un équipement : émulateur xterm.js relié au shell de la machine
 * par une WebSocket (protocole : voir backend/app/terminal.py).
 *
 * Le composant reste monté quand son onglet est masqué : la session continue
 * en arrière-plan (un ping lancé dans un onglet tourne pendant qu'on en consulte un autre).
 *
 * @param openRequest compteur de demandes d'ouverture (voir useTerminals) :
 *                    s'il change alors que la session est terminée, on se reconnecte
 */
export default function TerminalView({ nodeId, active, openRequest }) {
  const screenRef = useRef(null);
  const termRef = useRef(null);
  const fitRef = useRef(null);
  const [status, setStatus] = useState('connecting'); // 'connecting' | 'open' | 'closed'
  const [attempt, setAttempt] = useState(0);

  const fit = useCallback(() => {
    if (screenRef.current?.clientWidth) fitRef.current?.fit();
  }, []);

  // Émulateur : un seul pour toute la vie de l'onglet (l'historique survit aux reconnexions)
  useEffect(() => {
    const term = new Terminal(OPTIONS);
    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(screenRef.current);
    termRef.current = term;
    fitRef.current = fitAddon;
    fit();
    const observer = new ResizeObserver(fit);
    observer.observe(screenRef.current);
    return () => {
      observer.disconnect();
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, [fit]);

  // Session : une WebSocket = un shell sur la machine ; la fermer arrête le shell
  useEffect(() => {
    const term = termRef.current;
    const socket = new WebSocket(terminalUrl(nodeId, { cols: term.cols, rows: term.rows }));
    socket.binaryType = 'arraybuffer';
    setStatus('connecting');
    let ended = false; // le serveur a déjà expliqué la fin de session

    const send = (message) => {
      if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(message));
    };

    socket.onmessage = ({ data }) => {
      if (data instanceof ArrayBuffer) {
        term.write(new Uint8Array(data)); // xterm.js décode l'UTF-8 même coupé entre deux paquets
        return;
      }
      const message = JSON.parse(data);
      if (message.type === 'ready') {
        setStatus('open');
        send({ type: 'resize', cols: term.cols, rows: term.rows }); // taille changée pendant la connexion
      } else if (message.type === 'exit' || message.type === 'error') {
        ended = true;
        notice(term, message.message, message.type === 'error');
      }
    };
    let opened = false;
    socket.onopen = () => {
      opened = true;
    };
    socket.onclose = () => {
      if (!ended) notice(term, websocketFailure(opened), true);
      setStatus('closed');
    };

    // Frappes clavier (et réponses automatiques du terminal) → shell
    const input = term.onData((data) => send({ type: 'input', data }));
    const resize = term.onResize(({ cols, rows }) => send({ type: 'resize', cols, rows }));

    return () => {
      input.dispose();
      resize.dispose();
      socket.onclose = null;
      socket.close();
    };
  }, [nodeId, attempt]);

  // Reclic sur l'équipement alors que la session est terminée : reconnexion
  const statusRef = useRef(status);
  statusRef.current = status;
  useEffect(() => {
    if (statusRef.current === 'closed') setAttempt((n) => n + 1);
  }, [openRequest]);

  // Onglet affiché : ajuste la taille et donne le focus au clavier
  useEffect(() => {
    if (!active) return undefined;
    const frame = requestAnimationFrame(() => {
      fit();
      termRef.current?.focus();
    });
    return () => cancelAnimationFrame(frame);
  }, [active, fit]);

  return (
    <div className={`terminal-view${active ? '' : ' terminal-view--hidden'}`}>
      <div ref={screenRef} className="terminal-view__screen" />
      {status === 'closed' && (
        <div className="terminal-view__ended">
          Session fermée
          <button type="button" className="btn btn--primary" onClick={() => setAttempt((n) => n + 1)}>
            Rouvrir
          </button>
        </div>
      )}
    </div>
  );
}
