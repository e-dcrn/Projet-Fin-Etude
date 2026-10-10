import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { captureUrl, websocketFailure } from '../services/topologyApi.js';
import { colorRule, createDissector } from '../utils/packetDissector.js';
import { compileFilter } from '../utils/displayFilter.js';
import { buildPcap, splitPackets } from '../utils/pcap.js';

const ROW_HEIGHT = 20;
const MAX_PACKETS = 50000; // au-delà la capture s'arrête (mémoire du navigateur)
const FLUSH_DELAY = 100; // ms : regroupe l'affichage des paquets reçus en rafale
const FILTER_EXAMPLES = 'icmp · tcp.port == 80 · ip.addr == 10.0.1.10 · arp || dns · !(tcp.flags.ack == 1)';

/**
 * Capture du trafic d'un lien, à la manière de Wireshark : liste des paquets,
 * détail par couche, dump hexadécimal, filtres d'affichage et export .pcap.
 *
 * Les paquets arrivent bruts par WebSocket (voir backend/app/capture.py) et sont
 * décodés dans le navigateur (utils/packetDissector.js). Seul un résumé est
 * conservé par paquet ; le détail est recalculé quand on sélectionne un paquet.
 */
export default function CaptureView({ nodeId, interfaceName, title, active, openRequest }) {
  const [status, setStatus] = useState('connecting'); // 'connecting' | 'running' | 'stopped'
  const [notice, setNotice] = useState(null); // { text, error }
  const [attempt, setAttempt] = useState(0);
  const [, setTick] = useState(0); // nouveau rendu quand des paquets arrivent
  const [filterInput, setFilterInput] = useState('');
  const [selected, setSelected] = useState(null); // index dans packets
  const [highlight, setHighlight] = useState(null); // { start, end } dans le paquet sélectionné
  const [expanded, setExpanded] = useState(() => new Set()); // couches dépliées (gardées d'un paquet à l'autre)

  const packets = useRef([]); // [{ no, time, sec, usec, origLen, bytes, summary }]
  const visible = useRef([]); // indices des paquets qui passent le filtre
  const predicate = useRef(() => true);
  const dissector = useRef(createDissector());
  const stopRef = useRef(() => {}); // arrêt demandé par l'utilisateur (bouton Arrêter)
  const flushTimer = useRef(null);

  const refresh = useCallback(() => {
    if (flushTimer.current) return;
    flushTimer.current = setTimeout(() => {
      flushTimer.current = null;
      setTick((n) => n + 1);
    }, FLUSH_DELAY);
  }, []);

  const clear = useCallback(() => {
    packets.current = [];
    visible.current = [];
    dissector.current = createDissector();
    setSelected(null);
    setHighlight(null);
    setTick((n) => n + 1);
  }, []);

  // ------------------------------------------------------------ session de capture
  useEffect(() => {
    clear();
    setStatus('connecting');
    setNotice(null);
    const socket = new WebSocket(captureUrl(nodeId, interfaceName));
    socket.binaryType = 'arraybuffer';
    let ended = false; // la fin de capture a déjà été expliquée

    const stop = (text, error = false) => {
      ended = true;
      setNotice({ text, error });
      setStatus('stopped');
    };
    stopRef.current = () => {
      stop('Capture arrêtée.');
      socket.close(); // le serveur arrête tcpdump et supprime l'outil de capture
    };

    socket.onmessage = ({ data }) => {
      if (typeof data === 'string') {
        const message = JSON.parse(data);
        if (message.type === 'ready') setStatus('running');
        else if (message.type === 'stopped') stop(message.message);
        else if (message.type === 'error') stop(message.message, true);
        return;
      }
      for (const raw of splitPackets(data)) {
        const list = packets.current;
        if (list.length >= MAX_PACKETS) {
          stop(`Limite de ${MAX_PACKETS.toLocaleString('fr-FR')} paquets atteinte : capture arrêtée (exportez-la en .pcap).`);
          socket.close();
          break;
        }
        const timestamp = raw.sec + raw.usec / 1e6;
        const t0 = list.length ? list[0].timestamp : timestamp;
        const summary = dissector.current(raw.bytes);
        const packet = { ...raw, no: list.length + 1, timestamp, time: timestamp - t0, summary, color: colorRule(summary) };
        list.push(packet);
        if (predicate.current(summary)) visible.current.push(list.length - 1);
      }
      refresh();
    };
    let opened = false;
    socket.onopen = () => {
      opened = true;
    };
    socket.onclose = () => {
      if (!ended) stop(websocketFailure(opened), true);
    };

    return () => {
      socket.onclose = null;
      socket.close();
      clearTimeout(flushTimer.current);
      flushTimer.current = null;
    };
  }, [nodeId, interfaceName, attempt, clear, refresh]);

  // Redemander la capture d'un lien dont la capture est arrêtée : nouvelle capture
  const statusRef = useRef(status);
  statusRef.current = status;
  useEffect(() => {
    if (statusRef.current === 'stopped') setAttempt((n) => n + 1);
  }, [openRequest]);

  // ------------------------------------------------------------ filtre d'affichage
  const filterState = useMemo(() => {
    try {
      compileFilter(filterInput);
      return filterInput.trim() ? 'valid' : 'empty';
    } catch (err) {
      return err.message;
    }
  }, [filterInput]);

  const applyFilter = () => {
    if (filterState !== 'valid' && filterState !== 'empty') return;
    predicate.current = compileFilter(filterInput);
    visible.current = packets.current.reduce((acc, p, i) => (predicate.current(p.summary) ? (acc.push(i), acc) : acc), []);
    setTick((n) => n + 1);
  };

  const download = () => {
    const url = URL.createObjectURL(buildPcap(packets.current));
    const link = document.createElement('a');
    link.href = url;
    link.download = `capture-${title.replace(/[^\w.-]+/g, '_')}.pcap`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  // ------------------------------------------------------------ liste virtualisée
  const listRef = useRef(null);
  const [viewport, setViewport] = useState({ top: 0, height: 200 });
  const stickToBottom = useRef(true);

  useEffect(() => {
    const element = listRef.current;
    const observer = new ResizeObserver(() => setViewport((v) => ({ ...v, height: element.clientHeight })));
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const onScroll = (event) => {
    const el = event.currentTarget;
    stickToBottom.current = el.scrollTop + el.clientHeight >= el.scrollHeight - ROW_HEIGHT;
    setViewport({ top: el.scrollTop, height: el.clientHeight });
  };

  // Défilement automatique pendant la capture, tant qu'on est en bas de la liste
  const visibleCount = visible.current.length;
  useLayoutEffect(() => {
    const el = listRef.current;
    if (el && stickToBottom.current && active) el.scrollTop = el.scrollHeight;
  }, [visibleCount, active]);

  const first = Math.max(0, Math.floor(viewport.top / ROW_HEIGHT) - 5);
  const last = Math.min(visibleCount, Math.ceil((viewport.top + viewport.height) / ROW_HEIGHT) + 5);
  const rows = visible.current.slice(first, last);

  const select = (index) => {
    setSelected(index);
    setHighlight(null);
  };

  const onListKeyDown = (event) => {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
    event.preventDefault();
    const list = visible.current;
    if (!list.length) return;
    const position = list.indexOf(selected);
    const next = event.key === 'ArrowDown' ? Math.min(list.length - 1, position + 1) : Math.max(0, position - 1);
    select(list[next < 0 ? 0 : next]);
    const el = listRef.current;
    const y = (next + 1) * ROW_HEIGHT; // +1 : ligne d'en-tête
    if (y < el.scrollTop + ROW_HEIGHT) el.scrollTop = y - ROW_HEIGHT;
    else if (y + ROW_HEIGHT > el.scrollTop + el.clientHeight) el.scrollTop = y + ROW_HEIGHT - el.clientHeight;
    stickToBottom.current = false;
  };

  // ------------------------------------------------------------ détail du paquet sélectionné
  const packet = selected !== null ? packets.current[selected] : null;
  const detail = useMemo(() => {
    if (!packet) return null;
    const { tree } = dissector.current(packet.bytes);
    const length = packet.bytes.length;
    const date = new Date(packet.timestamp * 1000);
    const frame = {
      key: 'frame',
      label: `Frame ${packet.no}: ${packet.origLen} bytes on wire (${packet.origLen * 8} bits), ${length} bytes captured (${length * 8} bits)`,
      start: 0,
      end: length,
      children: [
        { label: `Arrival Time: ${date.toLocaleString('fr-FR')}.${String(packet.usec).padStart(6, '0')}`, start: 0, end: 0, children: [] },
        { label: `Time since first frame: ${packet.time.toFixed(6)} seconds`, start: 0, end: 0, children: [] },
        { label: `Frame Number: ${packet.no}`, start: 0, end: 0, children: [] },
        { label: `Frame Length: ${packet.origLen} bytes`, start: 0, end: 0, children: [] },
        { label: `Protocols in frame: ${['frame', ...tree.map((n) => n.key)].join(':')}`, start: 0, end: 0, children: [] },
      ],
    };
    return [frame, ...tree];
  }, [packet]);

  const toggleLayer = (key) =>
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const running = status === 'running';
  const filterClass = filterState === 'empty' ? '' : filterState === 'valid' ? ' capture__filter--valid' : ' capture__filter--invalid';

  return (
    <div className={`capture${active ? '' : ' capture--hidden'}`}>
      <div className="capture__toolbar">
        <span className={`capture__status capture__status--${status}`}>
          {status === 'connecting' ? 'Démarrage…' : running ? 'Capture en cours' : 'Capture arrêtée'}
        </span>
        <span className="capture__title">{title}</span>
        <span className="capture__spacer" />
        {running ? (
          <button type="button" className="btn btn--light btn--small" onClick={() => stopRef.current()}>
            ■ Arrêter
          </button>
        ) : (
          <button type="button" className="btn btn--primary btn--small" onClick={() => setAttempt((n) => n + 1)} disabled={status === 'connecting'}>
            ▶ Nouvelle capture
          </button>
        )}
        <button type="button" className="btn btn--light btn--small" onClick={clear} disabled={!packets.current.length}>
          Effacer
        </button>
        <button type="button" className="btn btn--light btn--small" onClick={download} disabled={!packets.current.length} title="Ouvrir ensuite le fichier dans Wireshark">
          ⬇ Exporter .pcap
        </button>
      </div>

      <form
        className="capture__filterbar"
        onSubmit={(event) => {
          event.preventDefault();
          applyFilter();
        }}
      >
        <input
          className={`capture__filter${filterClass}`}
          value={filterInput}
          spellCheck={false}
          placeholder={`Filtre d'affichage (Entrée pour appliquer) — ex. ${FILTER_EXAMPLES}`}
          title={filterState !== 'valid' && filterState !== 'empty' ? filterState : undefined}
          onChange={(event) => setFilterInput(event.target.value)}
        />
        <button type="submit" className="btn btn--light btn--small" disabled={filterState !== 'valid' && filterState !== 'empty'}>
          Appliquer
        </button>
        <span className="capture__count">
          Paquets : {packets.current.length.toLocaleString('fr-FR')}
          {visibleCount !== packets.current.length && ` · Affichés : ${visibleCount.toLocaleString('fr-FR')}`}
        </span>
      </form>
      {filterState !== 'valid' && filterState !== 'empty' && <div className="capture__filter-error">{filterState}</div>}
      {notice && <div className={`capture__notice${notice.error ? ' capture__notice--error' : ''}`}>{notice.text}</div>}

      <div className="capture__list" ref={listRef} onScroll={onScroll} onKeyDown={onListKeyDown} tabIndex={0}>
        <div className="capture__row capture__row--head">
          <span>No.</span>
          <span>Time</span>
          <span>Source</span>
          <span>Destination</span>
          <span>Protocol</span>
          <span>Length</span>
          <span>Info</span>
        </div>
        <div style={{ height: visibleCount * ROW_HEIGHT, position: 'relative' }}>
          {rows.map((index, i) => {
            const p = packets.current[index];
            return (
              <div
                key={p.no}
                className={`capture__row capture-row--${p.color}${index === selected ? ' capture__row--selected' : ''}`}
                style={{ top: (first + i) * ROW_HEIGHT }}
                onClick={() => select(index)}
              >
                <span>{p.no}</span>
                <span>{p.time.toFixed(6)}</span>
                <span>{p.summary.src}</span>
                <span>{p.summary.dst}</span>
                <span>{p.summary.protocol}</span>
                <span>{p.bytes.length}</span>
                <span>{p.summary.info}</span>
              </div>
            );
          })}
        </div>
        {visibleCount === 0 && (
          <p className="capture__empty">
            {packets.current.length
              ? 'Aucun paquet ne correspond au filtre.'
              : running
                ? 'En attente de trafic sur ce lien… (essayez un ping depuis le terminal d\'un équipement)'
                : ''}
          </p>
        )}
      </div>

      <div className="capture__bottom">
        <div className="capture__tree">
          {detail ? (
            detail.map((layer) => (
              <div key={layer.key} className="capture__layer">
                <button
                  type="button"
                  className={`capture__layer-title${highlight?.layer === layer.key && highlight.whole ? ' capture__line--active' : ''}`}
                  onClick={() => {
                    toggleLayer(layer.key);
                    setHighlight({ start: layer.start, end: layer.end, layer: layer.key, whole: true });
                  }}
                >
                  <span className="capture__caret">{expanded.has(layer.key) ? '▾' : '▸'}</span>
                  {layer.label}
                </button>
                {expanded.has(layer.key) &&
                  layer.children.map((field, i) => (
                    <button
                      key={i}
                      type="button"
                      className={`capture__field${highlight?.layer === layer.key && highlight.index === i ? ' capture__line--active' : ''}`}
                      onClick={() => setHighlight({ start: field.start, end: field.end, layer: layer.key, index: i })}
                    >
                      {field.label}
                    </button>
                  ))}
              </div>
            ))
          ) : (
            <p className="capture__empty">Sélectionnez un paquet pour voir son contenu, couche par couche.</p>
          )}
        </div>
        <HexDump bytes={packet?.bytes} highlight={highlight} />
      </div>
    </div>
  );
}

/** Octets du paquet : position, hexadécimal (16 par ligne), texte ASCII ; surligne la plage sélectionnée. */
function HexDump({ bytes, highlight }) {
  if (!bytes) return <div className="capture__hex" />;
  const lines = [];
  const marked = (i) => highlight && i >= highlight.start && i < highlight.end;
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const slice = Array.from(bytes.subarray(offset, offset + 16));
    lines.push(
      <div key={offset} className="capture__hex-line">
        <span className="capture__hex-offset">{offset.toString(16).padStart(4, '0')}</span>
        <span className="capture__hex-bytes">
          {slice.map((b, i) => (
            <span key={i} className={marked(offset + i) ? 'capture__byte--marked' : undefined}>
              {b.toString(16).padStart(2, '0')}
              {i === 7 ? '  ' : ' '}
            </span>
          ))}
        </span>
        <span className="capture__hex-ascii">
          {slice.map((b, i) => (
            <span key={i} className={marked(offset + i) ? 'capture__byte--marked' : undefined}>
              {b >= 32 && b < 127 ? String.fromCharCode(b) : '.'}
            </span>
          ))}
        </span>
      </div>,
    );
  }
  return <div className="capture__hex">{lines}</div>;
}
