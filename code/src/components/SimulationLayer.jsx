import { useEffect, useRef } from 'react';
import { ViewportPortal } from '@xyflow/react';

/**
 * Affiche les paquets en vol : une boule par paquet réel (voir useSimulation),
 * qui parcourt une seule fois son chemin source → destination. La couleur
 * indique le protocole (TCP, ICMP, UDP, ARP).
 *
 * Le déplacement est piloté en JavaScript (requestAnimationFrame) : à chaque
 * image, on place la boule au point correspondant à sa progression le long du
 * tracé. On n'utilise pas l'animation SMIL <animateMotion> car, sur un <svg>
 * déjà monté, une animation ajoutée avec begin="0s" démarre dans le passé et
 * s'affiche figée à l'arrivée — la boule ne se déplaçait pas.
 */

/** Point à la fraction t ∈ [0,1] de la polyligne, mesurée en longueur d'arc. */
function pointAt(points, t) {
  if (points.length <= 1) return points[0] ?? { x: 0, y: 0 };
  const seg = [];
  let total = 0;
  for (let i = 1; i < points.length; i += 1) {
    const len = Math.hypot(points[i].x - points[i - 1].x, points[i].y - points[i - 1].y);
    seg.push(len);
    total += len;
  }
  if (total === 0) return points[0];
  let dist = t * total;
  for (let i = 0; i < seg.length; i += 1) {
    if (dist <= seg[i]) {
      const r = seg[i] ? dist / seg[i] : 0;
      return {
        x: points[i].x + (points[i + 1].x - points[i].x) * r,
        y: points[i].y + (points[i + 1].y - points[i].y) * r,
      };
    }
    dist -= seg[i];
  }
  return points[points.length - 1];
}

export default function SimulationLayer({ balls }) {
  const els = useRef(new Map());     // id de boule → élément <circle>
  const starts = useRef(new Map());  // id de boule → instant de départ (ms)
  const ballsRef = useRef(balls);
  ballsRef.current = balls;

  // Boucle d'animation unique : positionne chaque boule selon sa progression.
  useEffect(() => {
    let raf = 0;
    const tick = (now) => {
      const live = ballsRef.current;
      for (const ball of live) {
        let start = starts.current.get(ball.id);
        if (start === undefined) {
          start = now;
          starts.current.set(ball.id, now);
        }
        const el = els.current.get(ball.id);
        if (!el) continue;
        const t = Math.min(1, (now - start) / ball.durMs);
        const p = pointAt(ball.points, t);
        el.setAttribute('cx', p.x);
        el.setAttribute('cy', p.y);
      }
      // Oublie les instants de départ des boules disparues.
      if (starts.current.size > live.length) {
        const ids = new Set(live.map((b) => b.id));
        for (const id of starts.current.keys()) {
          if (!ids.has(id)) starts.current.delete(id);
        }
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);

  if (!balls || balls.length === 0) return null;
  return (
    <ViewportPortal>
      <svg
        className="sim-layer"
        width="1"
        height="1"
        style={{ position: 'absolute', left: 0, top: 0, overflow: 'visible', pointerEvents: 'none' }}
      >
        {balls.map((ball) => (
          <circle
            key={ball.id}
            r={6}
            cx={ball.points[0].x}
            cy={ball.points[0].y}
            className={`sim-packet sim-packet--${ball.proto}`}
            ref={(el) => {
              if (el) els.current.set(ball.id, el);
              else els.current.delete(ball.id);
            }}
          />
        ))}
      </svg>
    </ViewportPortal>
  );
}
