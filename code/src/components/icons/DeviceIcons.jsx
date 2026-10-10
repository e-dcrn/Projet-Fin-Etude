/**
 * Icônes SVG des équipements.
 * Elles utilisent `currentColor` : la couleur est donc pilotée par le CSS du parent.
 */

const svgProps = {
  viewBox: '0 0 48 48',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 2.5,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  'aria-hidden': true,
};

export function PcIcon() {
  return (
    <svg {...svgProps}>
      <rect x="6" y="8" width="36" height="24" rx="2" />
      <path d="M18 40h12M24 32v8" />
    </svg>
  );
}

export function ServerIcon() {
  return (
    <svg {...svgProps}>
      <rect x="10" y="5" width="28" height="11" rx="2" />
      <rect x="10" y="18.5" width="28" height="11" rx="2" />
      <rect x="10" y="32" width="28" height="11" rx="2" />
      <path d="M15 10.5h2M15 24h2M15 37.5h2" />
    </svg>
  );
}

export function RouterIcon() {
  return (
    <svg {...svgProps}>
      <ellipse cx="24" cy="18" rx="18" ry="7" />
      <path d="M6 18v12c0 3.9 8 7 18 7s18-3.1 18-7V18" />
      {/* Flèches caractéristiques du pictogramme « routeur » */}
      <path d="M17 15l-4 3 4 3M31 15l4 3-4 3" />
    </svg>
  );
}

export function SwitchIcon() {
  return (
    <svg {...svgProps}>
      <rect x="4" y="14" width="40" height="20" rx="2" />
      <path d="M12 20h18l-3-3M36 28H18l3 3" />
    </svg>
  );
}

export function IdsIcon() {
  return (
    <svg {...svgProps}>
      {/* Bouclier + œil : sonde de détection */}
      <path d="M24 4l16 6v12c0 10-7 18-16 22C15 40 8 32 8 22V10z" />
      <path d="M15 23s3.5-6 9-6 9 6 9 6-3.5 6-9 6-9-6-9-6z" />
      <circle cx="24" cy="23" r="2" />
    </svg>
  );
}
