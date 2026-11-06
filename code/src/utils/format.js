/** Mise en forme des dates, durées et taux affichés dans l'interface. */

/** Date ISO → « 30/10/2026 10:49 ». */
export const formatDate = (iso) => (iso ? new Date(iso).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' }) : '');

/** Secondes → « 50 s » ou « 3 min 05 s ». */
export function formatDuration(secs) {
  const s = Math.round(secs);
  return s >= 60 ? `${Math.floor(s / 60)} min ${String(s % 60).padStart(2, '0')} s` : `${s} s`;
}

/**
 * Proportion (0–1) → « 97,5 % » ; « — » si absente. Un taux presque parfait n'est
 * jamais arrondi à 100 % (ni un taux minime à 0 %) : 9 attaques manquées sur
 * 66 854 s'affichent « > 99,9 % », pas « 100 % ».
 */
export function formatPercent(value) {
  if (value === null || value === undefined) return '—';
  if (value > 0.999 && value < 1) return '> 99,9 %';
  if (value > 0 && value < 0.001) return '< 0,1 %';
  return `${(value * 100).toLocaleString('fr-FR', { maximumFractionDigits: 1 })} %`;
}
