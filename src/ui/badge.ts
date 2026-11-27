/**
 * Score badge generation. Pure functions, no network: the markdown points at
 * shields.io's static-badge URL scheme, and the SVG is rendered locally.
 */

export type BadgeColor = 'brightgreen' | 'green' | 'yellow' | 'orange' | 'red';

const HEX: Record<BadgeColor, string> = {
  brightgreen: '#4c1',
  green: '#97ca00',
  yellow: '#dfb317',
  orange: '#fe7d37',
  red: '#e05d44',
};

/** Clamp to an integer 0..100; non-finite values count as 0. */
export function normalizeScore(score: number): number {
  if (!Number.isFinite(score)) return 0;
  return Math.max(0, Math.min(100, Math.round(score)));
}

export function badgeColor(score: number): BadgeColor {
  const s = normalizeScore(score);
  if (s >= 90) return 'brightgreen';
  if (s >= 75) return 'green';
  if (s >= 60) return 'yellow';
  if (s >= 40) return 'orange';
  return 'red';
}

export function badgeUrl(score: number): string {
  const s = normalizeScore(score);
  return `https://img.shields.io/badge/DeployReady-${s}%2F100-${badgeColor(s)}`;
}

export function badgeMarkdown(score: number): string {
  return `![DeployReady score](${badgeUrl(score)})`;
}

/** Self-contained flat SVG badge ("DeployReady | 87/100"). */
export function badgeSvg(score: number): string {
  const s = normalizeScore(score);
  const label = 'DeployReady';
  const value = `${s}/100`;
  const lw = 86;
  const vw = 54;
  const w = lw + vw;
  const fill = HEX[badgeColor(s)];
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${label}: ${value}">` +
    `<title>${label}: ${value}</title>` +
    `<clipPath id="r"><rect width="${w}" height="20" rx="3"/></clipPath>` +
    `<g clip-path="url(#r)"><rect width="${lw}" height="20" fill="#555"/><rect x="${lw}" width="${vw}" height="20" fill="${fill}"/></g>` +
    `<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">` +
    `<text x="${lw / 2}" y="14">${label}</text><text x="${lw + vw / 2}" y="14">${value}</text></g></svg>\n`
  );
}
