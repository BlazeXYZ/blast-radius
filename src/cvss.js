// CVSS v3.x base score calculator (spec section 7.1), used when an advisory
// carries a vector string but no severity label.

const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 },
};
const PR = { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } };

// "Round up" to one decimal exactly as the spec defines it, avoiding float drift.
function roundUp(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

export function cvss3Score(vector) {
  if (!/^CVSS:3\.[01]\//.test(vector || '')) return null;
  const m = Object.fromEntries(vector.split('/').slice(1).map(p => p.split(':')));
  const scope = m.S;
  const av = WEIGHTS.AV[m.AV], ac = WEIGHTS.AC[m.AC], ui = WEIGHTS.UI[m.UI];
  const pr = PR[scope]?.[m.PR];
  const c = WEIGHTS.C[m.C], i = WEIGHTS.I[m.I], a = WEIGHTS.A[m.A];
  if ([av, ac, ui, pr, c, i, a].some(w => w === undefined)) return null;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scope === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  return scope === 'U'
    ? roundUp(Math.min(impact + exploitability, 10))
    : roundUp(Math.min(1.08 * (impact + exploitability), 10));
}

export function severityFromScore(score) {
  if (score == null) return null;
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return null;
}
