// A compact PEP 440 implementation: version parsing, ordering, and specifier matching.
// https://peps.python.org/pep-0440/

const VERSION_RE =
  /^\s*v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(alpha|beta|preview|pre|a|b|c|rc)[-_.]?(\d*))?(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d*))?(?:[-_.]?(dev)[-_.]?(\d*))?(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?\s*$/i;

const PRE_NORMAL = { a: 'a', alpha: 'a', b: 'b', beta: 'b', c: 'rc', rc: 'rc', pre: 'rc', preview: 'rc' };
const PRE_RANK = { a: 0, b: 1, rc: 2 };

export function parseVersion(input) {
  const m = VERSION_RE.exec(String(input));
  if (!m) return null;
  return {
    epoch: Number(m[1] || 0),
    release: m[2].split('.').map(Number),
    pre: m[3] ? [PRE_NORMAL[m[3].toLowerCase()], Number(m[4] || 0)] : null,
    post: m[5] != null ? Number(m[5]) : m[6] ? Number(m[7] || 0) : null,
    dev: m[8] ? Number(m[9] || 0) : null,
    local: m[10] ? m[10].toLowerCase() : null,
  };
}

export const isPrerelease = v => Boolean(v.pre || v.dev != null);

function compareRelease(a, b) {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] || 0) - (b[i] || 0);
    if (d) return Math.sign(d);
  }
  return 0;
}

// Mirrors packaging.version._cmpkey: 1.0.dev0 < 1.0a1 < 1.0 < 1.0.post1
function sortKey(v) {
  const pre = v.pre
    ? PRE_RANK[v.pre[0]] * 1e9 + v.pre[1]
    : v.post == null && v.dev != null ? -Infinity : Infinity;
  const post = v.post == null ? -Infinity : v.post;
  const dev = v.dev == null ? Infinity : v.dev;
  return [pre, post, dev];
}

export function compareParsed(a, b) {
  if (a.epoch !== b.epoch) return Math.sign(a.epoch - b.epoch);
  const r = compareRelease(a.release, b.release);
  if (r) return r;
  const ka = sortKey(a);
  const kb = sortKey(b);
  for (let i = 0; i < 3; i++) if (ka[i] !== kb[i]) return ka[i] < kb[i] ? -1 : 1;
  const la = a.local || '';
  const lb = b.local || '';
  return la === lb ? 0 : la < lb ? -1 : 1;
}

export function compareVersions(a, b) {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) return String(a).localeCompare(String(b));
  return compareParsed(pa, pb);
}

const CLAUSE_RE = /^\s*(~=|===|==|!=|<=|>=|<|>)\s*(\S+)\s*$/;

function matchClause(raw, v, clause) {
  const m = CLAUSE_RE.exec(clause);
  // Pre-PEP 440 metadata has clauses like ">dev" or a bare "1.0". Old setuptools
  // ignored them, so ignoring them here picks what an install would actually get.
  if (!m) return !/^[<>=!~]/.test(clause) ? satisfiesBare(v, clause) : true;
  const [, op, target] = m;

  if (op === '===') return String(raw).trim() === target;
  if (!parseVersion(target.replace(/\.\*$/, ''))) return true;

  if ((op === '==' || op === '!=') && target.endsWith('.*')) {
    const t = parseVersion(target.slice(0, -2));
    if (!t) return false;
    const match = v.epoch === t.epoch && t.release.every((n, i) => (v.release[i] || 0) === n);
    return op === '==' ? match : !match;
  }

  const t = parseVersion(target);
  if (!t) return false;
  // A specifier without a local label matches any local variant of that version.
  const c = compareParsed(t.local ? v : { ...v, local: null }, t);
  const sameRelease = compareRelease(v.release, t.release) === 0;

  switch (op) {
    case '==': return c === 0;
    case '!=': return c !== 0;
    case '<=': return c <= 0;
    case '>=': return c >= 0;
    // "<1.0" must not admit 1.0rc1; ">1.0" must not admit 1.0.post1.
    case '<': return c < 0 && !(isPrerelease(v) && !isPrerelease(t) && sameRelease);
    case '>': return c > 0 && !(v.post != null && t.post == null && sameRelease);
    case '~=': {
      if (t.release.length < 2) return false;
      const prefix = t.release.slice(0, -1);
      return c >= 0 && v.epoch === t.epoch && prefix.every((n, i) => (v.release[i] || 0) === n);
    }
    default: return false;
  }
}

function satisfiesBare(v, clause) {
  const t = parseVersion(clause);
  return t ? compareParsed(v, t) === 0 : true;
}

export function satisfies(version, specifier) {
  const v = parseVersion(version);
  if (!v) return false;
  return String(specifier || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .every(clause => matchClause(version, v, clause));
}

/**
 * Highest version satisfying `specifier`. Pre-releases are only chosen when the
 * specifier names one, or when nothing else matches (PEP 440 "pre-release handling").
 */
export function maxSatisfying(versions, specifier) {
  const matches = versions
    .map(s => ({ s, v: parseVersion(s) }))
    .filter(x => x.v && satisfies(x.s, specifier));
  if (!matches.length) return null;
  const namesPre = /\d(?:a|b|c|rc|alpha|beta|pre|preview|dev)\d*/i.test(specifier || '');
  const stable = matches.filter(x => !isPrerelease(x.v));
  const pool = namesPre || !stable.length ? matches : stable;
  return pool.reduce((best, x) => (compareParsed(x.v, best.v) > 0 ? x : best)).s;
}
