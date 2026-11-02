// PEP 508 environment-marker evaluator, e.g.
//   python_version < "3.8" and (sys_platform == "win32" or extra == 'socks')

import { parseVersion, compareParsed, satisfies } from './pep440.js';

/** The target environment dependencies are resolved for. */
export const DEFAULT_ENV = Object.freeze({
  python_version: '3.12',
  python_full_version: '3.12.7',
  implementation_version: '3.12.7',
  implementation_name: 'cpython',
  platform_python_implementation: 'CPython',
  os_name: 'posix',
  sys_platform: 'linux',
  platform_system: 'Linux',
  platform_machine: 'x86_64',
  platform_release: '',
  platform_version: '',
});

const VERSION_VARS = new Set(['python_version', 'python_full_version', 'implementation_version']);

const TOKEN_RE =
  /\s*(?:(\()|(\))|("[^"]*"|'[^']*')|(===|==|!=|<=|>=|~=|<|>)|(not\s+in\b|in\b|and\b|or\b)|([A-Za-z_][A-Za-z0-9_.]*))/y;

function tokenize(src) {
  const tokens = [];
  TOKEN_RE.lastIndex = 0;
  while (TOKEN_RE.lastIndex < src.length) {
    if (/^\s*$/.test(src.slice(TOKEN_RE.lastIndex))) break;
    const m = TOKEN_RE.exec(src);
    if (!m) throw new Error(`Unexpected marker syntax near "${src.slice(TOKEN_RE.lastIndex)}"`);
    if (m[1]) tokens.push({ t: '(' });
    else if (m[2]) tokens.push({ t: ')' });
    else if (m[3]) tokens.push({ t: 'str', v: m[3].slice(1, -1) });
    else if (m[4]) tokens.push({ t: 'op', v: m[4] });
    else if (m[5]) {
      const word = m[5].replace(/\s+/g, ' ');
      tokens.push(word === 'and' || word === 'or' ? { t: word } : { t: 'op', v: word });
    } else tokens.push({ t: 'var', v: m[6] });
  }
  return tokens;
}

const normalizeExtra = s => s.toLowerCase().replace(/[-_.]+/g, '-');

function compare(left, op, right, env, extras) {
  if (left.t === 'var' && left.v === 'extra') return extraTest(op, right.v, extras);
  if (right.t === 'var' && right.v === 'extra') return extraTest(op, left.v, extras);

  const lv = left.t === 'var' ? env[left.v] ?? '' : left.v;
  const rv = right.t === 'var' ? env[right.v] ?? '' : right.v;

  if (op === 'in') return rv.includes(lv);
  if (op === 'not in') return !rv.includes(lv);

  const versionish = (left.t === 'var' && VERSION_VARS.has(left.v)) || (right.t === 'var' && VERSION_VARS.has(right.v));
  const pl = parseVersion(lv);
  const pr = parseVersion(rv);
  if (versionish && pl && pr) {
    if (op === '~=') return satisfies(lv, `~=${rv}`);
    const c = compareParsed(pl, pr);
    return { '==': c === 0, '===': lv === rv, '!=': c !== 0, '<': c < 0, '<=': c <= 0, '>': c > 0, '>=': c >= 0 }[op];
  }
  switch (op) {
    case '==': case '===': return lv === rv;
    case '!=': return lv !== rv;
    case '<': return lv < rv;
    case '<=': return lv <= rv;
    case '>': return lv > rv;
    case '>=': return lv >= rv;
    default: return false;
  }
}

function extraTest(op, value, extras) {
  const has = extras.has(normalizeExtra(value));
  if (op === '==' || op === '===') return has;
  if (op === '!=') return !has;
  return false;
}

/**
 * Evaluate a marker against an environment and the set of requested extras.
 * Unparseable markers evaluate to true: better to over-include a dependency than hide one.
 */
export function evaluateMarker(marker, env = DEFAULT_ENV, extras = new Set()) {
  if (!marker || !marker.trim()) return true;
  try {
    const tokens = tokenize(marker);
    let i = 0;
    const peek = () => tokens[i];
    const next = () => tokens[i++];

    const parseAtom = () => {
      if (peek()?.t === '(') {
        next();
        const value = parseOr();
        if (next()?.t !== ')') throw new Error('Unbalanced parentheses');
        return value;
      }
      const left = next();
      const op = next();
      const right = next();
      if (!left || !right || op?.t !== 'op') throw new Error('Incomplete comparison');
      return compare(left, op.v, right, env, extras);
    };
    const parseAnd = () => {
      let value = parseAtom();
      while (peek()?.t === 'and') { next(); value = parseAtom() && value; }
      return value;
    };
    const parseOr = () => {
      let value = parseAnd();
      while (peek()?.t === 'or') { next(); value = parseAnd() || value; }
      return value;
    };

    const result = parseOr();
    if (i !== tokens.length) throw new Error('Trailing tokens');
    return result;
  } catch {
    return true;
  }
}
