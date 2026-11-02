// Detects which manifest format was supplied and parses it into resolver input.

/** PEP 503 name normalization: "Flask_SQLAlchemy" -> "flask-sqlalchemy". */
export const normalizeName = name => name.toLowerCase().replace(/[-_.]+/g, '-');

const PEP508_RE = /^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[([^\]]*)\])?\s*\(?\s*([^()]*?)\s*\)?\s*$/;

/** Parses a PEP 508 requirement such as `requests[socks] (>=2.8,<3) ; python_version >= "3.7"`. */
export function parsePep508(input) {
  const semi = input.indexOf(';');
  const spec = semi === -1 ? input : input.slice(0, semi);
  const marker = semi === -1 ? null : input.slice(semi + 1).trim() || null;
  if (spec.includes('@')) return null; // direct URL references can't be resolved against the index
  const m = PEP508_RE.exec(spec);
  if (!m) return null;
  return {
    name: normalizeName(m[1]),
    displayName: m[1],
    extras: m[2] ? m[2].split(',').map(e => normalizeName(e.trim())).filter(Boolean) : [],
    specifier: m[3].replace(/\s+/g, ''),
    marker,
  };
}

export function parseRequirements(text) {
  const requirements = [];
  const skipped = [];
  const lines = text.replace(/\\\r?\n/g, ' ').split(/\r?\n/);
  for (const raw of lines) {
    let line = raw.replace(/(^|\s)#.*$/, '').trim();
    if (!line) continue;
    if (line.startsWith('-') || /^[a-z+]+:\/\//i.test(line) || line.startsWith('.') || line.startsWith('/')) {
      skipped.push(line); // -r, -e, --index-url, URLs and local paths
      continue;
    }
    line = line.replace(/\s+--[a-z-]+(?:[=\s]\S+)?/gi, ''); // per-line options like --hash=sha256:...
    const req = parsePep508(line);
    if (req) requirements.push(req);
    else skipped.push(line);
  }
  return { requirements, skipped };
}

/** Pulls `[project].name` and `[project].dependencies` out of a pyproject.toml. */
export function parsePyproject(text) {
  const section = /^\[project\]\s*$([\s\S]*?)(?=^\[|$(?![\s\S]))/m.exec(text);
  if (!section) throw new Error('pyproject.toml has no [project] table (Poetry-only projects are not supported yet)');
  const body = section[1];
  const name = /^\s*name\s*=\s*["']([^"']+)["']/m.exec(body)?.[1];
  const start = /^\s*dependencies\s*=\s*\[/m.exec(body);
  const strings = [];
  if (start) {
    // Scan string literals until the closing bracket; regex alone trips on "pkg[extra]".
    let i = start.index + start[0].length;
    while (i < body.length && body[i] !== ']') {
      const ch = body[i];
      if (ch === '"' || ch === "'") {
        const end = body.indexOf(ch, i + 1);
        if (end === -1) break;
        strings.push(body.slice(i + 1, end));
        i = end + 1;
      } else if (ch === '#') {
        i = body.indexOf('\n', i) === -1 ? body.length : body.indexOf('\n', i);
      } else i++;
    }
  }
  const requirements = [];
  const skipped = [];
  for (const s of strings) {
    const req = parsePep508(s);
    if (req) requirements.push(req);
    else skipped.push(s);
  }
  return { name, requirements, skipped };
}

/**
 * @returns {{kind: 'npm-manifest'|'npm-lock'|'pypi', ecosystem: string, label: string, data: any, name?: string, skipped?: string[]}}
 */
export function detectInput(text, filename = '') {
  const trimmed = text.trim();
  if (!trimmed) throw new Error('Nothing to analyze yet. Paste a manifest, upload a file or fetch a GitHub repo.');
  const lower = filename.toLowerCase();

  if (trimmed.startsWith('{')) {
    let json;
    try {
      json = JSON.parse(trimmed);
    } catch (err) {
      throw new Error(`That looks like JSON but didn't parse: ${err.message}`);
    }
    if (json.lockfileVersion) {
      return { kind: 'npm-lock', ecosystem: 'npm', label: 'package-lock.json', data: json, name: json.name };
    }
    if (json.dependencies || json.devDependencies || json.optionalDependencies || json.name) {
      return { kind: 'npm-manifest', ecosystem: 'npm', label: 'package.json', data: json, name: json.name };
    }
    throw new Error("This JSON doesn't look like a package.json or package-lock.json.");
  }

  if (lower.endsWith('.toml') || /^\[project\]\s*$/m.test(text)) {
    const parsed = parsePyproject(text);
    if (!parsed.requirements.length) throw new Error('No dependencies found in [project].dependencies.');
    return { kind: 'pypi', ecosystem: 'PyPI', label: 'pyproject.toml', data: parsed.requirements, name: parsed.name, skipped: parsed.skipped };
  }

  const parsed = parseRequirements(text);
  if (!parsed.requirements.length) {
    throw new Error("Couldn't find any requirements. Supported: package.json, package-lock.json, requirements.txt, pyproject.toml.");
  }
  return { kind: 'pypi', ecosystem: 'PyPI', label: 'requirements.txt', data: parsed.requirements, skipped: parsed.skipped };
}
