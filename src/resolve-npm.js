// Resolves a package.json into a full transitive graph by walking the npm registry,
// approximating npm's own choice of version for each range.

import semver from 'semver';
import { DepGraph, ROOT_ID } from './model.js';
import { getPackument, npmMeta } from './npm-registry.js';
import { createLimiter, mapLimit } from './util.js';

// git URLs, tarball URLs, local paths, "user/repo" GitHub shorthand, pnpm workspaces
const NON_REGISTRY = /^(?:git(?:\+[a-z]+)?:|github:|gitlab:|bitbucket:|file:|link:|workspace:|portal:|https?:|\.{0,2}\/|[\w.-]+\/[\w.-]+(?:#.*)?$)/i;

function parseAlias(range) {
  const m = /^npm:((?:@[^/]+\/)?[^@]+)(?:@(.*))?$/.exec(range);
  return m ? { name: m[1], range: m[2] || '*' } : null;
}

/** npm prefers the `latest` dist-tag whenever it satisfies the range. */
export function pickVersion(pk, range) {
  const r = range && range.trim() ? range.trim() : '*';
  if (pk.distTags[r]) return pk.distTags[r];
  const latest = pk.distTags.latest;
  try {
    if (latest && pk.versions[latest] && semver.satisfies(latest, r, { loose: true })) return latest;
    return semver.maxSatisfying(Object.keys(pk.versions), r, { loose: true });
  } catch {
    return null;
  }
}

export function semverCompare(a, b) {
  try {
    return semver.compare(a, b, { loose: true });
  } catch {
    return String(a).localeCompare(String(b));
  }
}

export async function resolveNpm(manifest, { includeDev = false, maxNodes = 1500, onProgress = () => {} } = {}) {
  const graph = new DepGraph('npm', manifest.name);
  const queue = [];
  const enqueue = (parent, deps, kind) => {
    for (const [name, range] of Object.entries(deps || {})) queue.push({ parent, name, range: String(range), kind });
  };
  enqueue(ROOT_ID, manifest.dependencies, 'prod');
  enqueue(ROOT_ID, manifest.optionalDependencies, 'optional');
  if (includeDev) enqueue(ROOT_ID, manifest.devDependencies, 'dev');

  let resolved = 0;

  const addPlaceholder = (parent, name, range, kind, fields) => {
    const id = `${name}@${range}`;
    if (!graph.get(id)) graph.addNode({ id, name, version: range, ...fields });
    graph.addEdge(parent, id, { range, kind });
  };

  const processItem = async ({ parent, name, range, kind }) => {
    let pkgName = name;
    let pkgRange = range;
    const alias = parseAlias(range);
    if (alias) ({ name: pkgName, range: pkgRange } = alias);

    if (NON_REGISTRY.test(pkgRange)) {
      addPlaceholder(parent, name, pkgRange, kind, { source: 'external' });
      return;
    }
    if (graph.truncated) return;

    let pk;
    try {
      pk = await getPackument(pkgName);
    } catch (err) {
      graph.warnings.push(`Couldn't fetch ${pkgName}: ${err.message}`);
    }
    const version = pk ? pickVersion(pk, pkgRange) : null;
    if (!version) {
      // Optional deps legitimately fail to resolve on some platforms; don't flag those.
      if (kind === 'optional') return;
      const exact = semver.valid(pkgRange, { loose: true });
      const why = pk === null
        ? 'Not found on the npm registry (removed or never published)'
        : !pk ? 'Registry request failed'
        : exact && pk.time?.[exact] ? `Version ${exact} was unpublished from the registry. npm usually does this when a release is malicious.`
        : `No published version satisfies "${pkgRange}"`;
      addPlaceholder(parent, pkgName, pkgRange, kind, { unresolved: why });
      return;
    }

    const id = `${pkgName}@${version}`;
    const existing = graph.get(id);
    if (!existing) {
      if (graph.size >= maxNodes) { graph.truncated = true; return; }
      graph.addNode({ id, name: pkgName, version, meta: npmMeta(pk, version) });
      onProgress({ phase: 'resolve', count: ++resolved, current: id });
    }
    graph.addEdge(parent, id, { range, kind });
    if (existing) return;

    const v = pk.versions[version];
    enqueue(id, v.dependencies, 'prod');
    enqueue(id, v.optionalDependencies, 'optional');
    // npm 7+ installs non-optional peers automatically.
    for (const [dep, r] of Object.entries(v.peerDependencies)) {
      if (!v.peerDependenciesMeta[dep]?.optional && !(dep in v.dependencies)) queue.push({ parent: id, name: dep, range: r, kind: 'peer' });
    }
  };

  const limit = createLimiter(12);
  const inflight = new Set();
  while (queue.length || inflight.size) {
    while (queue.length) {
      const item = queue.shift();
      const task = limit(() => processItem(item))
        .catch(err => graph.warnings.push(`${item.name}: ${err.message}`))
        .finally(() => inflight.delete(task));
      inflight.add(task);
    }
    if (inflight.size) await Promise.race(inflight);
  }

  if (graph.truncated) graph.warnings.push(`Stopped at ${maxNodes} packages. Raise "Max packages" to see the full tree.`);
  return graph;
}

/** Lockfile graphs already know exact versions; this adds the registry metadata they lack. */
export async function enrichFromRegistry(graph, { onProgress = () => {} } = {}) {
  const nodes = [...graph.packages()].filter(n => !n.source && !n.unresolved);
  let done = 0;
  await mapLimit(nodes, 12, async node => {
    try {
      const pk = await getPackument(node.name);
      if (pk?.versions[node.version]) {
        const meta = npmMeta(pk, node.version);
        // The lockfile's install-script flag is authoritative when the packument has none.
        if (!meta.installScripts.length && node.meta.installScripts?.length) meta.installScripts = node.meta.installScripts;
        node.meta = { ...node.meta, ...meta, license: meta.license || node.meta.license };
      } else if (pk === null) {
        node.unresolved = 'No longer on the npm registry (unpublished or removed)';
      }
    } catch (err) {
      graph.warnings.push(`Couldn't fetch metadata for ${node.name}: ${err.message}`);
    }
    onProgress({ phase: 'metadata', done: ++done, total: nodes.length });
  });
}
