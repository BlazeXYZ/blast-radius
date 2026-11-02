// Builds the exact installed graph from a package-lock.json (v1, v2 or v3) by
// replaying Node's module resolution over the lockfile's node_modules layout.

import { DepGraph, ROOT_ID } from './model.js';

const REGISTRY_TARBALL = /^https:\/\/registry\.(?:npmjs\.org|yarnpkg\.com)\//;

const nameFromPath = path => path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);

/**
 * Finds the install location `require(dep)` would hit from `fromPath`:
 * fromPath/node_modules/dep, then each ancestor's node_modules, then the top level.
 */
export function resolvePath(packages, fromPath, dep) {
  let path = fromPath;
  for (;;) {
    const candidate = `${path ? `${path}/` : ''}node_modules/${dep}`;
    if (packages[candidate]) return candidate;
    if (!path) return null;
    const i = path.lastIndexOf('/node_modules/');
    path = i >= 0 ? path.slice(0, i) : '';
  }
}

/** Converts lockfileVersion 1's nested `dependencies` tree into the v2 flat `packages` map. */
export function convertV1(lock) {
  const packages = { '': { name: lock.name, version: lock.version, dependencies: {}, devDependencies: {} } };
  const required = new Set();
  const walk = (deps, prefix) => {
    for (const [name, d] of Object.entries(deps || {})) {
      const key = `${prefix ? `${prefix}/` : ''}node_modules/${name}`;
      packages[key] = { version: d.version, resolved: d.resolved, dev: d.dev, optional: d.optional, dependencies: d.requires || {} };
      for (const r of Object.keys(d.requires || {})) required.add(r);
      walk(d.dependencies, key);
    }
  };
  walk(lock.dependencies, '');
  // v1 doesn't record which top-level packages are direct; anything nobody else requires must be.
  for (const [name, d] of Object.entries(lock.dependencies || {})) {
    if (required.has(name)) continue;
    packages[''][d.dev ? 'devDependencies' : 'dependencies'][name] = d.version;
  }
  return packages;
}

export function buildLockGraph(lock, { includeDev = false, maxNodes = 1500 } = {}) {
  const v1 = !lock.packages || !Object.keys(lock.packages).length;
  const packages = v1 ? convertV1(lock) : lock.packages;
  const rootEntry = packages[''] || {};
  const graph = new DepGraph('npm', rootEntry.name || lock.name);
  if (v1) graph.warnings.push('lockfileVersion 1: direct dependencies were inferred, so a few may appear deeper than they are.');

  const queue = [];
  const enqueue = (fromPath, fromId, deps, kind) => {
    for (const [name, range] of Object.entries(deps || {})) queue.push({ fromPath, fromId, name, range, kind });
  };
  enqueue('', ROOT_ID, rootEntry.dependencies, 'prod');
  enqueue('', ROOT_ID, rootEntry.optionalDependencies, 'optional');
  if (includeDev) enqueue('', ROOT_ID, rootEntry.devDependencies, 'dev');

  const visitedPaths = new Set();
  let missing = 0;

  while (queue.length) {
    const { fromPath, fromId, name, range, kind } = queue.shift();
    let path = resolvePath(packages, fromPath, name);
    if (path == null) {
      if (kind === 'prod') missing++;
      continue;
    }
    let entry = packages[path];
    if (entry.link) {
      path = entry.resolved;
      entry = packages[path] || {};
    }
    if (!includeDev && entry.dev) continue;

    const pkgName = entry.name || (path.includes('node_modules/') ? nameFromPath(path) : name);
    const version = entry.version || '0.0.0';
    const id = `${pkgName}@${version}`;
    if (!graph.get(id)) {
      if (graph.size >= maxNodes) { graph.truncated = true; continue; }
      const external = (entry.resolved && !REGISTRY_TARBALL.test(entry.resolved)) || /^(?:git|file|link|https?):/.test(version);
      graph.addNode({
        id,
        name: pkgName,
        version,
        source: external ? 'external' : undefined,
        meta: {
          license: entry.license || null,
          resolved: entry.resolved,
          installScripts: entry.hasInstallScript ? [{ hook: 'install', cmd: '(lockfile reports an install script)' }] : [],
        },
      });
    }
    graph.addEdge(fromId, id, { range, kind });

    if (visitedPaths.has(path)) continue;
    visitedPaths.add(path);
    enqueue(path, id, entry.dependencies, 'prod');
    enqueue(path, id, entry.optionalDependencies, 'optional');
    enqueue(path, id, entry.peerDependencies, 'peer');
  }

  if (missing) graph.warnings.push(`${missing} dependency reference${missing === 1 ? '' : 's'} pointed at packages missing from the lockfile.`);
  if (graph.truncated) graph.warnings.push(`Stopped at ${maxNodes} packages. Raise "Max packages" to see the full tree.`);
  return graph;
}
