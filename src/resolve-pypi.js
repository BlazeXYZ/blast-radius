// Resolves Python requirements against the PyPI JSON API, honouring extras and
// environment markers for a fixed target environment (see markers.js DEFAULT_ENV).

import { DepGraph, ROOT_ID } from './model.js';
import { fetchJson, createLimiter } from './util.js';
import { maxSatisfying, satisfies } from './pep440.js';
import { parsePep508 } from './parse.js';
import { evaluateMarker, DEFAULT_ENV } from './markers.js';

const PYPI = 'https://pypi.org/pypi/';
const SOURCE_KEYS = /^(source|source code|repository|code|github|git)$/i;

const getProject = name => fetchJson(`${PYPI}${encodeURIComponent(name)}/json`);
const getRelease = (name, version) => fetchJson(`${PYPI}${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`);

export function pickPypiVersion(project, specifier) {
  const releases = project.releases || {};
  const installable = Object.entries(releases)
    .filter(([, files]) => files.length && !files.every(f => f.yanked))
    .map(([v]) => v);
  // PEP 592: a yanked release is still selectable when pinned exactly.
  return maxSatisfying(installable, specifier) || (/^===?/.test(specifier) ? maxSatisfying(Object.keys(releases), specifier) : null);
}

function pypiMeta(project, release, version) {
  const info = release.info;
  let lastPublish = null;
  for (const files of Object.values(project.releases || {})) {
    for (const f of files) {
      const t = f.upload_time_iso_8601 || f.upload_time;
      if (t && (!lastPublish || t > lastPublish)) lastPublish = t;
    }
  }
  const files = project.releases?.[version] || [];
  const publishedAt = files.map(f => f.upload_time_iso_8601 || f.upload_time).sort()[0] || null;
  const urls = info.project_urls || {};
  const repository = Object.entries(urls).find(([k]) => SOURCE_KEYS.test(k))?.[1]
    || Object.values(urls).find(u => /github\.com|gitlab\.com/.test(u))
    || (/github\.com|gitlab\.com/.test(info.home_page || '') ? info.home_page : null);
  const classifierLicense = (info.classifiers || []).find(c => c.startsWith('License ::'))?.split(' :: ').pop();
  const license = info.license_expression || classifierLicense || (info.license && info.license.length <= 40 ? info.license : null);
  const yanked = files.length > 0 && files.every(f => f.yanked);

  return {
    description: info.summary || '',
    license,
    repository,
    homepage: info.home_page || urls.Homepage || urls.homepage || null,
    maintainers: (project.ownership?.roles || []).map(r => r.user),
    organization: project.ownership?.organization || null,
    lastPublish,
    publishedAt,
    latest: project.info.version,
    yanked: yanked ? files[0].yanked_reason || 'This release was yanked by its maintainers' : null,
    inactive: (info.classifiers || []).includes('Development Status :: 7 - Inactive'),
    requiresPython: info.requires_python || null,
    installScripts: [],
    registryUrl: `https://pypi.org/project/${project.info.name}/${version}/`,
  };
}

export async function resolvePypi(requirements, { rootName, maxNodes = 1500, env = DEFAULT_ENV, onProgress = () => {} } = {}) {
  const graph = new DepGraph('PyPI', rootName || 'requirements.txt');
  const state = new Map(); // node id -> { requires, extras }
  const queue = requirements
    .filter(req => !req.marker || evaluateMarker(req.marker, env, new Set()))
    .map(req => ({ parent: ROOT_ID, req }));
  let resolved = 0;

  // Unlike npm, a Python environment holds exactly one version of each package, and
  // your own top-level pins win. The first request for a name decides its version.
  const rootSpecs = new Map(queue.map(({ req }) => [req.name, req.specifier]));
  const chosen = new Map();
  const conflicts = new Set();
  const choose = req => {
    if (!chosen.has(req.name)) {
      chosen.set(req.name, getProject(req.name).then(project => project && {
        project,
        version: pickPypiVersion(project, rootSpecs.has(req.name) ? rootSpecs.get(req.name) : req.specifier),
      }));
    }
    return chosen.get(req.name);
  };

  const placeholder = (parent, req, why) => {
    const id = `${req.name}@${req.specifier || '*'}`;
    if (!graph.get(id)) graph.addNode({ id, name: req.displayName, version: req.specifier || '*', unresolved: why });
    graph.addEdge(parent, id, { range: req.specifier || '*', kind: 'prod' });
  };

  const processItem = async ({ parent, req }) => {
    if (graph.truncated) return;
    const pick = await choose(req);
    if (!pick) return placeholder(parent, req, 'Not found on PyPI');
    const { project, version } = pick;
    if (!version) return placeholder(parent, req, `No release satisfies "${rootSpecs.get(req.name) ?? req.specifier}"`);
    if (parent !== ROOT_ID && req.specifier && !satisfies(version, req.specifier)) {
      const who = graph.get(parent);
      conflicts.add(`${who.name} ${who.version} requires ${project.info.name}${req.specifier}, but ${version} is installed. pip would refuse this combination.`);
    }

    const id = `${req.name}@${version}`;
    let st = state.get(id);
    let fresh = false;
    if (!st) {
      const release = version === project.info.version ? project : await getRelease(req.name, version);
      st = state.get(id); // another task may have created it while we awaited
      if (!st) {
        if (graph.size >= maxNodes) { graph.truncated = true; return; }
        graph.addNode({ id, name: project.info.name, version, meta: pypiMeta(project, release || project, version) });
        st = {
          requires: ((release || project).info.requires_dist || []).map(parsePep508).filter(Boolean),
          extras: new Set(),
        };
        state.set(id, st);
        fresh = true;
        onProgress({ phase: 'resolve', count: ++resolved, current: id });
      }
    }
    graph.addEdge(parent, id, { range: req.specifier || '*', kind: req.extras.length ? `extras [${req.extras.join(', ')}]` : 'prod' });

    // Each newly requested extra can switch on more dependencies of an already-seen node.
    const before = new Set(st.extras);
    const added = req.extras.filter(e => !before.has(e));
    if (!fresh && !added.length) return;
    added.forEach(e => st.extras.add(e));
    for (const dep of st.requires) {
      const nowOn = evaluateMarker(dep.marker, env, st.extras);
      const wasOn = !fresh && evaluateMarker(dep.marker, env, before);
      if (nowOn && !wasOn) queue.push({ parent: id, req: dep });
    }
  };

  const limit = createLimiter(10);
  const inflight = new Set();
  while (queue.length || inflight.size) {
    while (queue.length) {
      const item = queue.shift();
      const task = limit(() => processItem(item))
        .catch(err => graph.warnings.push(`${item.req.displayName}: ${err.message}`))
        .finally(() => inflight.delete(task));
      inflight.add(task);
    }
    if (inflight.size) await Promise.race(inflight);
  }

  graph.warnings.push(...conflicts);
  graph.warnings.push(`Resolved for CPython ${env.python_version} on ${env.platform_system}. pip's backtracking resolver may pick slightly different versions.`);
  if (graph.truncated) graph.warnings.push(`Stopped at ${maxNodes} packages. Raise "Max packages" to see the full tree.`);
  return graph;
}
