// npm registry access. Packuments are slimmed on arrival: full documents can be
// megabytes each and we only need a handful of fields per version.

import { fetchJson } from './util.js';

const REGISTRY = 'https://registry.npmjs.org/';
const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall'];
const packuments = new Map();

export const encodePackageName = name =>
  name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);

export function getPackument(name) {
  if (!packuments.has(name)) {
    packuments.set(name, fetchJson(REGISTRY + encodePackageName(name), { cache: false }).then(slimPackument));
  }
  return packuments.get(name);
}

export function clearPackuments() {
  packuments.clear();
}

function slimPackument(doc) {
  if (!doc) return null;
  const versions = {};
  for (const [version, v] of Object.entries(doc.versions || {})) {
    const scripts = {};
    for (const hook of INSTALL_HOOKS) if (v.scripts?.[hook]) scripts[hook] = v.scripts[hook];
    versions[version] = {
      dependencies: v.dependencies || {},
      optionalDependencies: v.optionalDependencies || {},
      peerDependencies: v.peerDependencies || {},
      peerDependenciesMeta: v.peerDependenciesMeta || {},
      scripts,
      native: Boolean(v.gypfile),
      deprecated: typeof v.deprecated === 'string' && v.deprecated ? v.deprecated : null,
      license: licenseOf(v.license ?? v.licenses),
      description: v.description,
      repository: repoUrl(v.repository),
      homepage: v.homepage,
      maintainers: (v.maintainers || []).map(m => m.name || m),
    };
  }
  return {
    name: doc.name,
    distTags: doc['dist-tags'] || {},
    versions,
    time: doc.time || {},
    maintainers: (doc.maintainers || []).map(m => m.name || m),
    description: doc.description,
    repository: repoUrl(doc.repository),
  };
}

function licenseOf(license) {
  if (!license) return null;
  if (typeof license === 'string') return license;
  if (Array.isArray(license)) return license.map(licenseOf).filter(Boolean).join(' OR ') || null;
  return license.type || null;
}

/** Normalizes the many shapes of `repository` into an https URL (or null). */
export function repoUrl(repo) {
  let url = typeof repo === 'string' ? repo : repo?.url;
  if (!url) return null;
  url = url.trim();
  const shorthand = /^(github|gitlab|bitbucket):(.+)$/.exec(url);
  if (shorthand) return `https://${shorthand[1]}.${shorthand[1] === 'bitbucket' ? 'org' : 'com'}/${shorthand[2]}`;
  if (/^[\w.-]+\/[\w.-]+$/.test(url)) return `https://github.com/${url}`;
  url = url
    .replace(/^git\+/, '')
    .replace(/^git:\/\//, 'https://')
    .replace(/^ssh:\/\/git@/, 'https://')
    .replace(/^git@([^:]+):/, 'https://$1/')
    .replace(/\.git(#.*)?$/, '');
  return /^https?:\/\//.test(url) ? url : null;
}

/** Risk-relevant metadata for one version of a package. */
export function npmMeta(pk, version) {
  const v = pk.versions[version] || {};
  const installScripts = Object.entries(v.scripts || {}).map(([hook, cmd]) => ({ hook, cmd }));
  if (!installScripts.length && v.native) installScripts.push({ hook: 'install', cmd: 'node-gyp rebuild (native addon)' });

  let lastPublish = null;
  for (const ver of Object.keys(pk.versions)) {
    const t = pk.time[ver];
    if (t && (!lastPublish || t > lastPublish)) lastPublish = t;
  }

  return {
    description: v.description || pk.description || '',
    license: v.license,
    repository: v.repository || pk.repository,
    homepage: v.homepage,
    maintainers: pk.maintainers.length ? pk.maintainers : v.maintainers || [],
    lastPublish,
    publishedAt: pk.time[version] || null,
    latest: pk.distTags.latest || null,
    deprecated: v.deprecated,
    installScripts,
    registryUrl: `https://www.npmjs.com/package/${pk.name}/v/${version}`,
  };
}
