// Adds data the registries don't hold: known vulnerabilities (OSV.dev) and
// npm download counts (a rough proxy for how many eyes are on the code).

import { fetchJson, mapLimit, chunk } from './util.js';
import { cvss3Score, severityFromScore } from './cvss.js';

const OSV = 'https://api.osv.dev/v1/';
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'unknown'];
const MAX_ADVISORY_DETAILS = 600;

const normSeverity = s => ({ CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' })[String(s || '').toUpperCase()] || null;
const normName = s => String(s).toLowerCase().replace(/[-_.]+/g, '-');
export const bySeverity = (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);

function pickFix(fixed, current, compare) {
  const sorted = [...new Set(fixed)].sort(compare);
  return sorted.find(v => compare(v, current) > 0) || sorted.at(-1) || null;
}

export function summarizeAdvisory(doc, id, node, compare) {
  const url = `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
  if (!doc) return { id, aliases: [], summary: 'Advisory details unavailable', severity: 'unknown', score: null, fixedIn: null, url };

  let severity = normSeverity(doc.database_specific?.severity);
  let score = null;
  const v3 = (doc.severity || []).find(s => s.type === 'CVSS_V3');
  if (v3) score = cvss3Score(v3.score);
  if (!severity) {
    const affectedSeverity = (doc.affected || []).map(a => normSeverity(a.database_specific?.severity || a.ecosystem_specific?.severity)).find(Boolean);
    severity = affectedSeverity || severityFromScore(score) || (id.startsWith('MAL-') ? 'critical' : 'unknown');
  }

  const fixed = [];
  for (const affected of doc.affected || []) {
    if (affected.package && normName(affected.package.name) !== normName(node.name)) continue;
    for (const range of affected.ranges || []) {
      if (range.type === 'GIT') continue;
      for (const event of range.events || []) if (event.fixed) fixed.push(event.fixed);
    }
  }

  return {
    id,
    aliases: doc.aliases || [],
    summary: doc.summary || (doc.details || '').split('\n')[0].slice(0, 200),
    severity,
    score,
    fixedIn: fixed.length ? pickFix(fixed, node.version, compare) : null,
    published: doc.published || null,
    // OSV's MAL-* feed, or GitHub advisories tagged CWE-506 "Embedded Malicious Code".
    malicious: id.startsWith('MAL-') || (doc.database_specific?.cwe_ids || []).includes('CWE-506'),
    url,
  };
}

/** Drops duplicates of one issue reported under different IDs (e.g. PYSEC-* and GHSA-*). */
function dedupe(vulns) {
  const seen = new Set();
  const out = [];
  // GHSA entries carry reviewed severities, so keep those when both exist.
  for (const v of [...vulns].sort((a, b) => (b.id.startsWith('GHSA') ? 1 : 0) - (a.id.startsWith('GHSA') ? 1 : 0))) {
    if ([v.id, ...v.aliases].some(x => seen.has(x))) continue;
    [v.id, ...v.aliases].forEach(x => seen.add(x));
    out.push(v);
  }
  return out.sort(bySeverity);
}

export async function attachVulns(graph, { compare, onProgress = () => {} }) {
  // Unresolved exact pins are still worth checking: unpublished malware stays in OSV.
  const exactPin = /^v?\d+(?:\.\d+)*(?:[-+.][\w.]+)?$/;
  const nodes = [...graph.packages()].filter(n => !n.source && (!n.unresolved || exactPin.test(n.version)));
  const idsByNode = new Map();
  let queried = 0;

  for (const batch of chunk(nodes, 500)) {
    const res = await fetchJson(`${OSV}querybatch`, {
      cache: false,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries: batch.map(n => ({ package: { name: n.name, ecosystem: graph.ecosystem }, version: n.version })) }),
    });
    res?.results?.forEach((r, i) => {
      if (r.vulns?.length) idsByNode.set(batch[i], r.vulns.map(v => v.id));
    });
    queried += batch.length;
    onProgress({ phase: 'osv', done: queried, total: nodes.length });
  }

  const allIds = [...new Set([...idsByNode.values()].flat())];
  if (allIds.length > MAX_ADVISORY_DETAILS) {
    graph.warnings.push(`${allIds.length} advisories found; detailed severity fetched for the first ${MAX_ADVISORY_DETAILS}.`);
  }
  const details = new Map();
  let fetched = 0;
  await mapLimit(allIds.slice(0, MAX_ADVISORY_DETAILS), 10, async id => {
    try {
      details.set(id, await fetchJson(`${OSV}vulns/${encodeURIComponent(id)}`));
    } catch {
      // Summarized as "details unavailable" below.
    }
    onProgress({ phase: 'advisories', done: ++fetched, total: Math.min(allIds.length, MAX_ADVISORY_DETAILS) });
  });

  for (const [node, ids] of idsByNode) {
    node.vulns = dedupe(ids.map(id => summarizeAdvisory(details.get(id), id, node, compare)));
  }
  return allIds.length;
}

export async function attachNpmDownloads(graph, { onProgress = () => {} } = {}) {
  const names = [...new Set([...graph.packages()].filter(n => !n.unresolved && !n.source).map(n => n.name))];
  const counts = new Map();
  const api = 'https://api.npmjs.org/downloads/point/last-week/';

  // The bulk endpoint takes up to 128 comma-separated names but rejects scoped ones.
  for (const batch of chunk(names.filter(n => !n.startsWith('@')), 128)) {
    try {
      let res = await fetchJson(api + batch.join(','));
      if (batch.length === 1) res = { [batch[0]]: res };
      for (const [name, value] of Object.entries(res || {})) if (value) counts.set(name, value.downloads);
    } catch {
      // Download counts are a nice-to-have; carry on without them.
    }
  }
  await mapLimit(names.filter(n => n.startsWith('@')), 6, async name => {
    try {
      const res = await fetchJson(api + name);
      if (res) counts.set(name, res.downloads);
    } catch {
      // As above.
    }
  });

  for (const node of graph.packages()) if (counts.has(node.name)) node.meta.weeklyDownloads = counts.get(node.name);
  onProgress({ phase: 'downloads', done: names.length, total: names.length });
}
