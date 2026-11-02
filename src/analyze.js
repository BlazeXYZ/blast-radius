// Turns a resolved, enriched graph into risk findings and blast-radius metrics.
//
//   footprint   – packages a node drags in transitively (what you install because of it)
//   reachedBy   – which of YOUR direct dependencies pull a node in (who to blame / replace)
//   exclusive   – packages that disappear if you drop a direct dependency
//   inherited   – total risk score of everything a direct dependency brings along

import { reach } from './model.js';

const DAY = 86_400_000;
export const SEVERITY_POINTS = { critical: 35, high: 25, medium: 12, low: 4, unknown: 8 };
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'];

export function riskBand(score) {
  if (!score) return 'none';
  if (score < 15) return 'low';
  if (score < 35) return 'medium';
  if (score < 60) return 'high';
  return 'critical';
}

const years = days => {
  const y = days / 365;
  return y >= 2 ? `${Math.floor(y)} years` : `${Math.round(days / 30)} months`;
};
const majorOf = v => Number.parseInt(String(v).replace(/^\D+/, ''), 10);

export function scoreNode(node, ecosystem, now = Date.now()) {
  const issues = [];
  const m = node.meta;

  if (node.vulns.length) {
    const worst = node.vulns[0].severity;
    const malicious = node.vulns.some(v => v.malicious);
    const points = Math.min(60, node.vulns.reduce((s, v) => s + SEVERITY_POINTS[v.severity], 0) + (malicious ? 40 : 0));
    issues.push({
      kind: 'vuln',
      level: malicious ? 'critical' : worst === 'unknown' ? 'medium' : worst,
      label: malicious ? 'Known malicious release' : `${node.vulns.length} known vulnerabilit${node.vulns.length === 1 ? 'y' : 'ies'}`,
      detail: node.vulns.map(v => `${v.id}: ${v.summary}`).slice(0, 3).join('\n'),
      points,
    });
  }
  if (node.unresolved) issues.push({ kind: 'unresolved', level: 'high', label: 'Could not resolve', detail: node.unresolved, points: 20 });
  if (node.source === 'external') {
    issues.push({ kind: 'external', level: 'medium', label: 'Installed from outside the registry', detail: `${node.version}. Registry audits and vulnerability databases don't cover it.`, points: 10 });
  }
  if (m.deprecated) issues.push({ kind: 'deprecated', level: 'high', label: 'Deprecated', detail: m.deprecated, points: 15 });
  if (m.yanked) issues.push({ kind: 'yanked', level: 'high', label: 'Yanked release', detail: m.yanked, points: 15 });
  if (m.inactive) issues.push({ kind: 'inactive', level: 'medium', label: 'Marked inactive', detail: 'The author classifies this project as "Development Status :: 7 - Inactive".', points: 10 });
  if (m.installScripts?.length) {
    issues.push({ kind: 'install-script', level: 'medium', label: 'Runs code on install', detail: m.installScripts.map(s => `${s.hook}: ${s.cmd}`).join('\n'), points: 12 });
  }
  if (m.maintainers?.length === 1 && !m.organization) {
    issues.push({ kind: 'single-maintainer', level: 'low', label: 'Single maintainer', detail: `Only ${m.maintainers[0]} can publish releases. One compromised account is enough to ship malware.`, points: 8 });
  }
  if (m.lastPublish) {
    const age = (now - Date.parse(m.lastPublish)) / DAY;
    if (age > 4 * 365) issues.push({ kind: 'abandoned', level: 'medium', label: 'Possibly abandoned', detail: `No release of any version in ${years(age)}.`, points: 14 });
    else if (age > 2 * 365) issues.push({ kind: 'stale', level: 'low', label: 'Stale', detail: `Last release was ${years(age)} ago.`, points: 8 });
  }
  if (ecosystem === 'npm' && m.weeklyDownloads != null && m.weeklyDownloads < 1000) {
    issues.push({ kind: 'unpopular', level: 'low', label: 'Low adoption', detail: `${m.weeklyDownloads.toLocaleString()} downloads last week, so few people are watching this code.`, points: 6 });
  }
  if (m.latest && m.latest !== node.version && majorOf(m.latest) > majorOf(node.version)) {
    issues.push({ kind: 'outdated', level: 'info', label: 'Major version behind', detail: `${node.version} installed, ${m.latest} is current.`, points: 3 });
  }

  node.issues = issues;
  node.risk = Math.min(100, issues.reduce((s, i) => s + i.points, 0));
  return node;
}

export function countSeverities(nodes) {
  const counts = Object.fromEntries(SEVERITIES.map(s => [s, 0]));
  for (const n of nodes) for (const v of n.vulns) counts[v.severity]++;
  return counts;
}

export function analyze(graph, now = Date.now()) {
  const nodes = [...graph.nodes.values()];
  const packages = nodes.filter(n => !n.isRoot);

  // Depth and one shortest "why is this here?" chain per node.
  for (const n of nodes) { n.depth = Infinity; n.via = null; }
  graph.root.depth = 0;
  const queue = [graph.root];
  for (let i = 0; i < queue.length; i++) {
    const n = queue[i];
    for (const childId of n.children) {
      const child = graph.get(childId);
      if (child.depth === Infinity) { child.depth = n.depth + 1; child.via = n.id; queue.push(child); }
    }
  }

  const direct = [...graph.root.children].map(id => graph.get(id));
  for (const n of nodes) n.reachedBy = new Set();
  const subtrees = new Map();
  for (const d of direct) {
    const sub = reach(graph, d.id, 'children');
    subtrees.set(d.id, sub);
    for (const id of sub) graph.get(id).reachedBy.add(d.id);
  }

  for (const n of packages) {
    n.footprint = subtrees.has(n.id) ? subtrees.get(n.id).size - 1 : reach(graph, n.id, 'children').size - 1;
    n.dependentsTotal = reach(graph, n.id, 'parents').size - 2; // minus itself and the project root
    scoreNode(n, graph.ecosystem, now);
  }
  graph.root.footprint = packages.length;

  graph.directSummary = direct
    .map(d => {
      const sub = [...subtrees.get(d.id)].map(id => graph.get(id));
      return {
        id: d.id,
        footprint: sub.length - 1,
        // Transitive packages only this dependency pulls in (excluding itself, like footprint).
        exclusive: sub.filter(n => n.id !== d.id && n.reachedBy.size === 1).length,
        inheritedRisk: sub.reduce((s, n) => s + n.risk, 0),
        risky: sub.filter(n => n.risk >= 35).length,
        vulns: countSeverities(sub),
        deprecated: sub.filter(n => n.meta.deprecated).length,
        installScripts: sub.filter(n => n.meta.installScripts?.length).length,
        abandoned: sub.filter(n => n.issues.some(i => i.kind === 'abandoned' || i.kind === 'stale')).length,
      };
    })
    .sort((a, b) => b.inheritedRisk - a.inheritedRisk || b.footprint - a.footprint);

  const has = kind => packages.filter(n => n.issues.some(i => i.kind === kind)).length;
  const finite = packages.map(n => n.depth).filter(Number.isFinite);
  graph.summary = {
    packages: packages.length,
    direct: direct.length,
    transitive: packages.length - direct.length,
    maxDepth: finite.length ? Math.max(...finite) : 0,
    vulns: countSeverities(packages),
    vulnerablePackages: packages.filter(n => n.vulns.length).length,
    malicious: packages.filter(n => n.vulns.some(v => v.malicious)).length,
    deprecated: has('deprecated') + has('yanked'),
    installScripts: has('install-script'),
    singleMaintainer: has('single-maintainer'),
    stale: has('stale') + has('abandoned'),
    unresolved: has('unresolved') + has('external'),
    totalRisk: packages.reduce((s, n) => s + n.risk, 0),
  };
  return graph;
}

/** Shortest dependency chain from the project root to `id`, root first. */
export function pathToRoot(graph, id) {
  const path = [];
  for (let n = graph.get(id); n; n = n.via ? graph.get(n.via) : null) path.unshift(n);
  return path;
}
