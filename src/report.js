// Exports an analyzed graph as a Markdown report or machine-readable JSON.

import { SEVERITIES } from './analyze.js';

const cell = s => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');

export function toMarkdown(graph, sourceLabel) {
  const s = graph.summary;
  const pkgs = [...graph.packages()];
  const lines = [
    `# Dependency blast radius: ${graph.root.name}`,
    '',
    `Source: ${sourceLabel} · Ecosystem: ${graph.ecosystem} · Generated ${new Date().toISOString().slice(0, 10)} by Blast Radius`,
    '',
    '## Summary',
    '',
    '| Metric | Value |',
    '| --- | --- |',
    `| Packages installed | ${s.packages} (${s.direct} direct, ${s.transitive} transitive) |`,
    `| Deepest chain | ${s.maxDepth} levels |`,
    `| Vulnerabilities | ${SEVERITIES.map(k => `${s.vulns[k]} ${k}`).join(', ')} |`,
    `| Packages with vulnerabilities | ${s.vulnerablePackages} |`,
    `| Deprecated or yanked | ${s.deprecated} |`,
    `| Run install scripts | ${s.installScripts} |`,
    `| Single maintainer | ${s.singleMaintainer} |`,
    `| Stale or abandoned | ${s.stale} |`,
    '',
    '## Direct dependencies by inherited risk',
    '',
    '| Dependency | Brings in | Removed if dropped | Inherited risk | Critical/High vulns |',
    '| --- | --- | --- | --- | --- |',
    ...graph.directSummary.map(d => {
      const n = graph.get(d.id);
      return `| ${cell(n.name)}@${cell(n.version)} | ${d.footprint} | ${d.exclusive} | ${d.inheritedRisk} | ${d.vulns.critical + d.vulns.high} |`;
    }),
    '',
    '## Riskiest packages',
    '',
    '| Package | Risk | Depth | Pulled in by | Issues |',
    '| --- | --- | --- | --- | --- |',
    ...pkgs
      .filter(n => n.risk > 0)
      .sort((a, b) => b.risk - a.risk)
      .slice(0, 25)
      .map(n => `| ${cell(n.id)} | ${n.risk} | ${n.depth} | ${[...n.reachedBy].map(id => graph.get(id).name).join(', ')} | ${cell(n.issues.map(i => i.label).join('; '))} |`),
  ];

  const vulnerable = pkgs.filter(n => n.vulns.length).sort((a, b) => b.risk - a.risk);
  if (vulnerable.length) {
    lines.push('', '## Vulnerabilities', '', '| Package | Advisory | Severity | Fixed in | Summary |', '| --- | --- | --- | --- | --- |');
    for (const n of vulnerable) {
      for (const v of n.vulns) lines.push(`| ${cell(n.id)} | [${v.id}](${v.url}) | ${v.severity} | ${cell(v.fixedIn || 'n/a')} | ${cell(v.summary)} |`);
    }
  }

  if (graph.warnings.length) lines.push('', '## Notes', '', ...graph.warnings.map(w => `- ${w}`));
  return `${lines.join('\n')}\n`;
}

export function toJSON(graph, sourceLabel) {
  return JSON.stringify(
    {
      project: graph.root.name,
      ecosystem: graph.ecosystem,
      source: sourceLabel,
      generatedAt: new Date().toISOString(),
      summary: graph.summary,
      directDependencies: graph.directSummary.map(d => ({ ...d, name: graph.get(d.id).name, version: graph.get(d.id).version })),
      packages: [...graph.packages()].map(n => ({
        id: n.id,
        name: n.name,
        version: n.version,
        depth: n.depth,
        risk: n.risk,
        footprint: n.footprint,
        dependents: n.dependentsTotal,
        pulledInBy: [...n.reachedBy].map(id => graph.get(id).name),
        dependencies: [...n.children],
        issues: n.issues.map(({ kind, level, label, detail }) => ({ kind, level, label, detail })),
        vulnerabilities: n.vulns,
        meta: n.meta,
      })),
      warnings: graph.warnings,
    },
    null,
    2,
  );
}
