import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildLockGraph, resolvePath } from '../src/resolve-lock.js';
import { analyze, riskBand, pathToRoot } from '../src/analyze.js';
import { cvss3Score, severityFromScore } from '../src/cvss.js';
import { summarizeAdvisory } from '../src/enrich.js';
import { repoUrl } from '../src/npm-registry.js';
import { ROOT_ID } from '../src/model.js';

const NOW = Date.parse('2026-11-01T00:00:00Z');

// app -> web (-> qs, debug@2) and app -> cli (-> debug@4 nested, qs shared)
const lock = {
  name: 'app',
  lockfileVersion: 3,
  packages: {
    '': { name: 'app', dependencies: { web: '^1.0.0', cli: '^2.0.0' }, devDependencies: { jest: '^29' } },
    'node_modules/web': { version: '1.2.0', resolved: 'https://registry.npmjs.org/web/-/web-1.2.0.tgz', dependencies: { qs: '^6', debug: '^2' } },
    'node_modules/cli': { version: '2.0.0', resolved: 'https://registry.npmjs.org/cli/-/cli-2.0.0.tgz', hasInstallScript: true, dependencies: { qs: '^6', debug: '^4' } },
    'node_modules/cli/node_modules/debug': { version: '4.3.4', resolved: 'https://registry.npmjs.org/debug/-/debug-4.3.4.tgz', dependencies: { ms: '2.1.2' } },
    'node_modules/debug': { version: '2.6.9', resolved: 'https://registry.npmjs.org/debug/-/debug-2.6.9.tgz', dependencies: { ms: '2.0.0' } },
    'node_modules/ms': { version: '2.0.0', resolved: 'https://registry.npmjs.org/ms/-/ms-2.0.0.tgz' },
    'node_modules/cli/node_modules/ms': { version: '2.1.2', resolved: 'https://registry.npmjs.org/ms/-/ms-2.1.2.tgz' },
    'node_modules/qs': { version: '6.11.0', resolved: 'https://registry.npmjs.org/qs/-/qs-6.11.0.tgz' },
    'node_modules/jest': { version: '29.7.0', dev: true, resolved: 'https://registry.npmjs.org/jest/-/jest-29.7.0.tgz' },
  },
};

test('resolvePath walks up node_modules like Node does', () => {
  assert.equal(resolvePath(lock.packages, 'node_modules/cli', 'debug'), 'node_modules/cli/node_modules/debug');
  assert.equal(resolvePath(lock.packages, 'node_modules/cli/node_modules/debug', 'ms'), 'node_modules/cli/node_modules/ms');
  assert.equal(resolvePath(lock.packages, 'node_modules/web', 'debug'), 'node_modules/debug');
  assert.equal(resolvePath(lock.packages, 'node_modules/web', 'missing'), null);
});

test('lockfile graph has one node per name@version and respects dev flags', () => {
  const g = buildLockGraph(lock);
  assert.deepEqual([...g.nodes.keys()].filter(k => k !== ROOT_ID).sort(), [
    'cli@2.0.0', 'debug@2.6.9', 'debug@4.3.4', 'ms@2.0.0', 'ms@2.1.2', 'qs@6.11.0', 'web@1.2.0',
  ]);
  assert.ok(g.get('cli@2.0.0').meta.installScripts.length);
  assert.ok(buildLockGraph(lock, { includeDev: true }).get('jest@29.7.0'));
});

test('lockfile v1 is converted and direct deps inferred', () => {
  const v1 = {
    name: 'old',
    lockfileVersion: 1,
    dependencies: {
      a: { version: '1.0.0', requires: { b: '^1' } },
      b: { version: '1.1.0' },
      c: { version: '3.0.0', dev: true },
    },
  };
  const g = buildLockGraph(v1);
  assert.deepEqual([...g.root.children], ['a@1.0.0']);
  assert.deepEqual([...g.get('a@1.0.0').children], ['b@1.1.0']);
});

test('blast-radius metrics', () => {
  const g = buildLockGraph(lock);
  g.get('qs@6.11.0').vulns = [{ id: 'GHSA-x', severity: 'high', aliases: [], summary: 'proto pollution' }];
  g.get('debug@2.6.9').meta.lastPublish = '2017-09-22T00:00:00Z';
  g.get('ms@2.0.0').meta.maintainers = ['solo'];
  analyze(g, NOW);

  const qs = g.get('qs@6.11.0');
  assert.deepEqual([...qs.reachedBy].sort(), ['cli@2.0.0', 'web@1.2.0']);
  assert.equal(qs.dependentsTotal, 2);
  assert.equal(qs.risk, 25);
  assert.equal(riskBand(qs.risk), 'medium');

  const web = g.directSummary.find(d => d.id === 'web@1.2.0');
  assert.equal(web.footprint, 3); // qs, debug@2, ms@2.0.0
  assert.equal(web.exclusive, 2); // debug@2 and ms@2.0.0; qs is shared with cli
  assert.equal(web.vulns.high, 1);

  assert.ok(g.get('debug@2.6.9').issues.some(i => i.kind === 'abandoned'));
  assert.ok(g.get('ms@2.0.0').issues.some(i => i.kind === 'single-maintainer'));
  assert.deepEqual(pathToRoot(g, 'ms@2.1.2').map(n => n.name), ['app', 'cli', 'debug', 'ms']);
  assert.equal(g.summary.packages, 7);
  assert.equal(g.summary.maxDepth, 3);
});

test('CVSS v3 base scores match the NVD calculator', () => {
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H'), 7.2);
  assert.equal(cvss3Score('CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1);
  assert.equal(cvss3Score('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N'), 0);
  assert.equal(cvss3Score('CVSS:4.0/AV:N'), null);
  assert.equal(severityFromScore(9.8), 'critical');
  assert.equal(severityFromScore(5), 'medium');
});

test('advisory summaries pick the nearest fixed version for this package', () => {
  const doc = {
    summary: 'Prototype pollution',
    aliases: ['CVE-2020-1'],
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    affected: [
      { package: { name: 'other' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '9.9.9' }] }] },
      { package: { name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }, { introduced: '5.0.0' }, { fixed: '5.0.1' }] }] },
    ],
  };
  const cmp = (a, b) => a.localeCompare(b, undefined, { numeric: true });
  const v = summarizeAdvisory(doc, 'GHSA-1', { name: 'lodash', version: '4.17.15' }, cmp);
  assert.equal(v.severity, 'critical');
  assert.equal(v.score, 9.8);
  assert.equal(v.fixedIn, '4.17.21');
  assert.equal(summarizeAdvisory(null, 'MAL-1', { name: 'x', version: '1' }, cmp).severity, 'unknown');
});

test('repository URL normalization', () => {
  assert.equal(repoUrl({ url: 'git+https://github.com/lodash/lodash.git' }), 'https://github.com/lodash/lodash');
  assert.equal(repoUrl('git@github.com:user/repo.git'), 'https://github.com/user/repo');
  assert.equal(repoUrl('github:user/repo'), 'https://github.com/user/repo');
  assert.equal(repoUrl('user/repo'), 'https://github.com/user/repo');
  assert.equal(repoUrl('javascript:alert(1)'), null);
});
