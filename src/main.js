import { detectInput } from './parse.js';
import { resolveNpm, enrichFromRegistry, semverCompare } from './resolve-npm.js';
import { buildLockGraph } from './resolve-lock.js';
import { resolvePypi } from './resolve-pypi.js';
import { clearPackuments } from './npm-registry.js';
import { attachVulns, attachNpmDownloads } from './enrich.js';
import { analyze, riskBand, pathToRoot, SEVERITIES } from './analyze.js';
import { compareVersions as pep440Compare } from './pep440.js';
import { GraphView } from './graph-view.js';
import { toMarkdown, toJSON } from './report.js';
import { EXAMPLES } from './examples.js';
import { esc, fmtNum, relTime, safeUrl, download } from './format.js';

const $ = sel => document.querySelector(sel);
const $$ = sel => [...document.querySelectorAll(sel)];

const state = {
  graph: null,
  source: '',
  filename: '',
  view: 'graph',
  selected: null,
  sort: { key: 'risk', dir: -1 },
  filter: null,
  search: '',
  running: false,
};

const FILTERS = [
  { key: 'vuln', label: 'Vulnerable', test: n => n.vulns.length > 0 },
  { key: 'deprecated', label: 'Deprecated', test: n => n.issues.some(i => i.kind === 'deprecated' || i.kind === 'yanked') },
  { key: 'install-script', label: 'Install scripts', test: n => n.issues.some(i => i.kind === 'install-script') },
  { key: 'single-maintainer', label: 'Single maintainer', test: n => n.issues.some(i => i.kind === 'single-maintainer') },
  { key: 'stale', label: 'Stale / abandoned', test: n => n.issues.some(i => i.kind === 'stale' || i.kind === 'abandoned') },
  { key: 'unresolved', label: 'Unresolved / external', test: n => n.issues.some(i => i.kind === 'unresolved' || i.kind === 'external') },
];

const graphView = new GraphView($('#graph'), { onSelect: id => select(id) });
window.blastRadius = { state, graphView }; // handy for poking at results from devtools

/* ---------- Theme ---------- */

// The graph draws its labels on a canvas, so it re-reads the font once the web fonts have loaded.
document.fonts?.ready.then(() => graphView.refreshColors());

/* ---------- Input ---------- */

function setInput(text, filename = '', source = '') {
  $('#manifest').value = text;
  state.filename = filename;
  state.source = source || filename || 'pasted input';
}

$('#manifest').addEventListener('input', () => { state.filename = ''; state.source = 'pasted input'; });

$$('[data-example]').forEach(btn => btn.addEventListener('click', () => {
  const ex = EXAMPLES[btn.dataset.example];
  setInput(ex.text, ex.filename, `example ${ex.filename}`);
  run();
}));

$('#file-input').addEventListener('change', async e => {
  const file = e.target.files[0];
  if (file) { setInput(await file.text(), file.name, file.name); run(); }
  e.target.value = '';
});

const dropZone = $('#input-panel');
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragging'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragging'));
dropZone.addEventListener('drop', async e => {
  e.preventDefault();
  dropZone.classList.remove('dragging');
  const file = e.dataTransfer.files[0];
  if (file) { setInput(await file.text(), file.name, file.name); run(); }
});

async function fetchFromGitHub(spec) {
  const m = /^(?:https?:\/\/github\.com\/)?([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:\/tree\/([^/]+)(?:\/(.+?))?)?\/?$/.exec(spec.trim());
  if (!m) throw new Error('Enter a repo as owner/repo or paste a github.com URL.');
  const [, owner, repo, ref = 'HEAD', dir = ''] = m;
  const base = `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${dir ? `${dir}/` : ''}`;
  for (const file of ['package-lock.json', 'package.json', 'requirements.txt', 'pyproject.toml']) {
    status(`Looking for ${file} in ${owner}/${repo}…`);
    const res = await fetch(base + file);
    if (res.ok) return { text: await res.text(), filename: file, label: `${owner}/${repo}${dir ? `/${dir}` : ''} · ${file}`, slug: `${owner}/${repo}${dir ? `/tree/${ref}/${dir}` : ''}` };
  }
  throw new Error(`No package-lock.json, package.json, requirements.txt or pyproject.toml at the root of ${owner}/${repo}.`);
}

async function runGitHub(spec) {
  if (state.running) return;
  $('#gh-input').value = spec;
  try {
    const found = await fetchFromGitHub(spec);
    setInput(found.text, found.filename, found.label);
    history.replaceState(null, '', `#gh=${encodeURIComponent(found.slug)}`);
    await run();
  } catch (err) {
    status(err.message, 'error');
  }
}

$('#gh-form').addEventListener('submit', e => { e.preventDefault(); runGitHub($('#gh-input').value); });
$$('[data-gh]').forEach(btn => btn.addEventListener('click', () => runGitHub(btn.dataset.gh)));
$('#analyze').addEventListener('click', () => run());

/* ---------- Pipeline ---------- */

function status(message, kind = '') {
  const el = $('#status');
  el.textContent = message;
  el.className = `status ${kind}`;
}

function logStep(message) {
  const li = document.createElement('li');
  li.textContent = message;
  $('#log').append(li);
}

function progress(p) {
  if (p.phase === 'resolve') status(`Resolving dependency tree… ${p.count} packages (${p.current})`);
  else if (p.phase === 'metadata') status(`Fetching registry metadata… ${p.done}/${p.total}`);
  else if (p.phase === 'osv') status(`Checking OSV.dev for known vulnerabilities… ${p.done}/${p.total}`);
  else if (p.phase === 'advisories') status(`Reading advisories… ${p.done}/${p.total}`);
  else if (p.phase === 'downloads') status('Fetching download counts…');
}

async function run() {
  if (state.running) return;
  state.running = true;
  $('#analyze').disabled = true;
  $('#analyze').textContent = 'Analyzing…';
  $('#log').textContent = '';
  document.body.classList.add('busy');
  const started = performance.now();

  try {
    const input = detectInput($('#manifest').value, state.filename);
    if (!state.source || state.source === 'pasted input') state.source = `pasted ${input.label}`;
    const includeDev = $('#opt-dev').checked;
    const maxNodes = Number($('#opt-max').value);
    logStep(`Detected ${input.label} (${input.ecosystem})`);
    if (input.skipped?.length) logStep(`Skipped ${input.skipped.length} line(s) that aren't index requirements`);

    let graph;
    let t = performance.now();
    if (input.kind === 'npm-manifest') {
      graph = await resolveNpm(input.data, { includeDev, maxNodes, onProgress: progress });
      logStep(`Resolved ${graph.size} packages from the npm registry (${secs(t)})`);
    } else if (input.kind === 'npm-lock') {
      graph = buildLockGraph(input.data, { includeDev, maxNodes });
      logStep(`Read ${graph.size} installed packages from the lockfile`);
      t = performance.now();
      await enrichFromRegistry(graph, { onProgress: progress });
      logStep(`Fetched registry metadata (${secs(t)})`);
    } else {
      graph = await resolvePypi(input.data, { rootName: input.name, maxNodes, onProgress: progress });
      logStep(`Resolved ${graph.size} packages from PyPI (${secs(t)})`);
    }
    clearPackuments();
    if (!graph.size) throw new Error('No dependencies to analyze. Is the dependency list empty, or are they all devDependencies?');

    t = performance.now();
    const advisories = await attachVulns(graph, { compare: graph.ecosystem === 'npm' ? semverCompare : pep440Compare, onProgress: progress });
    logStep(`Matched ${advisories} advisories from OSV.dev (${secs(t)})`);
    if (graph.ecosystem === 'npm') {
      await attachNpmDownloads(graph, { onProgress: progress });
      logStep('Fetched weekly download counts');
    }

    analyze(graph);
    state.graph = graph;
    state.selected = null;
    state.filter = null;
    state.search = '';
    $('#search').value = '';
    render();
    status(`Done in ${secs(started)}. ${graph.size} packages analyzed.`, 'ok');
    document.body.classList.add('has-results');
    if (matchMedia('(max-width: 760px)').matches) {
      // On phones the form would push results a full screen down; tuck it away.
      document.body.classList.add('input-collapsed');
      window.scrollTo({ top: 0 });
    }
  } catch (err) {
    console.error(err);
    status(err.message, 'error');
  } finally {
    state.running = false;
    $('#analyze').disabled = false;
    $('#analyze').textContent = 'Analyze dependencies';
    document.body.classList.remove('busy');
  }
}

const secs = since => `${((performance.now() - since) / 1000).toFixed(1)}s`;

/* ---------- Rendering ---------- */

function render() {
  const g = state.graph;
  $('#empty').hidden = true;
  $('#results').hidden = false;
  $('#export-md').disabled = false;
  $('#export-json').disabled = false;
  $('#project-title').textContent = g.root.name;
  $('#project-source').textContent = `${state.source} · ${g.ecosystem}`;
  renderSummary();
  renderWarnings();
  graphView.setData(g);
  renderDirect();
  renderFilters();
  renderTable();
  renderDetails();
  setView(state.view);
}

function renderSummary() {
  const s = state.graph.summary;
  const totalVulns = SEVERITIES.reduce((sum, k) => sum + s.vulns[k], 0);
  const sevBar = SEVERITIES.filter(k => s.vulns[k])
    .map(k => `<span class="sev-seg sev-${k}" style="flex:${s.vulns[k]}" title="${s.vulns[k]} ${k}"></span>`)
    .join('');
  const card = (value, label, sub = '', filter = null, tone = '') =>
    `<button class="stat ${tone}" ${filter ? `data-filter="${filter}"` : 'disabled'}>
      <span class="stat-value">${value}</span><span class="stat-label">${label}</span>${sub}
    </button>`;
  $('#summary').innerHTML = [
    card(s.packages, 'packages installed', `<span class="stat-sub">${s.direct} direct · ${s.transitive} transitive · ${s.maxDepth} deep</span>`),
    card(totalVulns, 'known vulnerabilities', `<span class="sev-bar">${sevBar}</span><span class="stat-sub">${SEVERITIES.filter(k => s.vulns[k]).map(k => `${s.vulns[k]} ${k}`).join(' · ') || 'none found'}</span>`, 'vuln', s.vulns.critical + s.vulns.high ? 'tone-bad' : ''),
    card(s.deprecated, 'deprecated or yanked', '', 'deprecated', s.deprecated ? 'tone-warn' : ''),
    card(s.installScripts, 'run code on install', '', 'install-script', s.installScripts ? 'tone-warn' : ''),
    card(s.singleMaintainer, 'single-maintainer', '', 'single-maintainer'),
    card(s.stale, 'stale or abandoned', '', 'stale'),
  ].join('');
}

function renderWarnings() {
  const g = state.graph;
  const notes = [...g.warnings];
  if (g.summary.malicious) notes.unshift(`${g.summary.malicious} package(s) match a known MALICIOUS release. Treat this install as compromised.`);
  $('#warnings').innerHTML = notes.map(w => `<li>${esc(w)}</li>`).join('');
  $('#warnings').hidden = !notes.length;
}

function setView(view) {
  state.view = view;
  $$('.tabs [data-view]').forEach(b => b.setAttribute('aria-selected', String(b.dataset.view === view)));
  $$('.view').forEach(v => { v.hidden = v.id !== `view-${view}`; });
  if (view === 'graph') graphView.resize();
}
$$('.tabs [data-view]').forEach(b => b.addEventListener('click', () => setView(b.dataset.view)));
$('#fit').addEventListener('click', () => graphView.fit());

const pkgButton = (n, text = n.name) => `<button class="pkg-link" data-id="${esc(n.id)}">${esc(text)}</button>`;
const riskPill = n => `<span class="risk-pill band-${riskBand(n.risk)}" title="Risk score (0–100)">${n.risk}</span>`;
const sevChips = counts =>
  SEVERITIES.filter(k => counts[k]).map(k => `<span class="sev-chip sev-${k}">${counts[k]} ${k}</span>`).join('') || '<span class="muted">no known vulns</span>';

function renderDirect() {
  const g = state.graph;
  const maxFoot = Math.max(1, ...g.directSummary.map(d => d.footprint));
  $('#direct-list').innerHTML = g.directSummary.map((d, i) => {
    const n = g.get(d.id);
    const extras = [
      d.deprecated && `${d.deprecated} deprecated`,
      d.installScripts && `${d.installScripts} install script${d.installScripts > 1 ? 's' : ''}`,
      d.abandoned && `${d.abandoned} stale`,
    ].filter(Boolean).join(' · ');
    return `<article class="dcard band-${riskBand(n.risk)}">
      <header>
        <span class="rank">${i + 1}</span>
        <div class="dname">${pkgButton(n)}<span class="ver">${esc(n.version)}</span></div>
        <div class="inherited" title="Sum of risk scores of this package and everything it pulls in"><b>${d.inheritedRisk}</b><span>inherited risk</span></div>
      </header>
      <div class="foot-bar" title="${d.footprint} transitive packages"><span style="width:${(d.footprint / maxFoot) * 100}%"></span><span class="excl" style="width:${(d.exclusive / maxFoot) * 100}%"></span></div>
      <dl class="dstats">
        <div><dt>Brings in</dt><dd>${d.footprint}</dd></div>
        <div><dt>Gone if dropped</dt><dd>${d.exclusive}</dd></div>
        <div><dt>Risky inside</dt><dd>${d.risky}</dd></div>
        <div><dt>Own risk</dt><dd>${riskPill(n)}</dd></div>
      </dl>
      <div class="sev-row">${sevChips(d.vulns)}</div>
      ${extras ? `<p class="dextras">${extras}</p>` : ''}
    </article>`;
  }).join('');
}

function renderFilters() {
  const g = state.graph;
  const pkgs = [...g.packages()];
  $('#filters').innerHTML = FILTERS.map(f => {
    const count = pkgs.filter(f.test).length;
    return `<button class="chip ${state.filter === f.key ? 'active' : ''}" data-chip="${f.key}" ${count ? '' : 'disabled'}>${f.label} <span>${count}</span></button>`;
  }).join('');
}

$('#filters').addEventListener('click', e => {
  const chip = e.target.closest('[data-chip]');
  if (!chip) return;
  state.filter = state.filter === chip.dataset.chip ? null : chip.dataset.chip;
  renderFilters();
  renderTable();
});
$('#summary').addEventListener('click', e => {
  const card = e.target.closest('[data-filter]');
  if (!card) return;
  state.filter = card.dataset.filter;
  renderFilters();
  renderTable();
  setView('table');
});
$('#search').addEventListener('input', e => { state.search = e.target.value.trim().toLowerCase(); renderTable(); });

const COLUMNS = [
  { key: 'name', label: 'Package', value: n => n.name.toLowerCase() },
  { key: 'risk', label: 'Risk', value: n => n.risk },
  { key: 'depth', label: 'Depth', value: n => n.depth },
  { key: 'issues', label: 'Issues', value: n => n.issues.length, sortable: false },
  { key: 'reach', label: 'Pulled in by', value: n => n.reachedBy.size },
  { key: 'footprint', label: 'Brings in', value: n => n.footprint },
  { key: 'lastPublish', label: 'Last release', value: n => n.meta.lastPublish || '' },
  { key: 'downloads', label: 'Weekly DLs', value: n => n.meta.weeklyDownloads ?? -1 },
];

function renderTable() {
  const g = state.graph;
  const filter = FILTERS.find(f => f.key === state.filter);
  const col = COLUMNS.find(c => c.key === state.sort.key);
  const rows = [...g.packages()]
    .filter(n => !filter || filter.test(n))
    .filter(n => !state.search || n.name.toLowerCase().includes(state.search))
    .sort((a, b) => {
      const va = col.value(a), vb = col.value(b);
      return (va < vb ? -1 : va > vb ? 1 : 0) * state.sort.dir || b.risk - a.risk;
    });
  const showDownloads = g.ecosystem === 'npm';

  const head = COLUMNS.filter(c => showDownloads || c.key !== 'downloads').map(c => {
    const active = state.sort.key === c.key;
    const aria = active ? `aria-sort="${state.sort.dir === 1 ? 'ascending' : 'descending'}"` : '';
    return c.sortable === false
      ? `<th>${c.label}</th>`
      : `<th ${aria}><button data-sort="${c.key}">${c.label}${active ? (state.sort.dir === 1 ? ' ↑' : ' ↓') : ''}</button></th>`;
  }).join('');

  const body = rows.slice(0, 1000).map(n => {
    const reachedBy = [...n.reachedBy].map(id => g.get(id).name);
    return `<tr class="${n.id === state.selected ? 'selected' : ''}" data-row="${esc(n.id)}">
      <td>${pkgButton(n)}<span class="ver">${esc(n.version)}</span></td>
      <td>${riskPill(n)}</td>
      <td>${n.depth}</td>
      <td class="issues">${n.issues.filter(i => i.level !== 'info').map(i => `<span class="issue lvl-${i.level}">${esc(i.label)}</span>`).join('')}</td>
      <td title="${esc(reachedBy.join(', '))}">${reachedBy.length === 1 && n.depth === 1 ? '<span class="muted">you</span>' : `${esc(reachedBy.slice(0, 2).join(', '))}${reachedBy.length > 2 ? ` +${reachedBy.length - 2}` : ''}`}</td>
      <td>${n.footprint}</td>
      <td>${relTime(n.meta.lastPublish)}</td>
      ${showDownloads ? `<td>${fmtNum(n.meta.weeklyDownloads)}</td>` : ''}
    </tr>`;
  }).join('');

  $('#pkg-table').innerHTML = `<thead><tr>${head}</tr></thead><tbody>${body || `<tr><td colspan="8" class="muted">No packages match.</td></tr>`}</tbody>`;
  $('#table-count').textContent = `${rows.length} of ${g.size} packages${rows.length > 1000 ? ' (showing first 1000)' : ''}`;
}

$('#pkg-table').addEventListener('click', e => {
  const sort = e.target.closest('[data-sort]');
  if (sort) {
    const key = sort.dataset.sort;
    state.sort = { key, dir: state.sort.key === key ? -state.sort.dir : key === 'name' ? 1 : -1 };
    renderTable();
    return;
  }
  const row = e.target.closest('[data-row]');
  if (row && !e.target.closest('.pkg-link')) select(row.dataset.row, { center: true });
});

/* ---------- Selection + details ---------- */

function select(id, { center = false } = {}) {
  state.selected = id;
  graphView.select(id, { center });
  renderDetails();
  $$('#pkg-table tr.selected').forEach(r => r.classList.remove('selected'));
  if (id) $(`#pkg-table tr[data-row="${CSS.escape(id)}"]`)?.classList.add('selected');
  if (id && matchMedia('(max-width: 1100px)').matches) $('#details').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

document.addEventListener('click', e => {
  const link = e.target.closest('.pkg-link[data-id]');
  if (link) select(link.dataset.id, { center: true });
});

function renderDetails() {
  const el = $('#details');
  const g = state.graph;
  const n = g && state.selected ? g.get(state.selected) : null;
  if (!g) return;
  if (!n || n.isRoot) { el.innerHTML = overviewDetails(g); return; }

  const m = n.meta;
  const path = pathToRoot(g, n.id);
  const reachedBy = [...n.reachedBy].map(id => g.get(id));
  const links = [
    safeUrl(m.registryUrl) && `<a href="${esc(m.registryUrl)}" target="_blank" rel="noopener">${g.ecosystem === 'npm' ? 'npm' : 'PyPI'}</a>`,
    safeUrl(m.repository) && `<a href="${esc(safeUrl(m.repository))}" target="_blank" rel="noopener">source</a>`,
    `<a href="https://osv.dev/list?ecosystem=${encodeURIComponent(g.ecosystem)}&q=${encodeURIComponent(n.name)}" target="_blank" rel="noopener">OSV</a>`,
  ].filter(Boolean).join('');

  const issues = n.issues.length
    ? n.issues.map(i => `<li class="lvl-${i.level}"><strong>${esc(i.label)}</strong>${i.kind !== 'vuln' && i.detail ? `<span>${esc(i.detail)}</span>` : ''}</li>`).join('')
    : '<li class="lvl-ok"><strong>No issues found</strong><span>No known vulnerabilities and nothing unusual in the registry metadata.</span></li>';

  const vulns = n.vulns.map(v => `<li>
      <div class="vhead"><span class="sev-chip sev-${v.severity}">${v.severity}${v.score != null ? ` ${v.score}` : ''}</span><a href="${esc(v.url)}" target="_blank" rel="noopener">${esc(v.id)}</a>${v.aliases.filter(a => a.startsWith('CVE')).slice(0, 1).map(a => `<span class="muted">${esc(a)}</span>`).join('')}</div>
      <p>${esc(v.summary)}</p>
      ${v.fixedIn ? `<p class="fix">Fixed in <code>${esc(v.fixedIn)}</code></p>` : '<p class="fix muted">No fixed version published</p>'}
    </li>`).join('');

  const chain = path.map((p, i) => `<li>${p.isRoot ? `<span class="muted">${esc(p.name)}</span>` : i === path.length - 1 ? `<strong>${esc(p.name)}</strong>` : pkgButton(p)}${p.isRoot ? '' : `<span class="ver">${esc(p.version)}</span>`}</li>`).join('');

  const listOf = ids => [...ids].map(id => g.get(id)).filter(x => !x.isRoot).sort((a, b) => b.risk - a.risk)
    .map(x => `<li>${pkgButton(x)}<span class="ver">${esc(x.version)}</span>${x.risk ? riskPill(x) : ''}</li>`).join('');

  const fact = (label, value) => `<div><dt>${label}</dt><dd>${value}</dd></div>`;

  el.innerHTML = `
    <div class="dhead">
      <div><h2>${esc(n.name)}</h2><span class="ver big">${esc(n.version)}</span></div>
      <div class="risk-big band-${riskBand(n.risk)}"><b>${n.risk}</b><span>risk</span></div>
    </div>
    ${m.description ? `<p class="desc">${esc(m.description)}</p>` : ''}
    <div class="links">${links}<button class="ghost small" data-clear>Clear</button></div>

    <section><h3>Findings</h3><ul class="issue-list">${issues}</ul></section>
    ${vulns ? `<section><h3>Vulnerabilities</h3><ul class="vuln-list">${vulns}</ul></section>` : ''}

    <section>
      <h3>Blast radius</h3>
      <dl class="facts">
        ${fact('Pulled in by', `${reachedBy.length} of ${g.summary.direct} direct deps`)}
        ${fact('Depended on by', `${n.dependentsTotal} packages`)}
        ${fact('Brings in', `${n.footprint} packages`)}
        ${fact('Depth', n.depth)}
      </dl>
      <p class="hint">${blastSentence(n, reachedBy)}</p>
    </section>

    <section><h3>Why is this installed?</h3><ol class="chain">${chain}</ol>
      ${reachedBy.length > 1 ? `<p class="hint">Also reached through: ${reachedBy.filter(r => r.id !== path[1]?.id).slice(0, 8).map(r => pkgButton(r)).join(', ')}</p>` : ''}
    </section>

    <section><h3>Package health</h3>
      <dl class="facts">
        ${fact('This version', relTime(m.publishedAt))}
        ${fact('Latest release', relTime(m.lastPublish))}
        ${fact('Latest version', esc(m.latest || '–'))}
        ${fact('Maintainers', m.maintainers ? `${m.maintainers.length}${m.organization ? ` · org ${esc(m.organization)}` : ''}` : '–')}
        ${g.ecosystem === 'npm' ? fact('Weekly downloads', fmtNum(m.weeklyDownloads)) : fact('Requires Python', esc(m.requiresPython || '–'))}
        ${fact('License', esc(m.license || '–'))}
      </dl>
      ${m.maintainers?.length ? `<p class="hint">Publishers: ${m.maintainers.slice(0, 12).map(esc).join(', ')}${m.maintainers.length > 12 ? '…' : ''}</p>` : ''}
      ${m.installScripts?.length ? `<pre class="scripts">${m.installScripts.map(s => `${esc(s.hook)}: ${esc(s.cmd)}`).join('\n')}</pre>` : ''}
    </section>

    ${n.children.size ? `<section><h3>Depends on (${n.children.size})</h3><ul class="mini-list">${listOf(n.children)}</ul></section>` : ''}
    ${[...n.parents].some(id => !g.get(id).isRoot) ? `<section><h3>Required by (${[...n.parents].filter(id => !g.get(id).isRoot).length})</h3><ul class="mini-list">${listOf(n.parents)}</ul></section>` : ''}
  `;
}

function blastSentence(n, reachedBy) {
  if (n.depth === 1 && reachedBy.length === 1) {
    const d = state.graph.directSummary.find(x => x.id === n.id);
    return `You depend on this directly. Dropping it would remove it plus <b>${d?.exclusive ?? 0}</b> other package(s) from your install.`;
  }
  if (reachedBy.length === 1) return `Only ${pkgButton(reachedBy[0])} pulls this in. Replacing or upgrading that one dependency removes it.`;
  return `${reachedBy.length} of your direct dependencies pull this in, so getting rid of it would mean replacing all of them, or overriding the version.`;
}

function overviewDetails(g) {
  const top = [...g.packages()].filter(n => n.risk > 0).sort((a, b) => b.risk - a.risk).slice(0, 8);
  return `
    <div class="dhead"><div><h2>Riskiest packages</h2><span class="muted">Click any one, or any node on the radar.</span></div></div>
    <ul class="top-list">${top.map(n => `<li>${riskPill(n)}<div>${pkgButton(n)}<span class="ver">${esc(n.version)}</span><small>${esc(n.issues.slice(0, 2).map(i => i.label).join(' · '))}</small></div></li>`).join('') || '<li class="muted">Nothing risky found. Nice.</li>'}</ul>
    <section><h3>How risk is scored</h3>
      <p class="hint">Each package earns points for known vulnerabilities (by severity), deprecation, install scripts, a single publisher, no releases in 2+ years, and low adoption, capped at 100. <b>Inherited risk</b> adds up a direct dependency's whole subtree.</p>
    </section>`;
}

$('#details').addEventListener('click', e => { if (e.target.closest('[data-clear]')) select(null); });

/* ---------- Exports & sharing ---------- */

const slug = () => state.graph.root.name.replace(/[^\w.-]+/g, '-');
$('#export-md').addEventListener('click', () => download(`${slug()}-blast-radius.md`, toMarkdown(state.graph, state.source), 'text/markdown'));
$('#export-json').addEventListener('click', () => download(`${slug()}-blast-radius.json`, toJSON(state.graph, state.source), 'application/json'));
$('#toggle-input').addEventListener('click', () => document.body.classList.toggle('input-collapsed'));

/* ---------- Boot ---------- */

// Shareable links: #gh=owner/repo or #example=npm|pypi
function loadFromHash() {
  const hash = new URLSearchParams(location.hash.slice(1));
  const gh = hash.get('gh');
  const ex = EXAMPLES[hash.get('example')];
  if (gh && gh !== $('#gh-input').value) runGitHub(gh);
  else if (ex) {
    setInput(ex.text, ex.filename, `example ${ex.filename}`);
    run();
  }
}
window.addEventListener('hashchange', loadFromHash);
loadFromHash();
