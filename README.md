<div align="center">

# Blast Radius

**See everything your dependencies drag in: which packages are dangerous, how deep they're buried, and which of your choices pulled them in.**

![runs in: the browser](https://img.shields.io/badge/runs%20in-the%20browser-blue)
![build step: none](https://img.shields.io/badge/build%20step-none-brightgreen)
![ecosystems: npm, PyPI](https://img.shields.io/badge/ecosystems-npm%20%C2%B7%20PyPI-blueviolet)
![license: MIT](https://img.shields.io/badge/license-MIT-lightgrey)

<img src="docs/screenshot.jpg" alt="The radar view: every installed package on a ring by depth, coloured by risk" width="820">

</div>

---

## Table of contents

1. [The problem](#the-problem)
2. [What Blast Radius does](#what-blast-radius-does)
3. [Quick start](#quick-start)
4. [Demo: two legacy apps, two kinds of problem](#demo-two-legacy-apps-two-kinds-of-problem)
5. [Metrics specification](#metrics-specification)
6. [Risk score specification](#risk-score-specification)
7. [Architecture](#architecture)
8. [Key design decisions](#key-design-decisions)
9. [Testing and CI](#testing-and-ci)
10. [Limitations and roadmap](#limitations-and-roadmap)

---

## The problem

A typical app lists a dozen dependencies and installs hundreds. `npm audit` and `pip-audit` tell you which of those hundreds have a known CVE, but not the questions that decide what to do about it:

- Is anything dangerous that *isn't* a CVE yet: malware, deprecated or yanked releases, install scripts, a single maintainer, code nobody has touched in years?
- **Why** is this package even installed? Which of *my* direct dependencies pulls it in?
- What does each direct dependency really cost me, and what would disappear if I dropped it?

## What Blast Radius does

A browser app that resolves the **entire transitive dependency tree** of an npm or Python project and answers those three questions:

1. **Which packages are actually dangerous?** Known CVEs from OSV.dev with the version that fixes each one, known-malicious releases, deprecated or yanked packages, install scripts, single-maintainer packages and abandoned code.
2. **Why is it installed?** The shortest chain from your project to any package, and which direct dependencies can reach it.
3. **What does each dependency cost?** Total footprint, inherited risk, and how many packages would leave your tree if you removed it.

Everything runs client-side. There is no backend and there are no API keys; the only requests go to public APIs (npm registry, PyPI, OSV.dev, GitHub).

## Quick start

```bash
npm start            # serves the app at http://localhost:8080
```

Then either:

- click **legacy Node app** or **legacy Python app** for a pre-loaded demo,
- type a GitHub repo (`expressjs/express`, or a `github.com/.../tree/main/packages/x` URL), or
- paste, upload or drag in a `package.json`, `package-lock.json`, `requirements.txt` or `pyproject.toml`.

Links are shareable: `#gh=owner/repo` and `#example=npm` load automatically.

> Any static file server works (`python -m http.server`). The page uses ES modules, so it can't be opened from `file://`. It deploys to GitHub Pages as-is.

## Demo: two legacy apps, two kinds of problem

### 1. `legacy-node-app`: a supply-chain attack hiding in plain sight

The bundled Node demo pins ten once-popular packages. Blast Radius resolves them to **269 installed packages, 8 levels deep**, and surfaces:

- `event-stream@3.3.6`: the 2018 [flatmap-stream supply-chain attack](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident). npm unpublished it, so a plain resolver just fails. Blast Radius still checks the exact pin against OSV and flags it as **known malicious**.
- `node-sass` alone brings in **196 packages**, and **149 of them** exist only because of it. It's deprecated and runs a native build on install.
- 86 advisories (4 critical), each with the version that fixes it.

### 2. `legacy-python-app`: a tree that can't install

`requests==2.19.0` requires `urllib3<1.24`, but `urllib3==1.24.1` is pinned. Blast Radius reports the conflict the same way pip would refuse it.

## Metrics specification

| Metric | Definition |
| --- | --- |
| **Footprint** | The number of packages a node pulls in transitively. |
| **Pulled in by** | Which of your direct dependencies can reach this package: what you'd have to replace to get rid of it. |
| **Gone if dropped** | Packages reachable from exactly one direct dependency, so removing that dependency removes them. |
| **Inherited risk** | The sum of risk scores over a direct dependency's whole subtree. This ranks the Direct deps view. |

## Risk score specification

Each package gets a score from 0 to 100:

| Signal | Points |
| --- | --- |
| Known vulnerability | critical 35 · high 25 · medium 12 · low 4 (capped at 60) |
| Known malicious release | +40 |
| Could not resolve / unpublished | 20 |
| Deprecated or yanked | 15 |
| No release in 4+ years / 2+ years | 14 / 8 |
| Install scripts (`preinstall`, `install`, `postinstall`, node-gyp) | 12 |
| Installed from git/URL (invisible to audits) | 10 |
| Single maintainer (no org) | 8 |
| Under 1,000 weekly downloads (npm) | 6 |
| Major version behind | 3 |

The weights are opinionated, and they live in one function (`scoreNode`) so they're easy to change.

## Architecture

```
manifest ──► detect format ──► resolve full graph ──► enrich ──► analyze ──► radar / tables / report
                               (npm · lockfile · PyPI)  (OSV, downloads)  (risk + blast radius)
```

| Stage | Module | Notes |
| --- | --- | --- |
| Parsing | [`parse.js`](src/parse.js) | package.json, lockfiles, requirements.txt (options, hashes and continuation lines), pyproject `[project]` (a string scanner, since a regex trips on `pkg[extra]`). |
| npm resolution | [`resolve-npm.js`](src/resolve-npm.js) | Concurrent BFS over the registry. It mirrors npm's version choice (prefers `latest` when it satisfies the range) and handles aliases (`npm:`), git/URL/file sources and auto-installed peer deps. |
| Lockfiles | [`resolve-lock.js`](src/resolve-lock.js) | Reproduces Node's module resolution (`node_modules` walk-up) over the lockfile layout to get the exact installed graph. Supports v1, v2 and v3, links and dev flags. |
| PyPI resolution | [`resolve-pypi.js`](src/resolve-pypi.js) | One version per package, with top-level pins winning. Supports extras, including extras requested later that switch on more dependencies of an already-resolved node. Reports conflicts. |
| PEP 440 | [`pep440.js`](src/pep440.js) | From scratch: version parsing, total ordering (`1.0.dev0 < 1.0a1 < 1.0 < 1.0.post1`), `~=`, `==1.*`, and the exclusive-ordered-comparison rules for pre and post releases. |
| PEP 508 markers | [`markers.js`](src/markers.js) | Tokenizer and recursive-descent parser for `python_version < "3.8" and (extra == 'socks' or ...)`, evaluated against a CPython 3.12 / Linux target. |
| Vulnerabilities | [`enrich.js`](src/enrich.js) | Batched OSV.dev queries, deduplicating aliases (PYSEC-* and GHSA-* for the same bug). Picks the nearest fixed version above the installed one. Detects malware via OSV `MAL-*` IDs and CWE-506. |
| CVSS | [`cvss.js`](src/cvss.js) | CVSS v3.x base-score calculator from the spec, used when an advisory has a vector but no severity label. |
| Analysis | [`analyze.js`](src/analyze.js) | Risk scoring and the graph metrics above. |
| Radar | [`graph-view.js`](src/graph-view.js) | Canvas plus d3-force with a radial force per depth ring. Zoom, pan and drag, with ancestor/descendant path highlighting. Labels appear progressively by zoom level and risk. |

**Tech:** vanilla JS (ES modules), with [d3](https://d3js.org) for forces and zoom and [semver](https://github.com/npm/node-semver) for npm ranges, both loaded through an import map. No build step. The look is shared with [blazexyz.com](https://blazexyz.com) through `bz-theme.css`.

## Key design decisions

### 1. Resolve the graph, don't just read the manifest

A manifest names what you chose; the risk lives in what those choices install. Every metric (footprint, "gone if dropped", inherited risk) needs the full graph, so resolution is the core of the tool, not a side feature.

### 2. Prefer the lockfile when there is one

npm's own algorithm (hoisting, `overrides`) is hard to reproduce exactly. A `package-lock.json` already records the installed tree, so Blast Radius walks it with Node's `node_modules` lookup rules instead of guessing.

### 3. Check exact pins even when they no longer resolve

Unpublished packages are often unpublished *because* they were malicious. A resolver that gives up on a 404 would hide `event-stream@3.3.6`; querying OSV with the exact pin catches it.

### 4. Write the version logic from scratch

PEP 440 ordering, PEP 508 markers and the CVSS calculator are small, well-specified and easy to get subtly wrong. Implementing them against the specs keeps the app dependency-light and makes the edge cases testable.

### 5. No backend

Everything a backend would do here is a public API call. Keeping it in the browser means nothing to host, no keys to leak and nothing to trust but the page itself.

## Testing and CI

```bash
npm test
```

15 tests on `node:test`, with no dependencies. They cover PEP 440 ordering and specifiers, marker evaluation, every manifest format, lockfile path resolution (including v1 conversion), blast-radius metrics on a hand-built graph, the CVSS calculator against NVD reference scores, advisory fix-version selection and repository-URL normalization.

## Limitations and roadmap

**Known limitations:**

- npm resolution approximates npm's algorithm: it doesn't model hoisting or `overrides`. For exact results, use a `package-lock.json`.
- Python resolution is greedy (first choice wins) rather than backtracking like pip's resolver, and the target environment is fixed.
- Not yet supported: `yarn.lock`, `pnpm-lock.yaml`, Poetry and uv lockfiles, other ecosystems (OSV also covers crates.io, Go and Maven).

**Roadmap:**

- Diff two manifests: "what does this upgrade change?"
- A CI mode that fails on new critical findings.
- OpenSSF Scorecard data per repo.

---

<div align="center">

MIT License · Built by <b>BlazeXYZ</b> · Part of <a href="https://blazexyz.com">blazexyz.com</a>

</div>
