// Canvas "radar" view: the project sits at the center, each ring is one level of
// dependency depth, node size is footprint and color is risk.

import * as d3 from 'd3';
import { riskBand } from './analyze.js';
import { reach } from './model.js';

// The first ring gets extra room because direct dependencies are always labelled.
const ringRadius = depth => (depth <= 0 ? 0 : 130 + (depth - 1) * 70);

export class GraphView {
  constructor(container, { onSelect } = {}) {
    this.container = container;
    this.onSelect = onSelect;
    this.canvas = document.createElement('canvas');
    this.canvas.setAttribute('role', 'img');
    this.canvas.setAttribute('aria-label', 'Dependency graph. Use the Direct deps or All packages tabs for an accessible list.');
    this.ctx = this.canvas.getContext('2d');
    this.tooltip = document.createElement('div');
    this.tooltip.className = 'graph-tooltip';
    this.tooltip.hidden = true;
    container.append(this.canvas, this.tooltip);

    this.transform = d3.zoomIdentity;
    this.nodes = [];
    this.links = [];
    this.selected = null;
    this.hovered = null;
    this.highlight = null;

    this.zoom = d3.zoom().scaleExtent([0.04, 10]).on('zoom', e => {
      this.transform = e.transform;
      if (e.sourceEvent) this.userMoved = true;
      this.draw();
    });
    const canvas = d3.select(this.canvas);
    canvas
      .call(
        d3.drag()
          .container(this.canvas)
          .subject(e => this.nodeAt(e.x, e.y))
          .on('start', e => {
            if (!e.active) this.sim.alphaTarget(0.15).restart();
            e.subject.fx = e.subject.x;
            e.subject.fy = e.subject.y;
          })
          .on('drag', e => {
            const [x, y] = this.transform.invert(d3.pointer(e.sourceEvent, this.canvas));
            e.subject.fx = x;
            e.subject.fy = y;
          })
          .on('end', e => {
            if (!e.active) this.sim.alphaTarget(0);
            if (!e.subject.ref.isRoot) { e.subject.fx = null; e.subject.fy = null; }
          }),
      )
      .call(this.zoom)
      .on('dblclick.zoom', null)
      .on('click', e => {
        const [px, py] = d3.pointer(e, this.canvas);
        this.onSelect?.(this.nodeAt(px, py)?.id ?? null);
      })
      .on('mousemove', e => this.hover(e))
      .on('mouseleave', () => { this.hovered = null; this.tooltip.hidden = true; this.draw(); });

    new ResizeObserver(() => this.resize()).observe(container);
    matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => this.refreshColors());
    this.refreshColors();
  }

  refreshColors() {
    const s = getComputedStyle(this.container);
    const v = name => s.getPropertyValue(name).trim();
    this.colors = {
      bg: v('--bg'),
      text: v('--text'),
      muted: v('--muted'),
      ring: v('--ring'),
      edge: v('--edge'),
      edgeHl: v('--accent'),
      root: v('--accent'),
      direct: v('--text'),
      risk: { none: v('--risk-none'), low: v('--risk-low'), medium: v('--risk-medium'), high: v('--risk-high'), critical: v('--risk-critical') },
    };
    this.font = s.fontFamily;
    this.draw();
  }

  resize() {
    const { clientWidth: w, clientHeight: h } = this.container;
    if (!w || !h) return;
    const dpr = window.devicePixelRatio || 1;
    this.w = w;
    this.h = h;
    this.canvas.width = Math.round(w * dpr);
    this.canvas.height = Math.round(h * dpr);
    this.canvas.style.width = `${w}px`;
    this.canvas.style.height = `${h}px`;
    if (!this.fitted && this.nodes.length) this.fit(false);
    this.draw();
  }

  setData(graph) {
    this.graph = graph;
    this.sim?.stop();
    this.selected = null;
    this.highlight = null;
    const finite = [...graph.nodes.values()].map(n => n.depth).filter(Number.isFinite);
    this.maxDepth = Math.max(1, ...finite);

    const direct = [...graph.root.children];
    const angle = new Map(direct.map((id, i) => [id, (i / direct.length) * Math.PI * 2]));
    this.nodes = [...graph.nodes.values()].map(ref => {
      const depth = Number.isFinite(ref.depth) ? ref.depth : this.maxDepth + 1;
      // Seed each node near the direct dependency that pulls it in, so subtrees form wedges.
      const group = [...(ref.reachedBy || [])][0];
      const a = (angle.get(group) ?? Math.random() * Math.PI * 2) + (Math.random() - 0.5) * 0.5;
      return {
        id: ref.id,
        ref,
        depth,
        r: ref.isRoot ? 13 : Math.min(3.5 + Math.sqrt(ref.footprint || 0) * 1.5, 20),
        x: Math.cos(a) * ringRadius(depth),
        y: Math.sin(a) * ringRadius(depth),
      };
    });
    const byId = new Map(this.nodes.map(n => [n.id, n]));
    const rootNode = byId.get(graph.root.id);
    rootNode.fx = 0;
    rootNode.fy = 0;
    this.links = [];
    for (const n of graph.nodes.values()) for (const c of n.children) this.links.push({ source: byId.get(n.id), target: byId.get(c) });
    // Draw low-risk nodes first so the dangerous ones sit on top.
    this.order = [...this.nodes].sort((a, b) => (a.ref.risk || 0) - (b.ref.risk || 0));
    this.byId = byId;

    const big = this.nodes.length > 800;
    this.sim = d3.forceSimulation(this.nodes)
      .force('link', d3.forceLink(this.links).distance(50).strength(0.08))
      .force('charge', d3.forceManyBody().strength(big ? -14 : -28).distanceMax(220).theta(0.95))
      .force('collide', d3.forceCollide(d => d.r + 1.5).iterations(1))
      .force('radial', d3.forceRadial(d => ringRadius(d.depth), 0, 0).strength(0.9))
      .alphaDecay(big ? 0.05 : 0.03)
      .on('tick', () => this.draw())
      .on('end', () => { if (!this.userMoved) this.fit(); });

    this.userMoved = false;
    this.fitted = false;
    this.fit(false);
  }

  /** Zooms so every node is visible, centered on the project root. */
  fit(animate = true) {
    if (!this.w) return;
    let extent = ringRadius(1);
    for (const n of this.nodes) extent = Math.max(extent, Math.hypot(n.x, n.y) + n.r);
    const k = Math.min(this.w, this.h) / (2 * (extent + 24));
    const t = d3.zoomIdentity.translate(this.w / 2, this.h / 2).scale(k);
    const canvas = d3.select(this.canvas);
    (animate ? canvas.transition().duration(600) : canvas).call(this.zoom.transform, t);
    this.fitted = true;
  }

  select(id, { center = false } = {}) {
    this.selected = id;
    if (id && this.graph?.get(id)) {
      this.ancestors = reach(this.graph, id, 'parents');
      this.descendants = reach(this.graph, id, 'children');
      this.highlight = new Set([...this.ancestors, ...this.descendants]);
      if (center) {
        const n = this.byId.get(id);
        if (n) d3.select(this.canvas).transition().duration(600).call(this.zoom.translateTo, n.x, n.y);
      }
    } else {
      this.highlight = this.ancestors = this.descendants = null;
    }
    this.draw();
  }

  nodeAt(px, py) {
    const [x, y] = this.transform.invert([px, py]);
    const slack = 4 / this.transform.k;
    let best = null;
    let bestDist = Infinity;
    for (const n of this.nodes) {
      const d = (n.x - x) ** 2 + (n.y - y) ** 2;
      if (d < (n.r + slack) ** 2 && d < bestDist) { best = n; bestDist = d; }
    }
    return best;
  }

  hover(e) {
    const [px, py] = d3.pointer(e, this.canvas);
    const n = this.nodeAt(px, py);
    this.canvas.style.cursor = n ? 'pointer' : 'grab';
    if (n?.id === this.hovered) {
      if (n) this.placeTooltip(px, py);
      return;
    }
    this.hovered = n?.id ?? null;
    if (n) {
      const ref = n.ref;
      const issues = ref.issues?.length ? ref.issues.slice(0, 3).map(i => i.label).join(' · ') : ref.isRoot ? 'Your project' : 'No issues found';
      this.tooltip.textContent = '';
      const title = document.createElement('strong');
      title.textContent = ref.isRoot ? ref.name : `${ref.name}@${ref.version}`;
      const sub = document.createElement('span');
      sub.textContent = ref.isRoot ? `${this.graph.size} packages` : `risk ${ref.risk} · depth ${ref.depth} · ${issues}`;
      this.tooltip.append(title, sub);
      this.tooltip.hidden = false;
      this.placeTooltip(px, py);
    } else {
      this.tooltip.hidden = true;
    }
    this.draw();
  }

  placeTooltip(px, py) {
    const flip = px > this.w - 240;
    this.tooltip.style.transform = `translate(${flip ? px - 14 : px + 14}px, ${py + 14}px) translateX(${flip ? '-100%' : '0'})`;
  }

  draw() {
    if (!this.w || !this.colors || !this.nodes.length) return;
    const { ctx, transform: t, colors: c } = this;
    const dpr = window.devicePixelRatio || 1;
    const k = t.k;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, this.w, this.h);
    ctx.save();
    ctx.translate(t.x, t.y);
    ctx.scale(k, k);

    // Depth rings
    ctx.lineWidth = 1 / k;
    ctx.strokeStyle = c.ring;
    ctx.setLineDash([3 / k, 5 / k]);
    for (let d = 1; d <= this.maxDepth; d++) {
      ctx.beginPath();
      ctx.arc(0, 0, ringRadius(d), 0, Math.PI * 2);
      ctx.stroke();
    }
    ctx.setLineDash([]);
    ctx.fillStyle = c.muted;
    ctx.font = `${10 / k}px ${this.font}`;
    ctx.textAlign = 'left';
    for (let d = 1; d <= this.maxDepth; d++) ctx.fillText(d === 1 ? 'direct' : `depth ${d}`, 5 / k, -ringRadius(d) - 5 / k);

    const hl = this.highlight;
    const onPath = l =>
      hl && ((this.ancestors.has(l.source.id) && this.ancestors.has(l.target.id)) || (this.descendants.has(l.source.id) && this.descendants.has(l.target.id)));

    // Edges
    ctx.globalAlpha = hl ? 0.12 : 0.45;
    ctx.strokeStyle = c.edge;
    ctx.lineWidth = 0.7 / k;
    ctx.beginPath();
    for (const l of this.links) {
      if (onPath(l)) continue;
      ctx.moveTo(l.source.x, l.source.y);
      ctx.lineTo(l.target.x, l.target.y);
    }
    ctx.stroke();
    if (hl) {
      ctx.globalAlpha = 0.9;
      ctx.strokeStyle = c.edgeHl;
      ctx.lineWidth = 1.4 / k;
      ctx.beginPath();
      for (const l of this.links) {
        if (!onPath(l)) continue;
        ctx.moveTo(l.source.x, l.source.y);
        ctx.lineTo(l.target.x, l.target.y);
      }
      ctx.stroke();
    }

    // Nodes
    for (const n of this.order) {
      const faded = hl && !hl.has(n.id);
      ctx.globalAlpha = faded ? 0.15 : 1;
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fillStyle = n.ref.isRoot ? c.root : c.risk[riskBand(n.ref.risk)];
      ctx.fill();
      if (n.depth === 1) {
        ctx.lineWidth = 1.5 / k;
        ctx.strokeStyle = c.direct;
        ctx.stroke();
      }
      if (n.id === this.selected || n.id === this.hovered) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r + 4 / k, 0, Math.PI * 2);
        ctx.lineWidth = 2 / k;
        ctx.strokeStyle = c.edgeHl;
        ctx.stroke();
      }
    }

    // Labels: always for the important nodes, everything once zoomed in.
    ctx.globalAlpha = 1;
    ctx.font = `${11 / k}px ${this.font}`;
    ctx.textAlign = 'center';
    ctx.lineJoin = 'round';
    const [x0, y0] = t.invert([0, 0]);
    const [x1, y1] = t.invert([this.w, this.h]);
    const smallHl = hl && hl.size <= 40;
    for (const n of this.order) {
      if (n.x < x0 || n.x > x1 || n.y < y0 || n.y > y1) continue;
      if (hl && !hl.has(n.id)) continue;
      // Reveal labels progressively: direct deps, then critical, then high risk, then all.
      const always = n.ref.isRoot || n.depth === 1 || n.id === this.selected || n.id === this.hovered;
      const minRisk = k < 0.5 ? Infinity : k < 0.9 ? 60 : k < 1.6 ? 35 : 0;
      if (!always && !smallHl && n.ref.risk < minRisk) continue;
      const label = n.ref.name;
      const y = n.y + n.r + 12 / k;
      ctx.lineWidth = 3.5 / k;
      ctx.strokeStyle = c.bg;
      ctx.strokeText(label, n.x, y);
      ctx.fillStyle = n.id === this.selected ? c.edgeHl : c.text;
      ctx.fillText(label, n.x, y);
    }
    ctx.restore();
  }
}
