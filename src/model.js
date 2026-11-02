// The dependency graph every resolver produces and every other module consumes.
// Nodes are keyed by `name@version`, so two versions of the same package are two nodes.

export const ROOT_ID = '<root>';

export class DepGraph {
  constructor(ecosystem, rootName) {
    this.ecosystem = ecosystem; // 'npm' | 'PyPI' (OSV ecosystem names)
    this.nodes = new Map();
    this.warnings = [];
    this.truncated = false;
    this.root = this.addNode({ id: ROOT_ID, name: rootName || 'your-project', isRoot: true });
  }

  addNode(fields) {
    const node = {
      version: '',
      isRoot: false,
      meta: {},
      vulns: [],
      issues: [],
      risk: 0,
      parents: new Set(),
      children: new Set(),
      edges: new Map(), // childId -> { range, kind }
      ...fields,
    };
    this.nodes.set(node.id, node);
    return node;
  }

  get(id) {
    return this.nodes.get(id);
  }

  addEdge(fromId, toId, info = {}) {
    const from = this.nodes.get(fromId);
    const to = this.nodes.get(toId);
    if (!from || !to || fromId === toId) return;
    from.children.add(toId);
    to.parents.add(fromId);
    if (!from.edges.has(toId)) from.edges.set(toId, info);
  }

  *packages() {
    for (const node of this.nodes.values()) if (!node.isRoot) yield node;
  }

  get size() {
    return this.nodes.size - 1;
  }
}

/** BFS over children or parents; returns the set of reachable ids including `startId`. */
export function reach(graph, startId, direction = 'children') {
  const seen = new Set([startId]);
  const queue = [startId];
  while (queue.length) {
    for (const next of graph.get(queue.pop())[direction]) {
      if (!seen.has(next)) { seen.add(next); queue.push(next); }
    }
  }
  return seen;
}
