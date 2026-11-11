/** Small, dependency-free Isolation Forest (Liu et al., 2008). */

export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

type Leaf = { size: number };
type Split = { f: number; s: number; l: TreeNode; r: TreeNode };
type TreeNode = Leaf | Split;

const EULER = 0.5772156649;

/** Average path length of an unsuccessful BST search over n points. */
export function averagePathLength(n: number): number {
  if (n <= 1) return 0;
  if (n === 2) return 1;
  return 2 * (Math.log(n - 1) + EULER) - (2 * (n - 1)) / n;
}

export interface IsolationForestOptions {
  nTrees?: number;
  sampleSize?: number;
  seed?: number;
}

export class IsolationForest {
  private trees: TreeNode[] = [];
  private psi = 0;
  private readonly nTrees: number;
  private readonly sampleSize: number;
  private readonly seed: number;

  constructor(opts: IsolationForestOptions = {}) {
    this.nTrees = opts.nTrees ?? 150;
    this.sampleSize = opts.sampleSize ?? 256;
    this.seed = opts.seed ?? 42;
  }

  fit(X: number[][]): this {
    const rng = mulberry32(this.seed);
    const n = X.length;
    this.psi = Math.min(this.sampleSize, n);
    const maxDepth = Math.ceil(Math.log2(Math.max(this.psi, 2)));
    const idx = X.map((_, i) => i);
    this.trees = [];
    for (let t = 0; t < this.nTrees; t++) {
      // partial Fisher-Yates: first psi entries become the sample
      for (let i = 0; i < this.psi; i++) {
        const j = i + Math.floor(rng() * (n - i));
        const tmp = idx[i]!;
        idx[i] = idx[j]!;
        idx[j] = tmp;
      }
      const sample = idx.slice(0, this.psi).map((i) => X[i]!);
      this.trees.push(this.build(sample, 0, maxDepth, rng));
    }
    return this;
  }

  private build(rows: number[][], depth: number, maxDepth: number, rng: () => number): TreeNode {
    if (depth >= maxDepth || rows.length <= 1) return { size: rows.length };
    const dims = rows[0]!.length;
    const candidates: { f: number; min: number; max: number }[] = [];
    for (let f = 0; f < dims; f++) {
      let min = Infinity;
      let max = -Infinity;
      for (const r of rows) {
        const v = r[f]!;
        if (v < min) min = v;
        if (v > max) max = v;
      }
      if (max > min) candidates.push({ f, min, max });
    }
    if (candidates.length === 0) return { size: rows.length };
    const c = candidates[Math.floor(rng() * candidates.length)]!;
    const s = c.min + rng() * (c.max - c.min);
    const left: number[][] = [];
    const right: number[][] = [];
    for (const r of rows) (r[c.f]! < s ? left : right).push(r);
    return {
      f: c.f,
      s,
      l: this.build(left, depth + 1, maxDepth, rng),
      r: this.build(right, depth + 1, maxDepth, rng),
    };
  }

  private pathLength(x: number[], node: TreeNode, depth: number): number {
    if ("size" in node) return depth + averagePathLength(node.size);
    return this.pathLength(x, x[node.f]! < node.s ? node.l : node.r, depth + 1);
  }

  /** Anomaly score in (0, 1]; values near 1 are anomalous, ~0.5 or below are normal. */
  score(x: number[]): number {
    if (this.trees.length === 0) throw new Error("IsolationForest: call fit() first");
    let total = 0;
    for (const tree of this.trees) total += this.pathLength(x, tree, 0);
    const mean = total / this.trees.length;
    return Math.pow(2, -mean / averagePathLength(this.psi));
  }
}
