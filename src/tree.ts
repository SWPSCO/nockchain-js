import {
  Cell,
  NockchainError,
  atomValue,
  boundedNoun,
  digestCompare,
  digestEqual,
  hashAtom,
  hashCell,
  hashEach,
  hashNoun,
  nounEqual,
  nounTuple,
  parts,
} from "./core.js";
import type { Digest, Noun } from "./core.js";

/** Internal persistent treap nodes preserve independently reviewed snapshots. */
export interface Tree {
  readonly key: Noun;
  readonly value: Noun;
  readonly regular: Digest;
  readonly signature: Digest;
  readonly sort: Digest;
  readonly priority: Digest;
  readonly isMap: boolean;
  readonly left: Tree | null;
  readonly right: Tree | null;
}
export function newTree(
  key: Noun,
  value: Noun,
  regular: Digest,
  signature: Digest,
  isMap: boolean,
): Tree {
  const sort = hashNoun(key);
  return Object.freeze({
    key,
    value,
    regular,
    signature,
    sort,
    priority: hashCell(sort, sort),
    isMap,
    left: null,
    right: null,
  });
}
export function treeNoun(tree: Tree | null): Noun {
  return tree === null
    ? 0n
    : nounTuple(
        tree.isMap ? new Cell(tree.key, tree.value) : tree.key,
        treeNoun(tree.left),
        treeNoun(tree.right),
      );
}
export function treeDigest(tree: Tree | null, signature = false): Digest {
  return tree === null
    ? hashAtom(0n)
    : hashCell(
        signature ? tree.signature : tree.regular,
        hashCell(
          treeDigest(tree.left, signature),
          treeDigest(tree.right, signature),
        ),
      );
}
function nounLess(a: Noun, b: Noun): boolean {
  if (nounEqual(a, b)) return true;
  if (typeof a === "bigint" || typeof b === "bigint")
    return typeof a === "bigint" && typeof b === "bigint" && a < b;
  return nounEqual(a.head, b.head)
    ? nounLess(a.tail, b.tail)
    : nounLess(a.head, b.head);
}
function less(a: Tree, b: Tree, priority = false): boolean {
  const x = priority ? a.priority : a.sort,
    y = priority ? b.priority : b.sort;
  return digestEqual(x, y) ? nounLess(a.key, b.key) : digestCompare(x, y) < 0;
}
export function treePut(tree: Tree | null, node: Tree): Tree {
  if (!tree) return node;
  if (nounEqual(tree.key, node.key))
    return Object.freeze({ ...node, left: tree.left, right: tree.right });
  if (less(node, tree)) {
    const child = treePut(tree.left, node);
    if (!less(tree, child, true))
      return Object.freeze({
        ...child,
        right: Object.freeze({ ...tree, left: child.right }),
      });
    return Object.freeze({ ...tree, left: child });
  }
  const child = treePut(tree.right, node);
  if (!less(tree, child, true))
    return Object.freeze({
      ...child,
      left: Object.freeze({ ...tree, right: child.left }),
    });
  return Object.freeze({ ...tree, right: child });
}
export function readTree(
  noun: Noun,
  isMap: boolean,
  maximum: number,
  entry: (key: Noun, value: Noun) => readonly [Digest, Digest],
): Tree | null {
  boundedNoun(noun);
  let tree: Tree | null = null,
    count = 0;
  const stack: Noun[] = [noun];
  while (stack.length) {
    const value = stack.pop()!;
    if (value === 0n) continue;
    let [key, left, right] = parts(value, 3);
    if (++count > maximum)
      throw new NockchainError("Tree entry limit exceeded");
    let val: Noun = 0n;
    if (isMap) [key, val] = parts(key, 2);
    const [regular, signature] = entry(key, val);
    tree = treePut(tree, newTree(key, val, regular, signature, isMap));
    stack.push(left, right);
  }
  if (!nounEqual(noun, treeNoun(tree)))
    throw new NockchainError("Noncanonical or duplicate tree entries");
  return tree;
}
export function metadataHash(noun: Noun): Digest {
  return treeDigest(
    readTree(noun, true, 64, (key, value) => {
      const result = hashCell(hashAtom(atomValue(key)), hashEach(value));
      return [result, result];
    }),
  );
}
export function metadataEntries(noun: Noun): Map<bigint, Noun> {
  const entries = new Map<bigint, Noun>();
  readTree(noun, true, 64, (key, value) => {
    const tag = atomValue(key),
      hash = hashCell(hashAtom(tag), hashEach(value));
    entries.set(tag, value);
    return [hash, hash];
  });
  return entries;
}
