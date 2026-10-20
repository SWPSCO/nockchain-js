import {
  Cell,
  NockchainError,
  atom,
  atomValue,
  boundedNoun,
  digest,
  digestEqual,
  digestNoun,
  foldHashes,
  formatDigest,
  hashAtom,
  hashCell,
  hashEach,
  nounDigest,
  nounEqual,
  nounList,
  nounTuple,
  parts,
} from "./core.js";
import type { Digest, Noun } from "./core.js";
import { LockV1, noteFirstV1 } from "./locks.js";
import { newTree, readTree, treePut } from "./tree.js";
import type { Tree } from "./tree.js";
const FULL = 0x6c6c7566n;
const STUB_AXIS_HASH = digest([
  1988594973584463658n,
  8158631336633700141n,
  2161567007650232260n,
  460329990575991155n,
  8368574252173164961n,
]);
function balanced<T>(values: readonly T[], combine: (a: T, b: T) => T): T {
  if (values.length === 1) return values[0];
  const middle = values.length / 2;
  return combine(
    balanced(values.slice(0, middle), combine),
    balanced(values.slice(middle), combine),
  );
}
/** Balanced OR tree, padded to 2/4/8/16 conditions with burn leaves. */
export class LockTreeV1 {
  readonly conditions: readonly LockV1[];
  readonly root: Digest;
  constructor(conditions: Iterable<LockV1>) {
    const values = Array.from(conditions);
    if (
      values.length < 2 ||
      values.length > 16 ||
      values.some((c) => !(c instanceof LockV1))
    )
      throw new NockchainError("A lock tree requires 2 through 16 conditions");
    const arity = 2 ** Math.ceil(Math.log2(values.length));
    while (values.length < arity) values.push(LockV1.burn());
    this.conditions = Object.freeze(values);
    this.root = hashCell(
      hashAtom(BigInt(arity)),
      balanced(
        values.map((c) => c.root),
        hashCell,
      ),
    );
    Object.freeze(this);
  }
  noun(): Noun {
    return new Cell(
      BigInt(this.conditions.length),
      balanced(
        this.conditions.map((c) => c.noun()),
        (a, b) => new Cell(a, b),
      ),
    );
  }
  metadata(): Noun {
    return nounTuple(new Cell(0x6b636f6cn, new Cell(0n, this.noun())), 0n, 0n);
  }
}
export type LockFormV1 = LockV1 | LockTreeV1;
export function parseLock(noun: Noun): LockFormV1 {
  boundedNoun(noun);
  if (!(noun instanceof Cell)) throw new NockchainError("Malformed lock");
  if (noun.head instanceof Cell) return LockV1.fromNoun(noun);
  if (![2n, 4n, 8n, 16n].includes(noun.head))
    throw new NockchainError("Invalid lock arity");
  const leaves = (body: Noun, count: number): LockV1[] => {
    if (count === 1) return [LockV1.fromNoun(body)];
    const [left, right] = parts(body, 2);
    return [...leaves(left, count / 2), ...leaves(right, count / 2)];
  };
  return new LockTreeV1(leaves(noun.tail, Number(noun.head)));
}
export class LockMerkleProof {
  readonly condition: LockV1;
  readonly axis: bigint;
  readonly root: Digest;
  readonly path: readonly Digest[];
  readonly full: boolean;
  constructor(
    condition: LockV1,
    axis: bigint,
    root: Digest,
    path: Iterable<Digest> = [],
    full = true,
  ) {
    if (!(condition instanceof LockV1) || typeof full !== "boolean")
      throw new NockchainError("Invalid lock proof");
    this.condition = condition;
    this.axis = atom(axis);
    this.root = digest(root);
    this.path = Object.freeze(Array.from(path, digest));
    this.full = full;
    if (this.path.length > 63)
      throw new NockchainError("Lock proof path exceeds axis depth");
    Object.freeze(this);
  }
  noun(): Noun {
    const fields: Noun[] = [
      this.condition.noun(),
      this.axis,
      new Cell(digestNoun(this.root), nounList(...this.path.map(digestNoun))),
    ];
    return nounTuple(...(this.full ? [FULL, ...fields] : fields));
  }
  hash(): Digest {
    let path = hashAtom(0n);
    for (const sibling of [...this.path].reverse())
      path = hashCell(sibling, path);
    const proof = hashCell(this.root, path);
    return this.full
      ? foldHashes(
          hashAtom(FULL),
          this.condition.root,
          hashAtom(this.axis),
          proof,
        )
      : foldHashes(this.condition.root, STUB_AXIS_HASH, proof);
  }
  verifyInclusion(): boolean {
    let axis = this.axis,
      leaf = this.condition.root;
    if (!axis) return false;
    for (const sibling of this.path) {
      if (axis === 1n) return false;
      leaf = axis & 1n ? hashCell(sibling, leaf) : hashCell(leaf, sibling);
      axis >>= 1n;
    }
    return axis === 1n && digestEqual(leaf, this.root);
  }
  check(parentFirstName: Digest): boolean {
    const leaf =
      this.axis === 1n ||
      [2n, 4n, 8n, 16n].some(
        (arity) =>
          this.axis >= 3n * arity &&
          this.axis < 4n * arity &&
          this.path.length > 0 &&
          digestEqual(this.path.at(-1)!, hashAtom(arity)),
      );
    return (
      digestEqual(noteFirstV1(this.root), parentFirstName) &&
      (this.full ? leaf : this.axis === 1n) &&
      this.verifyInclusion()
    );
  }
  static fromNoun(noun: Noun): LockMerkleProof {
    boundedNoun(noun);
    if (!(noun instanceof Cell))
      throw new NockchainError("Malformed lock proof");
    const full = noun.head === FULL;
    const fields = parts(noun, full ? 4 : 3),
      [condition, axis, proof] = full ? fields.slice(1) : fields;
    let [root, path] = parts(proof, 2);
    const siblings: Digest[] = [];
    while (path instanceof Cell) {
      siblings.push(nounDigest(path.head));
      path = path.tail;
    }
    if (path !== 0n) throw new NockchainError("Malformed lock proof path");
    return new LockMerkleProof(
      LockV1.fromNoun(condition),
      atomValue(axis),
      nounDigest(root),
      siblings,
      full,
    );
  }
}
export function buildLockMerkleProof(
  lock: LockFormV1,
  leafNumber = 1,
  full = true,
): LockMerkleProof {
  if (!(lock instanceof LockV1 || lock instanceof LockTreeV1))
    throw new NockchainError("Invalid lock");
  const conditions = lock instanceof LockTreeV1 ? lock.conditions : [lock];
  if (
    !Number.isSafeInteger(leafNumber) ||
    leafNumber < 1 ||
    leafNumber > conditions.length
  )
    throw new NockchainError("Lock leaf number out of range");
  const offset = leafNumber - 1,
    path: Digest[] = [];
  let index = offset,
    hashes = conditions.map((c) => c.root);
  while (hashes.length > 1) {
    path.push(hashes[index ^ 1]);
    const parents: Digest[] = [];
    for (let i = 0; i < hashes.length; i += 2)
      parents.push(hashCell(hashes[i], hashes[i + 1]));
    hashes = parents;
    index = Math.floor(index / 2);
  }
  if (conditions.length > 1) path.push(hashAtom(BigInt(conditions.length)));
  return new LockMerkleProof(
    conditions[offset],
    BigInt(conditions.length > 1 ? 3 * conditions.length + offset : 1),
    lock.root,
    path,
    full,
  );
}
export function validStubAxis(
  proof: LockMerkleProof,
  isProtocolFund = false,
): boolean {
  return isProtocolFund || proof.full || proof.axis === 1n;
}
export function preimageTree(values: Iterable<Noun>): Tree | null {
  let tree: Tree | null = null;
  const seen = new Map<string, Noun>();
  for (const value of values) {
    boundedNoun(value);
    const key = hashEach(value),
      id = formatDigest(key),
      prior = seen.get(id);
    if (prior !== undefined && !nounEqual(prior, value))
      throw new NockchainError("Conflicting hashlock preimages");
    seen.set(id, value);
    if (seen.size > 32)
      throw new NockchainError("Excessive hashlock preimages");
    const item = hashCell(key, key);
    tree = treePut(tree, newTree(digestNoun(key), value, item, item, true));
  }
  return tree;
}
export function parsePreimages(noun: Noun): readonly Noun[] {
  const values: Noun[] = [];
  readTree(noun, true, 32, (key, value) => {
    const hash = nounDigest(key);
    if (!digestEqual(hashEach(value), hash))
      throw new NockchainError("Hashlock preimage does not match its key");
    values.push(value);
    const item = hashCell(hash, hash);
    return [item, item];
  });
  return Object.freeze(values);
}
