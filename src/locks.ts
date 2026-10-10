import {
  Cell,
  NockchainError,
  atom,
  atomValue,
  digest,
  digestEqual,
  digestNoun,
  foldHashes,
  formatDigest,
  hashAtom,
  hashCell,
  nounDigest,
  nounList,
  nounTuple,
  parts,
} from "./core.js";
import type { Digest, Noun } from "./core.js";
import {
  metadataHash,
  newTree,
  readTree,
  treeDigest,
  treeNoun,
  treePut,
} from "./tree.js";
import type { Tree } from "./tree.js";

export interface HeightRange {
  readonly min?: bigint | null;
  readonly max?: bigint | null;
}
export interface TimelockV1 {
  readonly relative?: HeightRange;
  readonly absolute?: HeightRange;
}
interface Range {
  readonly min: bigint | null;
  readonly max: bigint | null;
}
export interface TimelockPolicy {
  readonly relative: Range;
  readonly absolute: Range;
}
function range(value: HeightRange = {}): Range {
  const min = value.min ?? null,
    max = value.max ?? null;
  if (min !== null) atom(min);
  if (max !== null) atom(max);
  if (min !== null && max !== null && min > max)
    throw new NockchainError("Inverted height range");
  return Object.freeze({ min, max });
}
function contains(value: Range, height: bigint): boolean {
  return (
    (value.min === null || height >= value.min) &&
    (value.max === null || height <= value.max)
  );
}
export function timelockAllows(
  time: TimelockV1,
  height: bigint,
  origin: bigint,
): boolean {
  atom(height);
  atom(origin);
  return (
    origin <= height &&
    contains(range(time.absolute), height) &&
    contains(range(time.relative), height - origin)
  );
}
function optional(value: bigint | null): Noun {
  return value === null ? 0n : new Cell(0n, value);
}
function optionalHash(value: bigint | null): Digest {
  return value === null
    ? hashAtom(0n)
    : hashCell(hashAtom(0n), hashAtom(value));
}
function rangeNoun(value: Range): Noun {
  return new Cell(optional(value.min), optional(value.max));
}
function rangeHash(value: Range): Digest {
  return hashCell(optionalHash(value.min), optionalHash(value.max));
}

/** Full m-of-n PKH policy, with optional inclusive conjunctive timelocks. */
export class LockV1 {
  readonly threshold: number;
  readonly keys: readonly Digest[];
  readonly timelock: TimelockPolicy | null;
  readonly root: Digest;
  /** @internal */ readonly condition: Noun;
  constructor(
    threshold: number,
    keys: Iterable<Digest>,
    time: TimelockV1 | null = null,
  ) {
    const list = Array.from(keys, digest);
    if (
      !Number.isSafeInteger(threshold) ||
      threshold < 1 ||
      threshold > list.length ||
      list.length > 32 ||
      new Set(list.map(formatDigest)).size !== list.length
    )
      throw new NockchainError("Invalid signature threshold or duplicate keys");
    this.threshold = threshold;
    this.keys = Object.freeze(list);
    this.timelock =
      time === null
        ? null
        : Object.freeze({
            relative: range(time.relative),
            absolute: range(time.absolute),
          });
    let tree: Tree | null = null;
    for (const key of this.keys)
      tree = treePut(tree, newTree(digestNoun(key), 0n, key, key, false));
    const pkh = nounTuple(0x686b70n, BigInt(threshold), treeNoun(tree));
    let tail: Noun = 0n,
      tailHash = hashAtom(0n);
    if (this.timelock) {
      const time = this.timelock;
      tail = nounList(
        nounTuple(
          0x6d6974n,
          rangeNoun(time.relative),
          rangeNoun(time.absolute),
        ),
      );
      tailHash = hashCell(
        foldHashes(
          hashAtom(0x6d6974n),
          rangeHash(time.relative),
          rangeHash(time.absolute),
        ),
        tailHash,
      );
    }
    this.root = hashCell(
      foldHashes(
        hashAtom(0x686b70n),
        hashAtom(BigInt(threshold)),
        treeDigest(tree),
      ),
      tailHash,
    );
    this.condition = new Cell(pkh, tail);
    Object.freeze(this);
  }
  metadata(): Noun {
    return nounTuple(
      new Cell(0x6b636f6cn, new Cell(0n, this.condition)),
      0n,
      0n,
    );
  }
  /** @internal */ proof(): Noun {
    return nounTuple(
      0x6c6c7566n,
      this.condition,
      1n,
      new Cell(digestNoun(this.root), 0n),
    );
  }
  /** @internal */ proofHash(): Digest {
    return foldHashes(
      hashAtom(0x6c6c7566n),
      this.root,
      hashAtom(1n),
      hashCell(this.root, hashAtom(0n)),
    );
  }
  authorizes(key: Digest): boolean {
    return this.keys.some((value) => digestEqual(value, key));
  }
}
export function newPKHLockV1(
  threshold: number,
  keys: Iterable<Digest>,
  timelock: TimelockV1 | null = null,
): LockV1 {
  return new LockV1(threshold, keys, timelock);
}
export function noteFirstV1(root: Digest): Digest {
  return hashCell(hashAtom(0n), digest(root));
}
export class NoteName {
  readonly first: Digest;
  readonly last: Digest;
  constructor(first: Digest, last: Digest) {
    this.first = digest(first);
    this.last = digest(last);
    Object.freeze(this);
  }
  noun(): Noun {
    return nounList(digestNoun(this.first), digestNoun(this.last));
  }
  hash(): Digest {
    return hashCell(this.first, hashCell(this.last, hashAtom(0n)));
  }
  /** @internal Exact identity for maps, including zero-valued digests. */
  key(): string {
    return `${formatDigest(this.first)}:${formatDigest(this.last)}`;
  }
}
export interface NoteRecordV1 {
  readonly originPage: bigint;
  readonly name: NoteName;
  readonly noteData: Noun;
  readonly nicks: bigint;
}
/** Complete input record. Applications authenticate existence and unspent status. */
export class NoteV1 implements NoteRecordV1 {
  readonly originPage: bigint;
  readonly name: NoteName;
  readonly noteData: Noun;
  readonly nicks: bigint;
  constructor(record: NoteRecordV1) {
    this.originPage = atom(record.originPage);
    this.nicks = atom(record.nicks);
    if (this.nicks === 0n || !(record.name instanceof NoteName))
      throw new NockchainError("Invalid note record");
    metadataHash(record.noteData);
    this.name = record.name;
    this.noteData = record.noteData;
    Object.freeze(this);
  }
  hash(): Digest {
    return foldHashes(
      hashAtom(1n),
      hashAtom(this.originPage),
      this.name.hash(),
      metadataHash(this.noteData),
      hashAtom(this.nicks),
    );
  }
}
function parseOptional(noun: Noun): bigint | null {
  if (noun === 0n) return null;
  const [tag, value] = parts(noun, 2);
  if (tag !== 0n) throw new NockchainError("Invalid optional height");
  return atomValue(value);
}
function parseRange(noun: Noun): Range {
  const [min, max] = parts(noun, 2);
  return range({ min: parseOptional(min), max: parseOptional(max) });
}
export function parseCondition(noun: Noun): LockV1 {
  if (!(noun instanceof Cell))
    throw new NockchainError("Unsupported lock condition");
  const [tag, threshold, keyset] = parts(noun.head, 3);
  if (tag !== 0x686b70n) throw new NockchainError("Unsupported lock primitive");
  const value = atomValue(threshold);
  if (value > 32n) throw new NockchainError("Invalid signature threshold");
  const keys: Digest[] = [];
  readTree(keyset, false, 32, (key) => {
    const value = nounDigest(key);
    keys.push(value);
    return [value, value];
  });
  let time: TimelockV1 | null = null;
  const tail = noun.tail;
  if (tail !== 0n) {
    if (!(tail instanceof Cell) || tail.tail !== 0n)
      throw new NockchainError("Unsupported lock condition");
    const [tag, relative, absolute] = parts(tail.head, 3);
    if (tag !== 0x6d6974n)
      throw new NockchainError("Unsupported lock primitive");
    time = { relative: parseRange(relative), absolute: parseRange(absolute) };
  }
  return new LockV1(Number(value), keys, time);
}
