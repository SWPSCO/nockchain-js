import {
  Cell,
  NockchainError,
  atom,
  atomValue,
  boundedNoun,
  hashEach,
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
export function range(value: HeightRange = {}): Range {
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
export function rangeNoun(value: Range): Noun {
  return new Cell(optional(value.min), optional(value.max));
}
export function rangeHash(value: Range): Digest {
  return hashCell(optionalHash(value.min), optionalHash(value.max));
}

export interface RequiredPkhPolicy {
  readonly threshold: number;
  readonly keys: readonly Digest[];
}
function digestSet(values: Iterable<Digest>): Noun {
  const keys = Array.from(values, digest);
  if (keys.length > 32 || new Set(keys.map(formatDigest)).size !== keys.length)
    throw new NockchainError("Duplicate or excessive hash set entries");
  let tree: Tree | null = null;
  for (const key of keys)
    tree = treePut(tree, newTree(digestNoun(key), 0n, key, key, false));
  return treeNoun(tree);
}
function readDigestSet(noun: Noun): { keys: Digest[]; tree: Tree | null } {
  const keys: Digest[] = [];
  const tree = readTree(noun, false, 32, (key) => {
    const value = nounDigest(key);
    keys.push(value);
    return [value, value];
  });
  return { keys, tree };
}
/** One conjunctive spend condition. LockTreeV1 provides alternative conditions. */
export class LockV1 {
  readonly threshold!: number;
  readonly keys!: readonly Digest[];
  readonly timelock!: TimelockPolicy | null;
  readonly hashes!: readonly Digest[];
  readonly root!: Digest;
  readonly condition!: Noun;
  readonly times!: readonly TimelockPolicy[];
  readonly policies!: readonly RequiredPkhPolicy[];
  readonly isBurn!: boolean;
  constructor(
    threshold: number,
    keys: Iterable<Digest>,
    time: TimelockV1 | null = null,
    hashes: Iterable<Digest> = [],
  ) {
    const list = Array.from(keys, digest);
    if (
      !Number.isSafeInteger(threshold) ||
      threshold < 1 ||
      threshold > list.length
    )
      throw new NockchainError("Invalid signature threshold");
    const primitives: Noun[] = [
      nounTuple(0x686b70n, BigInt(threshold), digestSet(list)),
    ];
    if (time)
      primitives.push(
        nounTuple(
          0x6d6974n,
          rangeNoun(range(time.relative)),
          rangeNoun(range(time.absolute)),
        ),
      );
    const required = Array.from(hashes);
    if (required.length)
      primitives.push(new Cell(0x786168n, digestSet(required)));
    this.initialize(nounList(...primitives));
  }
  private initialize(noun: Noun): void {
    boundedNoun(noun);
    const values: Digest[] = [],
      times: TimelockPolicy[] = [],
      policies: RequiredPkhPolicy[] = [],
      hashes: Digest[] = [];
    let tail = noun,
      isBurn = false;
    while (tail instanceof Cell) {
      const [tag, body] = parts(tail.head, 2);
      if (tag === 0x686b70n) {
        const [n, set] = parts(body, 2),
          threshold = Number(atomValue(n)),
          { keys, tree } = readDigestSet(set);
        if (threshold < 1 || threshold > keys.length)
          throw new NockchainError("Invalid signature threshold");
        policies.push(Object.freeze({ threshold, keys: Object.freeze(keys) }));
        values.push(
          foldHashes(
            hashAtom(tag),
            hashAtom(BigInt(threshold)),
            treeDigest(tree),
          ),
        );
      } else if (tag === 0x6d6974n) {
        const [rel, abs] = parts(body, 2),
          time = Object.freeze({
            relative: parseRange(rel),
            absolute: parseRange(abs),
          });
        times.push(time);
        values.push(
          foldHashes(
            hashAtom(tag),
            rangeHash(time.relative),
            rangeHash(time.absolute),
          ),
        );
      } else if (tag === 0x786168n) {
        const { keys, tree } = readDigestSet(body);
        hashes.push(...keys);
        values.push(hashCell(hashAtom(tag), treeDigest(tree)));
      } else if (tag === 0x6e7262n && body === 0n) {
        isBurn = true;
        values.push(hashCell(hashAtom(tag), hashAtom(0n)));
      } else throw new NockchainError("Invalid lock primitive");
      tail = tail.tail;
    }
    if (tail !== 0n || !values.length)
      throw new NockchainError("Empty or malformed spend condition");
    let root = hashAtom(0n);
    for (const value of values.reverse()) root = hashCell(value, root);
    let keys = policies[0]?.keys ?? [];
    for (const policy of policies.slice(1))
      keys = keys.filter((key) => policy.keys.some((k) => digestEqual(k, key)));
    Object.assign(this, {
      threshold: policies[0]?.threshold ?? 0,
      keys: Object.freeze(keys),
      timelock: times[0] ?? null,
      hashes: Object.freeze(
        Array.from(new Map(hashes.map((h) => [formatDigest(h), h])).values()),
      ),
      root,
      condition: noun,
      times: Object.freeze(times),
      policies: Object.freeze(policies),
      isBurn,
    });
    Object.freeze(this);
  }
  static fromNoun(noun: Noun): LockV1 {
    const value = Object.create(LockV1.prototype) as LockV1;
    value.initialize(noun);
    return value;
  }
  static hashlock(hashes: Iterable<Digest>): LockV1 {
    return LockV1.fromNoun(nounList(new Cell(0x786168n, digestSet(hashes))));
  }
  static burn(): LockV1 {
    return LockV1.fromNoun(nounList(new Cell(0x6e7262n, 0n)));
  }
  noun(): Noun {
    return this.condition;
  }
  requiredPkhPolicy(): RequiredPkhPolicy | null {
    if (!this.policies.length) return null;
    if (
      this.policies.some((p) => p.threshold !== this.threshold) ||
      this.keys.length < this.threshold
    )
      throw new NockchainError(
        "PKH conditions cannot share a satisfying signature map",
      );
    return Object.freeze({ threshold: this.threshold, keys: this.keys });
  }
  allows(
    height: bigint | null,
    origin: bigint,
    preimages: readonly Noun[] = [],
  ): boolean {
    if (this.isBurn) return false;
    this.requiredPkhPolicy();
    if (
      this.times.length &&
      (height === null ||
        this.times.some((t) => !timelockAllows(t, height, origin)))
    )
      return false;
    const supplied = new Set(
      preimages.map((value) => formatDigest(hashEach(value))),
    );
    return this.hashes.every((h) => supplied.has(formatDigest(h)));
  }
  metadata(): Noun {
    return nounTuple(new Cell(0x6b636f6cn, new Cell(0n, this.noun())), 0n, 0n);
  }
  proof(): Noun {
    return nounTuple(
      0x6c6c7566n,
      this.condition,
      1n,
      new Cell(digestNoun(this.root), 0n),
    );
  }
  proofHash(): Digest {
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
export function parseRange(noun: Noun): Range {
  const [min, max] = parts(noun, 2);
  return range({ min: parseOptional(min), max: parseOptional(max) });
}
export function parseCondition(noun: Noun): LockV1 {
  return LockV1.fromNoun(noun);
}
