import {
  Cell,
  NockchainError,
  atom,
  atomValue,
  bigintBytes,
  boundedNoun,
  concatBytes,
  digest,
  digestEqual,
  digestNoun,
  foldHashes,
  formatDigest,
  hashAtom,
  hashCell,
  hashNoun,
  nounDigest,
  nounTuple,
  parts,
} from "./core.js";
import type { Digest, Noun } from "./core.js";
import { parsePoint } from "./curve.js";
import { publicNoun } from "./keys.js";
import { newTree, readTree, treeDigest, treeNoun, treePut } from "./tree.js";
import type { Tree } from "./tree.js";
import {
  NoteName,
  parseRange,
  range,
  rangeHash,
  rangeNoun,
  timelockAllows,
} from "./locks.js";
import type { RequiredPkhPolicy, TimelockV1, TimelockPolicy } from "./locks.js";
function publicBytes(noun: Noun): Uint8Array {
  const [x, y, marker] = parts(noun, 3);
  if (marker !== 1n) throw new NockchainError("Invalid public point marker");
  const value = concatBytes(
    new Uint8Array([1]),
    ...[y, x].flatMap((coordinate) =>
      parts(coordinate, 6)
        .reverse()
        .map((v) => bigintBytes(atomValue(v), 8)),
    ),
  );
  parsePoint(value);
  return value;
}
/** Public-key lock committed by a V0 input record. */
export class LockV0 {
  readonly threshold: number;
  readonly keys: readonly Digest[];
  readonly root: Digest;
  readonly #public: readonly Uint8Array[];
  readonly #noun: Noun;
  constructor(threshold: number, publicKeys: Iterable<Uint8Array>) {
    const values = Array.from(publicKeys, (key) => key.slice());
    if (
      !Number.isSafeInteger(threshold) ||
      threshold < 1 ||
      threshold > values.length ||
      values.length > 32
    )
      throw new NockchainError("Invalid migration signature threshold");
    const nouns = values.map((key) => publicNoun(parsePoint(key))),
      keys = nouns.map((noun) => hashNoun(noun));
    if (new Set(keys.map(formatDigest)).size !== keys.length)
      throw new NockchainError("Duplicate migration public key");
    let tree: Tree | null = null;
    for (let i = 0; i < nouns.length; i++)
      tree = treePut(tree, newTree(nouns[i], 0n, keys[i], keys[i], false));
    this.threshold = threshold;
    this.keys = Object.freeze(keys);
    this.#public = Object.freeze(values);
    this.root = hashCell(hashAtom(BigInt(threshold)), treeDigest(tree));
    this.#noun = new Cell(BigInt(threshold), treeNoun(tree));
    Object.freeze(this);
  }
  get publicKeys(): readonly Uint8Array[] {
    return Object.freeze(this.#public.map((key) => key.slice()));
  }
  noun(): Noun {
    return this.#noun;
  }
  requiredPkhPolicy(): RequiredPkhPolicy {
    return Object.freeze({ threshold: this.threshold, keys: this.keys });
  }
  authorizes(key: Digest): boolean {
    return this.keys.some((value) => digestEqual(value, key));
  }
  static fromNoun(noun: Noun): LockV0 {
    const [threshold, keyset] = parts(noun, 2),
      keys: Uint8Array[] = [];
    readTree(keyset, false, 32, (key) => {
      keys.push(publicBytes(key));
      const hash = hashNoun(key);
      return [hash, hash];
    });
    return new LockV0(Number(atomValue(threshold)), keys);
  }
}
export function noteFirstV0(lock: LockV0, hasTimelock = false): Digest {
  if (!(lock instanceof LockV0) || typeof hasTimelock !== "boolean")
    throw new NockchainError("Invalid migration lock");
  return foldHashes(
    hashAtom(0n),
    hashAtom(hasTimelock ? 0n : 1n),
    lock.root,
    hashAtom(0n),
  );
}
export interface NoteRecordV0 {
  readonly originPage: bigint;
  readonly name: NoteName;
  readonly lock: LockV0;
  readonly source: Digest;
  readonly nicks: bigint;
  readonly timelock?: TimelockV1 | null;
  readonly coinbase?: boolean;
}
/** Complete V0 record for an authenticated migration into V1 outputs. */
export class NoteV0 {
  readonly originPage: bigint;
  readonly name: NoteName;
  readonly lock: LockV0;
  readonly source: Digest;
  readonly nicks: bigint;
  readonly timelock: TimelockPolicy | null;
  readonly coinbase: boolean;
  constructor(record: NoteRecordV0) {
    this.originPage = atom(record.originPage);
    this.nicks = atom(record.nicks);
    if (
      !this.nicks ||
      !(record.name instanceof NoteName) ||
      !(record.lock instanceof LockV0)
    )
      throw new NockchainError("Invalid migration note");
    this.name = record.name;
    this.lock = record.lock;
    this.source = digest(record.source);
    this.coinbase = record.coinbase ?? false;
    if (typeof this.coinbase !== "boolean")
      throw new NockchainError("Invalid coinbase flag");
    this.timelock = record.timelock
      ? Object.freeze({
          relative: range(record.timelock.relative),
          absolute: range(record.timelock.absolute),
        })
      : null;
    if (
      this.timelock &&
      [
        this.timelock.absolute.min,
        this.timelock.absolute.max,
        this.timelock.relative.min,
        this.timelock.relative.max,
      ].every((v) => v === null)
    )
      throw new NockchainError("Empty migration timelock");
    Object.freeze(this);
  }
  noun(): Noun {
    const time = this.timelock
      ? nounTuple(
          0n,
          rangeNoun(this.timelock.absolute),
          rangeNoun(this.timelock.relative),
        )
      : 0n;
    return nounTuple(
      nounTuple(0n, this.originPage, time),
      this.name.noun(),
      this.lock.noun(),
      new Cell(digestNoun(this.source), this.coinbase ? 0n : 1n),
      this.nicks,
    );
  }
  hash(): Digest {
    const time = this.timelock
      ? foldHashes(
          hashAtom(0n),
          rangeHash(this.timelock.absolute),
          rangeHash(this.timelock.relative),
        )
      : hashAtom(0n);
    return hashCell(
      foldHashes(hashAtom(0n), hashAtom(this.originPage), time),
      foldHashes(
        this.name.hash(),
        this.lock.root,
        hashCell(this.source, hashAtom(this.coinbase ? 0n : 1n)),
        hashAtom(this.nicks),
      ),
    );
  }
  admits(height: bigint | null): boolean {
    return (
      digestEqual(
        this.name.first,
        noteFirstV0(this.lock, this.timelock !== null),
      ) &&
      (!this.timelock ||
        (height !== null &&
          timelockAllows(this.timelock, height, this.originPage)))
    );
  }
  static fromNoun(noun: Noun): NoteV0 {
    boundedNoun(noun);
    const [meta, name, lock, source, nicks] = parts(noun, 5),
      [version, origin, time] = parts(meta, 3),
      [first, last, zero] = parts(name, 3),
      [sourceHash, coinbase] = parts(source, 2);
    if (version !== 0n || zero !== 0n || (coinbase !== 0n && coinbase !== 1n))
      throw new NockchainError("Malformed migration note");
    let timelock: TimelockV1 | null = null;
    if (time !== 0n) {
      const [tag, absolute, relative] = parts(time, 3);
      if (tag !== 0n) throw new NockchainError("Invalid migration timelock");
      timelock = {
        relative: parseRange(relative),
        absolute: parseRange(absolute),
      };
    }
    return new NoteV0({
      originPage: atomValue(origin),
      name: new NoteName(nounDigest(first), nounDigest(last)),
      lock: LockV0.fromNoun(lock),
      source: nounDigest(sourceHash),
      nicks: atomValue(nicks),
      timelock,
      coinbase: coinbase === 0n,
    });
  }
}
