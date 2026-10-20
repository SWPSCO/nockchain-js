import {
  PRIME,
  Cell,
  NockchainError,
  atom,
  atomValue,
  boundedNoun,
  digest,
  digestNoun,
  hashAtom,
  hashCell,
  hashEach,
  leafCount,
  nounDigest,
  nounEqual,
  nounList,
  nounTuple,
  parts,
} from "./core.js";
import type { Digest, Noun } from "./core.js";
import {
  metadataEntries,
  newTree,
  treeDigest,
  treeNoun,
  treePut,
} from "./tree.js";
import type { Tree } from "./tree.js";
import { parseLock } from "./lock-tree.js";
import type { LockFormV1 } from "./lock-tree.js";
function keyAtom(name: string): [string, bigint] {
  if (typeof name !== "string" || !name.trim())
    throw new NockchainError("Empty note-data key");
  name = name.trim();
  let value = 0n;
  const bytes = new TextEncoder().encode(name);
  for (let i = bytes.length - 1; i >= 0; i--)
    value = (value << 8n) | BigInt(bytes[i]);
  return [name, atom(value)];
}
export class LockData {
  constructor(readonly lock: LockFormV1) {
    Object.freeze(this);
  }
  noun(): Noun {
    return new Cell(0n, this.lock.noun());
  }
  static fromNoun(noun: Noun): LockData {
    const [version, lock] = parts(noun, 2);
    if (version !== 0n)
      throw new NockchainError("Unsupported lock-data version");
    return new LockData(parseLock(lock));
  }
}
export class BridgeDepositDataPayload {
  readonly #address: Uint8Array;
  constructor(address: Uint8Array) {
    if (!(address instanceof Uint8Array) || address.length !== 20)
      throw new NockchainError("EVM address must contain 20 bytes");
    this.#address = address.slice();
    Object.freeze(this);
  }
  get evmAddress(): Uint8Array {
    return this.#address.slice();
  }
  noun(): Noun {
    let value = 0n;
    for (const byte of this.#address) value = (value << 8n) | BigInt(byte);
    const digits: bigint[] = [];
    for (let i = 0; i < 3; i++) {
      digits.push(value % PRIME);
      value /= PRIME;
    }
    return nounTuple(0n, 0x65736162n, ...digits);
  }
  static fromNoun(noun: Noun): BridgeDepositDataPayload {
    const [version, network, a, b, c] = parts(noun, 5);
    if (version !== 0n || network !== 0x65736162n)
      throw new NockchainError("Unsupported bridge version or network");
    let value = atomValue(a) + PRIME * (atomValue(b) + PRIME * atomValue(c));
    if (value >= 1n << 160n)
      throw new NockchainError("EVM address exceeds 160 bits");
    const bytes = new Uint8Array(20);
    for (let i = 19; i >= 0; i--) {
      bytes[i] = Number(value & 255n);
      value >>= 8n;
    }
    return new BridgeDepositDataPayload(bytes);
  }
}
export class BridgeWithdrawalDataPayload {
  readonly beid: readonly bigint[];
  readonly baseHash: Digest;
  readonly lockRoot: Digest;
  readonly baseBatchEnd: bigint;
  constructor(
    beid: Iterable<bigint>,
    baseHash: Digest,
    lockRoot: Digest,
    end: bigint,
  ) {
    this.beid = Object.freeze(Array.from(beid, atom));
    this.baseHash = digest(baseHash);
    this.lockRoot = digest(lockRoot);
    this.baseBatchEnd = atom(end);
    Object.freeze(this);
  }
  noun(): Noun {
    return nounTuple(
      0n,
      nounList(...this.beid),
      digestNoun(this.baseHash),
      digestNoun(this.lockRoot),
      this.baseBatchEnd,
    );
  }
  static fromNoun(noun: Noun): BridgeWithdrawalDataPayload {
    boundedNoun(noun);
    let [version, beid, baseHash, lockRoot, end] = parts(noun, 5);
    if (version !== 0n)
      throw new NockchainError("Unsupported withdrawal version");
    const values: bigint[] = [];
    while (beid instanceof Cell) {
      values.push(atomValue(beid.head));
      beid = beid.tail;
    }
    if (beid !== 0n) throw new NockchainError("Invalid withdrawal beid");
    return new BridgeWithdrawalDataPayload(
      values,
      nounDigest(baseHash),
      nounDigest(lockRoot),
      atomValue(end),
    );
  }
}
export type NoteDataPayload =
  LockData | BridgeDepositDataPayload | BridgeWithdrawalDataPayload | Noun;
export interface DecodedNoteDataEntry {
  readonly key: string;
  readonly payload: NoteDataPayload;
}
export class NoteData {
  readonly entries: readonly (readonly [string, Noun])[];
  constructor(entries: Iterable<readonly [string, Noun]> = []) {
    const values = new Map<string, Noun>();
    for (const [key, value] of entries) {
      const [name] = keyAtom(key);
      boundedNoun(value);
      const prior = values.get(name);
      if (prior !== undefined && !nounEqual(prior, value))
        throw new NockchainError("Conflicting note-data values");
      values.set(name, value);
    }
    if (values.size > 64)
      throw new NockchainError("Too many note-data entries");
    this.entries = Object.freeze(
      [...values]
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map((e) => Object.freeze(e)),
    );
    Object.freeze(this);
  }
  private tree(): Tree | null {
    let tree: Tree | null = null;
    for (const [name, value] of this.entries) {
      const [, key] = keyAtom(name),
        hash = hashCell(hashAtom(key), hashEach(value));
      tree = treePut(tree, newTree(key, value, hash, hash, true));
    }
    return tree;
  }
  noun(): Noun {
    return treeNoun(this.tree());
  }
  hash(): Digest {
    return treeDigest(this.tree());
  }
  words(): number {
    return 1 + this.entries.reduce((n, [, v]) => n + 1 + leafCount(v), 0);
  }
  static fromNoun(noun: Noun): NoteData {
    const entries: [string, Noun][] = [];
    for (let [key, value] of metadataEntries(noun)) {
      const bytes: number[] = [];
      while (key) {
        bytes.push(Number(key & 255n));
        key >>= 8n;
      }
      let name: string;
      try {
        name = new TextDecoder("utf-8", { fatal: true }).decode(
          Uint8Array.from(bytes),
        );
      } catch {
        throw new NockchainError("Invalid note-data key encoding");
      }
      entries.push([name, value]);
    }
    return new NoteData(entries);
  }
  static fromLock(lock: LockFormV1): NoteData {
    return new NoteData([["lock", new LockData(lock).noun()]]);
  }
  withEntry(key: string, payload: NoteDataPayload): NoteData {
    const [name] = keyAtom(key),
      value =
        typeof payload === "object" && "noun" in payload
          ? payload.noun()
          : payload;
    return new NoteData([
      ...this.entries.filter(([k]) => k !== name),
      [name, value],
    ]);
  }
  decoded(): readonly DecodedNoteDataEntry[] {
    return Object.freeze(
      this.entries.map(([key, value]) => {
        let payload: NoteDataPayload = value;
        try {
          if (key === "lock") payload = LockData.fromNoun(value);
          else if (key === "bridge")
            payload = BridgeDepositDataPayload.fromNoun(value);
          else if (key === "bridge-w")
            payload = BridgeWithdrawalDataPayload.fromNoun(value);
        } catch (error) {
          if (!(error instanceof NockchainError)) throw error;
        }
        return Object.freeze({ key, payload });
      }),
    );
  }
}
