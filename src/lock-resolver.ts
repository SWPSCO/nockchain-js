import { NockchainError, atom, digest, digestEqual } from "./core.js";
import type { Digest, Noun } from "./core.js";
import { LockV1, NoteV1, noteFirstV1 } from "./locks.js";
import { LockTreeV1, buildLockMerkleProof } from "./lock-tree.js";
import type { LockFormV1, LockMerkleProof } from "./lock-tree.js";
import { LockData, NoteData } from "./note-data.js";
import { NoteV0, LockV0 } from "./migration.js";
export class FundMaturity {
  readonly candidateHeight: bigint;
  readonly minimum: bigint | null;
  constructor(height: bigint, minimum: bigint | null) {
    this.candidateHeight = atom(height);
    this.minimum = minimum === null ? null : atom(minimum);
    Object.freeze(this);
  }
  admits(origin: bigint): boolean {
    atom(origin);
    return (
      this.minimum === null ||
      (origin <= this.candidateHeight &&
        this.candidateHeight - origin >= this.minimum)
    );
  }
}
export class FundMaturityPolicy {
  readonly activationHeight: bigint;
  readonly minimum: bigint;
  constructor(activationHeight: bigint, minimum: bigint) {
    this.activationHeight = atom(activationHeight);
    this.minimum = atom(minimum);
    Object.freeze(this);
  }
  fundMinimumAt(height: bigint): bigint | null {
    atom(height);
    return height >= this.activationHeight ? this.minimum : null;
  }
  at(height: bigint): FundMaturity {
    return new FundMaturity(height, this.fundMinimumAt(height));
  }
}
export class FundLockPolicy {
  readonly lockRoot: Digest;
  readonly firstName: Digest;
  readonly maturity: FundMaturityPolicy;
  constructor(
    lockRoot: Digest,
    firstName: Digest,
    maturity: FundMaturityPolicy,
  ) {
    this.lockRoot = digest(lockRoot);
    this.firstName = digest(firstName);
    if (!(maturity instanceof FundMaturityPolicy))
      throw new NockchainError("Invalid fund maturity policy");
    this.maturity = maturity;
    Object.freeze(this);
  }
  authenticates(proof: LockMerkleProof, firstName: Digest): boolean {
    return (
      digestEqual(firstName, this.firstName) &&
      proof.axis === 1n &&
      digestEqual(proof.condition.root, this.lockRoot) &&
      proof.check(noteFirstV1(this.lockRoot))
    );
  }
}
export class LockResolution {
  readonly lock: LockFormV1 | LockV0;
  readonly leafNumber: number;
  readonly preimages: readonly Noun[];
  readonly fundPolicy: FundLockPolicy | null;
  constructor(
    lock: LockFormV1 | LockV0,
    leafNumber = 1,
    preimages: Iterable<Noun> = [],
    fundPolicy: FundLockPolicy | null = null,
  ) {
    if (lock instanceof LockV0) {
      if (leafNumber !== 1 || [...preimages].length || fundPolicy)
        throw new NockchainError("Invalid migration unlock context");
    } else buildLockMerkleProof(lock, leafNumber);
    this.lock = lock;
    this.leafNumber = leafNumber;
    this.preimages = Object.freeze([...preimages]);
    this.fundPolicy = fundPolicy;
    Object.freeze(this);
  }
  admits(note: NoteV1 | NoteV0, height: bigint | null): boolean {
    if (note instanceof NoteV0)
      return (
        this.lock instanceof LockV0 &&
        digestEqual(this.lock.root, note.lock.root) &&
        note.admits(height)
      );
    if (this.lock instanceof LockV0) return false;
    const proof = buildLockMerkleProof(this.lock, this.leafNumber);
    if (this.fundPolicy) {
      if (
        height === null ||
        !this.fundPolicy.authenticates(proof, note.name.first) ||
        !this.fundPolicy.maturity.at(height).admits(note.originPage)
      )
        return false;
    } else if (!proof.check(note.name.first)) return false;
    return proof.condition.allows(height, note.originPage, this.preimages);
  }
}
export interface LockMatcher {
  resolve(note: NoteV1 | NoteV0): LockResolution | null;
}
function disclosed(note: NoteV1): LockFormV1 | null {
  for (const entry of NoteData.fromNoun(note.noteData).decoded())
    if (entry.key === "lock" && entry.payload instanceof LockData)
      return entry.payload.lock;
  return null;
}
export class SigningKeyLockMatcher implements LockMatcher {
  readonly signerPKH: Digest;
  readonly coinbaseRelativeMin: bigint | null;
  constructor(signerPKH: Digest, coinbaseRelativeMin: bigint | null = 100n) {
    this.signerPKH = digest(signerPKH);
    this.coinbaseRelativeMin =
      coinbaseRelativeMin === null ? null : atom(coinbaseRelativeMin);
    Object.freeze(this);
  }
  resolve(note: NoteV1 | NoteV0): LockResolution | null {
    if (note instanceof NoteV0)
      return note.lock.threshold === 1 && note.lock.authorizes(this.signerPKH)
        ? new LockResolution(note.lock)
        : null;
    const locks = [disclosed(note), new LockV1(1, [this.signerPKH])];
    if (this.coinbaseRelativeMin !== null)
      locks.push(
        new LockV1(1, [this.signerPKH], {
          relative: { min: this.coinbaseRelativeMin },
        }),
      );
    for (const lock of locks) {
      if (!lock || !digestEqual(note.name.first, noteFirstV1(lock.root)))
        continue;
      const conditions = lock instanceof LockTreeV1 ? lock.conditions : [lock];
      for (let i = 0; i < conditions.length; i++) {
        const c = conditions[i];
        if (
          c.policies.length === 1 &&
          c.times.length <= 1 &&
          !c.hashes.length &&
          !c.isBurn &&
          c.threshold === 1 &&
          c.authorizes(this.signerPKH)
        )
          return new LockResolution(lock, i + 1);
      }
    }
    return null;
  }
}
export class LockRootLockMatcher implements LockMatcher {
  readonly lockRoot: Digest;
  readonly lock: LockFormV1 | null;
  readonly leafNumber: number;
  readonly preimages: readonly Noun[];
  readonly fundPolicy: FundLockPolicy | null;
  constructor(
    lockRoot: Digest,
    {
      lock = null,
      leafNumber = 1,
      preimages = [],
      fundPolicy = null,
    }: {
      lock?: LockFormV1 | null;
      leafNumber?: number;
      preimages?: readonly Noun[];
      fundPolicy?: FundLockPolicy | null;
    } = {},
  ) {
    this.lockRoot = digest(lockRoot);
    this.lock = lock;
    this.leafNumber = leafNumber;
    this.preimages = Object.freeze([...preimages]);
    this.fundPolicy = fundPolicy;
    if (lock && !digestEqual(lock.root, this.lockRoot))
      throw new NockchainError("Planning lock does not match its root");
    Object.freeze(this);
  }
  resolve(note: NoteV1 | NoteV0): LockResolution | null {
    if (note instanceof NoteV0) return null;
    const direct = digestEqual(note.name.first, noteFirstV1(this.lockRoot)),
      fund = this.fundPolicy;
    if (
      !direct &&
      (!fund ||
        !digestEqual(fund.lockRoot, this.lockRoot) ||
        !digestEqual(note.name.first, fund.firstName))
    )
      return null;
    let lock = direct ? disclosed(note) : null;
    if (!lock || !digestEqual(lock.root, this.lockRoot)) lock = this.lock;
    if (!lock || (!direct && lock instanceof LockTreeV1)) return null;
    return new LockResolution(
      lock,
      this.leafNumber,
      this.preimages,
      direct ? null : fund,
    );
  }
}
