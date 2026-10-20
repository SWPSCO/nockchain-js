import {
  UINT64_MAX,
  NockchainError,
  atom,
  atomValue,
  formatDigest,
  hashAtom,
  leafCount,
  nounDigest,
  parts,
  uint,
} from "./core.js";
import type { Noun } from "./core.js";
import { metadataEntries, readTree } from "./tree.js";
import type { Tree } from "./tree.js";
import { LockMerkleProof } from "./lock-tree.js";
export const BYTHOS_PHASE = 54000n,
  BASE_FEE = 16384n,
  INPUT_FEE_DIVISOR = 4n,
  MIN_FEE = 256n;
export interface FeeParametersOptions {
  readonly height?: bigint;
  readonly bythosPhase?: bigint;
  readonly baseFee?: bigint;
  readonly inputFeeDivisor?: bigint;
  readonly minFee?: bigint;
}
export class FeeParameters {
  readonly height: bigint;
  readonly bythosPhase: bigint;
  readonly baseFee: bigint;
  readonly inputFeeDivisor: bigint;
  readonly minFee: bigint;
  constructor(options: FeeParametersOptions = {}) {
    this.height = uint(options.height ?? BYTHOS_PHASE);
    this.bythosPhase = uint(options.bythosPhase ?? BYTHOS_PHASE);
    this.baseFee = uint(options.baseFee ?? BASE_FEE);
    this.inputFeeDivisor = uint(options.inputFeeDivisor ?? INPUT_FEE_DIVISOR);
    this.minFee = uint(options.minFee ?? MIN_FEE);
    Object.freeze(this);
  }
  get witnessDivisor(): bigint {
    return this.height >= this.bythosPhase ? this.inputFeeDivisor || 1n : 1n;
  }
}
export class ChainContext {
  readonly candidateHeight: bigint | null;
  readonly fees: FeeParameters;
  constructor(
    candidateHeight: bigint | null = null,
    fees = new FeeParameters(),
  ) {
    this.candidateHeight =
      candidateHeight === null ? null : atom(candidateHeight);
    if (!(fees instanceof FeeParameters))
      throw new NockchainError("Invalid fee parameters");
    this.fees = fees;
    Object.freeze(this);
  }
  static atHeight(
    height: bigint,
    rates: Omit<FeeParametersOptions, "height"> = {},
  ): ChainContext {
    return new ChainContext(height, new FeeParameters({ ...rates, height }));
  }
}
export interface FeeBreakdown {
  readonly seedFee: bigint;
  readonly witnessFee: bigint;
  readonly wordFee: bigint;
  readonly minimumFee: bigint;
  readonly witnessDivisor: bigint;
}
export interface WordCountBreakdown {
  readonly seedWords: bigint;
  readonly witnessWords: bigint;
}
const saturate = (value: bigint) => (value > UINT64_MAX ? UINT64_MAX : value);
export function computeMinimumFee(
  seedWords: bigint,
  witnessWords: bigint,
  p = new FeeParameters(),
): FeeBreakdown {
  uint(seedWords);
  uint(witnessWords);
  const base = saturate(p.baseFee * (p.height >= p.bythosPhase ? 1n : 2n)),
    seedFee = saturate(seedWords * base),
    witnessFee = saturate(witnessWords * base) / p.witnessDivisor,
    wordFee = saturate(seedFee + witnessFee);
  return Object.freeze({
    seedFee,
    witnessFee,
    wordFee,
    minimumFee: wordFee > p.minFee ? wordFee : p.minFee,
    witnessDivisor: p.witnessDivisor,
  });
}
export function computeBridgeFee(
  amount: bigint,
  nicksFeePerNock: bigint,
): bigint {
  uint(amount);
  uint(nicksFeePerNock);
  return saturate(((amount + 65535n) / 65536n) * nicksFeePerNock);
}
function entries(noun: Noun, isMap: boolean, maximum: number): [Noun, Noun][] {
  const zero = hashAtom(0n),
    tree = readTree(noun, isMap, maximum, () => [zero, zero]),
    values: [Noun, Noun][] = [];
  const tap = (node: Tree | null) => {
    if (node) {
      tap(node.right);
      values.push([node.key, node.value]);
      tap(node.left);
    }
  };
  tap(tree);
  return values;
}
export function noteDataWords(noun: Noun): number {
  return (
    1 +
    [...metadataEntries(noun).values()].reduce<number>(
      (n, value) => n + 1 + leafCount(value),
      0,
    )
  );
}
export function transactionWords(
  spends: Noun,
  { mergeByLockRoot = true, estimateSignatures = false } = {},
): WordCountBreakdown {
  let witnessWords = 0n,
    seedWords = 0n;
  const merged = new Map<string, Map<bigint, Noun>>();
  for (const [, spend] of entries(spends, true, 64)) {
    const [version, witness, seeds, fee] = parts(spend, 4);
    atomValue(fee);
    if (version !== 0n && version !== 1n)
      throw new NockchainError("Unsupported spend version");
    witnessWords += BigInt(leafCount(witness));
    if (estimateSignatures && version === 1n) {
      const [proof, signatures] = parts(witness, 4),
        condition = LockMerkleProof.fromNoun(proof).condition;
      condition.requiredPkhPolicy();
      witnessWords += BigInt(
        Math.max(
          0,
          condition.threshold - entries(signatures, true, 32).length,
        ) * 35,
      );
    }
    for (const [seed] of entries(seeds, false, 256)) {
      const [, root, data, amount] = parts(seed, 5);
      atomValue(amount);
      const fields = metadataEntries(data);
      if (mergeByLockRoot) {
        const key = formatDigest(nounDigest(root)),
          prior = merged.get(key) ?? new Map<bigint, Noun>();
        for (const [key, value] of fields) prior.set(key, value);
        merged.set(key, prior);
      } else
        seedWords += BigInt(
          1 +
            [...fields.values()].reduce<number>(
              (n, v) => n + 1 + leafCount(v),
              0,
            ),
        );
    }
  }
  for (const fields of merged.values())
    seedWords += BigInt(
      1 +
        [...fields.values()].reduce<number>((n, v) => n + 1 + leafCount(v), 0),
    );
  return Object.freeze({ seedWords, witnessWords });
}
