import {
  NockchainError,
  atom,
  digest,
  digestEqual,
  formatDigest,
  nounEqual,
  parts,
} from "./core.js";
import type { Digest, Noun } from "./core.js";
import { ChainContext, transactionWords } from "./fee.js";
import type { WordCountBreakdown } from "./fee.js";
import { LockV1, NoteName, NoteV1 } from "./locks.js";
import type {
  FundLockPolicy,
  LockMatcher,
  LockResolution,
} from "./lock-resolver.js";
import { NoteData } from "./note-data.js";
import { NoteV0, LockV0 } from "./migration.js";
import {
  MAX_TRANSFER_INPUTS,
  addAmount,
  prepareTransaction,
} from "./transaction.js";
import type { LockedSpendPlanV1, TransactionV1 } from "./transaction.js";
export class PlannedOutput {
  readonly lockRoot: Digest;
  readonly noteData: Noun;
  readonly amount: bigint;
  constructor(lockRoot: Digest, noteData: Noun, amount: bigint) {
    this.lockRoot = digest(lockRoot);
    this.noteData = NoteData.fromNoun(noteData).noun();
    this.amount = atom(amount);
    Object.freeze(this);
  }
  static payment(
    pkh: Digest,
    amount: bigint,
    privateOutput = false,
  ): PlannedOutput {
    const lock = new LockV1(1, [pkh]);
    return new PlannedOutput(
      lock.root,
      privateOutput ? 0n : lock.metadata(),
      amount,
    );
  }
  withAmount(amount: bigint): PlannedOutput {
    return new PlannedOutput(this.lockRoot, this.noteData, amount);
  }
}
export interface PlanRequest {
  readonly candidates: readonly (NoteV1 | NoteV0)[];
  readonly version?: 0 | 1;
  readonly outputs: readonly PlannedOutput[];
  readonly refund: PlannedOutput;
  readonly chain?: ChainContext;
  readonly selection?: readonly NoteName[];
  readonly order?: "ascending" | "descending";
  readonly feeNicks?: bigint;
  readonly sweep?: PlannedOutput;
}
export interface PlanResult {
  readonly transaction: TransactionV1;
  readonly selected: readonly (NoteV1 | NoteV0)[];
  readonly selectedTotal: bigint;
  readonly outputs: readonly PlannedOutput[];
  readonly refunds: readonly (readonly [NoteName, bigint])[];
  readonly finalFee: bigint;
  readonly minimumFee: bigint;
  readonly wordCounts: WordCountBreakdown;
}
function merge(outputs: PlannedOutput[], output: PlannedOutput): void {
  if (!output.amount) return;
  const index = outputs.findIndex((old) =>
    digestEqual(old.lockRoot, output.lockRoot),
  );
  if (index < 0) {
    outputs.push(output);
    return;
  }
  const old = outputs[index];
  if (!nounEqual(old.noteData, output.noteData))
    throw new NockchainError("Conflicting note data for the same output lock");
  outputs[index] = old.withAmount(addAmount(old.amount, output.amount));
}
type Candidate = readonly [NoteV1 | NoteV0, LockResolution];
function candidates(
  request: PlanRequest,
  matcher: LockMatcher,
  chain: ChainContext,
): Candidate[] {
  const seen = new Set<string>();
  for (const note of request.candidates) {
    if (!(note instanceof NoteV1 || note instanceof NoteV0))
      throw new NockchainError("Invalid input note");
    note.hash();
    if (seen.has(note.name.key()))
      throw new NockchainError("Duplicate input note");
    seen.add(note.name.key());
  }
  const selection = request.selection
    ? new Set(request.selection.map((n) => n.key()))
    : null;
  if (
    selection &&
    (selection.size !== request.selection!.length ||
      [...selection].some((key) => !seen.has(key)))
  )
    throw new NockchainError("Duplicate or missing manual input");
  const result: Candidate[] = [];
  for (const note of request.candidates) {
    if (selection && !selection.has(note.name.key())) continue;
    const resolved =
      note instanceof NoteV0 === ((request.version ?? 1) === 0)
        ? matcher.resolve(note)
        : null;
    if (
      resolved &&
      resolved.admits(note, chain.candidateHeight) &&
      (chain.fees.height >= chain.fees.bythosPhase ||
        resolved.lock instanceof LockV1 ||
        resolved.lock instanceof LockV0)
    )
      result.push([note, resolved]);
    else if (selection)
      throw new NockchainError("Manual input is not spendable");
  }
  const compare = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
  result.sort(([a], [b]) =>
    a.nicks !== b.nicks
      ? (a.nicks < b.nicks ? -1 : 1) * (request.order === "ascending" ? 1 : -1)
      : compare(formatDigest(a.name.first), formatDigest(b.name.first)) ||
        compare(formatDigest(a.name.last), formatDigest(b.name.last)),
  );
  return result;
}
function assemble(
  selected: readonly Candidate[],
  outputs: readonly PlannedOutput[],
  refund: PlannedOutput,
  fee: bigint,
  chain: ChainContext,
): PlanResult {
  if (!selected.length || selected.length > MAX_TRANSFER_INPUTS)
    throw new NockchainError("Input count out of range");
  const total = selected.reduce((n, [note]) => addAmount(n, note.nicks), 0n),
    paymentTotal = outputs.reduce((n, o) => addAmount(n, o.amount), 0n);
  if (addAmount(paymentTotal, fee) > total)
    throw new NockchainError("Insufficient funds");
  if (fee > total - BigInt(selected.length))
    throw new NockchainError("Fee leaves an input without a positive seed");
  const remaining = outputs.map((o) => o.amount),
    plans: LockedSpendPlanV1[] = [],
    emitted: PlannedOutput[] = [],
    refunds: [NoteName, bigint][] = [];
  let remainingFee = fee,
    fundPolicy: FundLockPolicy | null = null;
  for (const [note, resolved] of selected) {
    const inputFee = remainingFee < note.nicks ? remainingFee : note.nicks - 1n;
    remainingFee -= inputFee;
    let capacity = note.nicks - inputFee;
    const allocated: PlannedOutput[] = [];
    for (let i = 0; i < outputs.length; i++) {
      const amount = capacity < remaining[i] ? capacity : remaining[i];
      if (amount) {
        merge(allocated, outputs[i].withAmount(amount));
        capacity -= amount;
        remaining[i] -= amount;
      }
    }
    if (capacity) {
      refunds.push([note.name, capacity]);
      merge(allocated, refund.withAmount(capacity));
    }
    plans.push({
      note,
      lock: resolved.lock,
      leafNumber: resolved.leafNumber,
      preimages: resolved.preimages,
      fee: inputFee,
      outputs: allocated.map((o) => ({
        lock: o.lockRoot,
        noteData: o.noteData,
        nicks: o.amount,
      })),
    });
    if (resolved.fundPolicy) {
      if (
        fundPolicy &&
        (!digestEqual(fundPolicy.lockRoot, resolved.fundPolicy.lockRoot) ||
          !digestEqual(fundPolicy.firstName, resolved.fundPolicy.firstName) ||
          fundPolicy.maturity.activationHeight !==
            resolved.fundPolicy.maturity.activationHeight ||
          fundPolicy.maturity.minimum !== resolved.fundPolicy.maturity.minimum)
      )
        throw new NockchainError("Conflicting fund policies");
      fundPolicy = resolved.fundPolicy;
    }
    for (const output of allocated) merge(emitted, output);
  }
  if (remainingFee || remaining.some(Boolean))
    throw new NockchainError(
      "Input allocation does not cover payments and fee",
    );
  const transaction = prepareTransaction(plans, {
      fees: chain.fees,
      fundPolicy,
    }),
    rawWords = transactionWords(parts(transaction.noun(), 3)[2], {
      mergeByLockRoot: chain.fees.height >= chain.fees.bythosPhase,
      estimateSignatures: true,
    });
  const wordCounts = Object.freeze({
    seedWords: rawWords.seedWords,
    witnessWords:
      rawWords.witnessWords +
      selected.reduce(
        (n, [note]) =>
          n + (note instanceof NoteV0 ? BigInt(note.lock.threshold * 30) : 0n),
        0n,
      ),
  });
  return Object.freeze({
    transaction,
    selected: Object.freeze(selected.map(([n]) => n)),
    selectedTotal: total,
    outputs: Object.freeze(emitted),
    refunds: Object.freeze(refunds.map((r) => Object.freeze(r))),
    finalFee: fee,
    minimumFee: transaction.summary().minimumFeeNicks,
    wordCounts,
  });
}
export function plan(request: PlanRequest, matcher: LockMatcher): PlanResult {
  if (
    request.version !== undefined &&
    request.version !== 0 &&
    request.version !== 1
  )
    throw new NockchainError("Invalid candidate version");
  const chain = request.chain ?? new ChainContext();
  if (
    !(chain instanceof ChainContext) ||
    !(request.refund instanceof PlannedOutput) ||
    request.outputs.some((o) => !(o instanceof PlannedOutput)) ||
    (request.sweep !== undefined && !(request.sweep instanceof PlannedOutput))
  )
    throw new NockchainError("Invalid planning request");
  if (
    request.order !== undefined &&
    request.order !== "ascending" &&
    request.order !== "descending"
  )
    throw new NockchainError("Invalid selection order");
  if (request.feeNicks !== undefined) atom(request.feeNicks);
  const available = candidates(request, matcher, chain),
    outputs: PlannedOutput[] = [];
  if (!available.length) throw new NockchainError("No spendable inputs");
  for (const output of request.outputs) {
    if (!output.amount)
      throw new NockchainError("Payment amount must be positive");
    merge(outputs, output);
  }
  if (request.sweep && outputs.length)
    throw new NockchainError("Sweep has one planner-assigned destination");
  if (!request.sweep && !outputs.length)
    throw new NockchainError("At least one payment is required");
  const paymentTotal = outputs.reduce((n, o) => addAmount(n, o.amount), 0n),
    allInputs = request.sweep !== undefined || request.selection !== undefined;
  let fee = request.feeNicks ?? chain.fees.minFee;
  for (let round = 0; round < available.length * 2 + 8; round++) {
    const needed = addAmount(paymentTotal, fee),
      selected: Candidate[] = [];
    let total = 0n;
    for (const candidate of available) {
      total = addAmount(total, candidate[0].nicks);
      selected.push(candidate);
      if (!allInputs && total >= needed) break;
    }
    const roundOutputs = [...outputs];
    if (request.sweep) {
      if (total <= fee)
        throw new NockchainError("Balance does not cover the network fee");
      roundOutputs.push(request.sweep.withAmount(total - fee));
    }
    const result = assemble(selected, roundOutputs, request.refund, fee, chain);
    if (request.feeNicks !== undefined || result.minimumFee <= fee)
      return result;
    if (!request.sweep) {
      const remainder = total - paymentTotal;
      if (chain.fees.minFee <= remainder && remainder <= result.minimumFee) {
        try {
          const exact = assemble(
            selected,
            roundOutputs,
            request.refund,
            remainder,
            chain,
          );
          if (exact.minimumFee <= remainder) return exact;
        } catch (error) {
          if (!(error instanceof NockchainError)) throw error;
        }
      }
    }
    fee = result.minimumFee;
  }
  throw new NockchainError("Network fee does not converge");
}
