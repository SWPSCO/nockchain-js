import {
  NockchainError,
  PRIME,
  digest,
  digestCompare,
  digestEqual,
  equalBytes,
  formatDigest,
  formatNocks,
  parseDigest,
  parseNocks,
  uint,
} from "./core.js";
import type { Digest } from "./core.js";
import { ExtendedKey, lockRoot } from "./keys.js";
import { LockV1, NoteV1, noteFirstV1 } from "./locks.js";
import {
  MAX_TRANSFER_INPUTS,
  MAX_TRANSFER_OUTPUTS,
  TransactionV1,
  addAmount,
  prepareTransactionV1,
} from "./transaction.js";
import type { LockedSpendPlanV1 } from "./transaction.js";

export interface UnspentNote {
  readonly note: NoteV1;
  readonly lockRoot: Digest;
}
export interface Payment {
  readonly address: string;
  readonly amount: string;
}
export interface PaymentV1 {
  readonly recipient: Digest;
  readonly nicks: bigint;
}
export interface SpendPlanV1 {
  readonly note: NoteV1;
  readonly lockRoot: Digest;
  readonly outputs: readonly PaymentV1[];
  readonly fee: bigint;
}
export interface TransferOptions {
  readonly changeAddress?: string;
  readonly feeNicks?: bigint;
}
export interface TransferSummary {
  readonly inputCount: number;
  readonly inputNicks: bigint;
  readonly paymentNicks: bigint;
  readonly feeNicks: bigint;
  readonly changeNicks: bigint;
  readonly changeAddress: string;
  readonly payments: readonly Payment[];
}
const PLAN_TOKEN = Symbol("transfer");
export class PreparedTransfer {
  readonly #plans: readonly SpendPlanV1[];
  readonly #summary: TransferSummary;
  readonly #public: Uint8Array;
  /** @internal Use prepareTransfer() or selectTransfer(). */
  constructor(
    token: symbol,
    plans: readonly SpendPlanV1[],
    summary: TransferSummary,
    publicKey: Uint8Array,
  ) {
    if (token !== PLAN_TOKEN)
      throw new NockchainError("Use prepareTransfer or selectTransfer");
    this.#plans = Object.freeze(
      plans.map((plan) =>
        Object.freeze({
          ...plan,
          lockRoot: digest(plan.lockRoot),
          outputs: Object.freeze(
            plan.outputs.map((output) =>
              Object.freeze({ ...output, recipient: digest(output.recipient) }),
            ),
          ),
        }),
      ),
    );
    this.#summary = Object.freeze({
      ...summary,
      payments: Object.freeze(
        summary.payments.map((payment) => Object.freeze({ ...payment })),
      ),
    });
    this.#public = publicKey.slice();
    Object.freeze(this);
  }
  summary(): TransferSummary {
    return this.#summary;
  }
  notes(): readonly NoteV1[] {
    return Object.freeze(this.#plans.map((plan) => plan.note));
  }
  sign(key: ExtendedKey): TransactionV1 {
    if (!this.#plans.length || !equalBytes(key.publicBytes(), this.#public))
      throw new NockchainError("Signing key does not match prepared transfer");
    return signTransferV1(key, this.#plans);
  }
}
export function minimumTransferFeeV1(
  inputs: number,
  recipientValues: Iterable<Digest>,
): bigint {
  const recipients = Array.from(recipientValues, digest);
  if (
    !Number.isSafeInteger(inputs) ||
    inputs < 1 ||
    inputs > MAX_TRANSFER_INPUTS ||
    !recipients.length ||
    recipients.length > MAX_TRANSFER_OUTPUTS
  )
    throw new NockchainError("Transfer size out of range");
  return (
    BigInt(new Set(recipients.map(formatDigest)).size) * 13n * 16384n +
    BigInt(inputs) * 56n * 4096n
  );
}
export function signTransferV1(
  key: ExtendedKey,
  plans: Iterable<SpendPlanV1>,
): TransactionV1 {
  const lock = new LockV1(1, [parseDigest(key.address())]);
  const locked: LockedSpendPlanV1[] = [];
  for (const plan of plans) {
    if (!digestEqual(digest(plan.lockRoot), lock.root))
      throw new NockchainError("Input lock does not authorize this key");
    locked.push({
      note: plan.note,
      lock,
      fee: plan.fee,
      outputs: plan.outputs.map((output) => ({
        lock: new LockV1(1, [output.recipient]),
        nicks: output.nicks,
      })),
    });
  }
  return prepareTransactionV1(locked).sign(key);
}
/** Consume all supplied notes, merge recipients, estimate fees and return change. */
export function prepareTransfer(
  sender: ExtendedKey,
  records: Iterable<UnspentNote>,
  requestedPayments: Iterable<Payment>,
  options: TransferOptions = {},
): PreparedTransfer {
  const notes = Array.from(records),
    payments = Array.from(requestedPayments);
  if (
    !notes.length ||
    notes.length > MAX_TRANSFER_INPUTS ||
    !payments.length ||
    payments.length > MAX_TRANSFER_OUTPUTS
  )
    throw new NockchainError("Transfer size out of range");
  const address = sender.address(),
    root = lockRoot(parseDigest(address)),
    bound = noteFirstV1(root);
  const change = options.changeAddress || address,
    changePKH = parseDigest(change);
  let inputNicks = 0n,
    paymentNicks = 0n;
  const seen = new Set<string>();
  for (const unspent of notes) {
    const note = unspent.note;
    if (!(note instanceof NoteV1))
      throw new NockchainError("Invalid note record");
    note.hash();
    if (
      seen.has(note.name.key()) ||
      !digestEqual(note.name.first, bound) ||
      !digestEqual(digest(unspent.lockRoot), root)
    )
      throw new NockchainError("Duplicate or unauthorized input");
    seen.add(note.name.key());
    inputNicks = addAmount(inputNicks, note.nicks);
  }
  const recipients: Digest[] = [],
    amounts: bigint[] = [],
    positions = new Map<string, number>(),
    reviewedPayments: Payment[] = [];
  for (const payment of payments) {
    const recipient = parseDigest(payment.address),
      amount = parseNocks(payment.amount);
    if (amount === 0n || amount >= PRIME)
      throw new NockchainError("Invalid payment amount");
    paymentNicks = addAmount(paymentNicks, amount);
    const identity = formatDigest(recipient),
      position = positions.get(identity);
    if (position !== undefined)
      amounts[position] = addAmount(amounts[position], amount);
    else {
      positions.set(identity, recipients.length);
      recipients.push(recipient);
      amounts.push(amount);
    }
    reviewedPayments.push({
      address: payment.address,
      amount: formatNocks(amount),
    });
  }
  if (paymentNicks >= inputNicks)
    throw new NockchainError("Insufficient funds for payment and fees");
  const available = inputNicks - paymentNicks,
    minimum = minimumTransferFeeV1(notes.length, recipients);
  let fee = uint(options.feeNicks ?? 0n);
  if (!fee) {
    fee = minimum;
    if (available > fee) {
      fee = minimumTransferFeeV1(
        notes.length,
        positions.has(change) ? recipients : [...recipients, changePKH],
      );
      if (fee > available && available >= minimum) fee = available;
    }
  }
  if (fee > available)
    throw new NockchainError("Insufficient funds for payment and fees");
  const changeNicks = available - fee;
  if (changeNicks > 0n) {
    const position = positions.get(change);
    if (position !== undefined)
      amounts[position] = addAmount(amounts[position], changeNicks);
    else {
      recipients.push(changePKH);
      amounts.push(changeNicks);
    }
  }
  if (fee < minimumTransferFeeV1(notes.length, recipients))
    throw new NockchainError("Fee below minimum");
  const plans: SpendPlanV1[] = [];
  let remainingFee = fee,
    output = 0,
    outputCount = 0;
  for (const unspent of notes) {
    const inputFee =
      remainingFee < unspent.note.nicks
        ? remainingFee
        : unspent.note.nicks - 1n;
    remainingFee -= inputFee;
    let remaining = unspent.note.nicks - inputFee;
    const outputs: PaymentV1[] = [];
    while (remaining > 0n) {
      if (output >= amounts.length)
        throw new NockchainError("Input values cannot be allocated to outputs");
      const value = remaining < amounts[output] ? remaining : amounts[output];
      outputs.push({ recipient: recipients[output], nicks: value });
      if (++outputCount > MAX_TRANSFER_OUTPUTS)
        throw new NockchainError("Output count out of range");
      remaining -= value;
      amounts[output] -= value;
      if (!amounts[output]) output++;
    }
    plans.push({
      note: unspent.note,
      lockRoot: unspent.lockRoot,
      outputs,
      fee: inputFee,
    });
  }
  if (remainingFee)
    throw new NockchainError("Notes cannot cover the requested fee");
  return new PreparedTransfer(
    PLAN_TOKEN,
    plans,
    {
      inputCount: notes.length,
      inputNicks,
      paymentNicks,
      feeNicks: fee,
      changeNicks,
      changeAddress: change,
      payments: reviewedPayments,
    },
    sender.publicBytes(),
  );
}
/** Largest-first sufficient subset with deterministic note-name tie breaking. */
export function selectTransfer(
  sender: ExtendedKey,
  notes: Iterable<UnspentNote>,
  requestedPayments: Iterable<Payment>,
  options: TransferOptions = {},
): PreparedTransfer {
  const root = lockRoot(parseDigest(sender.address())),
    bound = noteFirstV1(root),
    seen = new Set<string>();
  const candidates: UnspentNote[] = [];
  for (const unspent of notes) {
    const note = unspent.note;
    if (!(note instanceof NoteV1))
      throw new NockchainError("Invalid note record");
    note.hash();
    if (seen.has(note.name.key()))
      throw new NockchainError("Duplicate input note");
    seen.add(note.name.key());
    if (
      digestEqual(digest(unspent.lockRoot), root) &&
      digestEqual(note.name.first, bound)
    )
      candidates.push(unspent);
  }
  candidates.sort((a, b) =>
    a.note.nicks !== b.note.nicks
      ? a.note.nicks > b.note.nicks
        ? -1
        : 1
      : digestCompare(a.note.name.first, b.note.name.first) ||
        digestCompare(a.note.name.last, b.note.name.last),
  );
  const payments = Array.from(requestedPayments);
  let failure = new NockchainError("No spendable notes");
  for (
    let count = 1;
    count <= Math.min(candidates.length, MAX_TRANSFER_INPUTS);
    count++
  ) {
    try {
      return prepareTransfer(
        sender,
        candidates.slice(0, count),
        payments,
        options,
      );
    } catch (error) {
      if (!(error instanceof NockchainError)) throw error;
      failure = error;
    }
  }
  throw failure;
}
