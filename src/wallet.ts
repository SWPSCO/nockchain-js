import {
  NockchainError,
  PRIME,
  digest,
  digestEqual,
  equalBytes,
  formatDigest,
  formatNocks,
  parseDigest,
  parseNocks,
} from "./core.js";
import type { Digest } from "./core.js";
import { ExtendedKey } from "./keys.js";
import { LockV1, NoteV1, noteFirstV1 } from "./locks.js";
import {
  MAX_TRANSFER_INPUTS,
  MAX_TRANSFER_OUTPUTS,
  TransactionV1,
  addAmount,
  minimumTransactionFeeV1,
  prepareTransactionV1,
} from "./transaction.js";
import type { LockedSpendPlanV1 } from "./transaction.js";

import { ChainContext, FeeParameters } from "./fee.js";
import { PlannedOutput, plan } from "./planner.js";
import { SigningKeyLockMatcher } from "./lock-resolver.js";
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
  readonly chain?: ChainContext;
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
  readonly #transaction: TransactionV1;
  readonly #notes: readonly NoteV1[];
  readonly #summary: TransferSummary;
  readonly #public: Uint8Array;
  /** @internal Use prepareTransfer() or selectTransfer(). */
  constructor(
    token: symbol,
    transaction: TransactionV1,
    notes: readonly NoteV1[],
    summary: TransferSummary,
    publicKey: Uint8Array,
  ) {
    if (token !== PLAN_TOKEN)
      throw new NockchainError("Use prepareTransfer or selectTransfer");
    this.#transaction = transaction;
    this.#notes = Object.freeze([...notes]);
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
    return this.#notes;
  }
  sign(key: ExtendedKey): TransactionV1 {
    if (!this.#notes.length || !equalBytes(key.publicBytes(), this.#public))
      throw new NockchainError("Signing key does not match prepared transfer");
    return this.#transaction.sign(key);
  }
}
export function minimumTransferFeeV1(
  inputs: number,
  recipientValues: Iterable<Digest>,
  fees = new FeeParameters(),
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
  const locks = [
    ...new Map(
      recipients.map((key) => [formatDigest(key), new LockV1(1, [key])]),
    ).values(),
  ];
  return minimumTransactionFeeV1(
    Array.from({ length: inputs }, () => locks[0]),
    locks,
    fees,
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
function transfer(
  sender: ExtendedKey,
  records: Iterable<UnspentNote>,
  requestedPayments: Iterable<Payment>,
  options: TransferOptions,
  manual: boolean,
): PreparedTransfer {
  const notes = [...records],
    payments = [...requestedPayments];
  if (
    !notes.length ||
    !payments.length ||
    payments.length > MAX_TRANSFER_OUTPUTS
  )
    throw new NockchainError("Transfer size out of range");
  const address = sender.address(),
    pkh = parseDigest(address),
    change = options.changeAddress || address;
  const refund = PlannedOutput.payment(parseDigest(change), 0n),
    candidates: NoteV1[] = [];
  for (const unspent of notes) {
    if (!(unspent.note instanceof NoteV1))
      throw new NockchainError("Invalid input record");
    if (!digestEqual(unspent.note.name.first, noteFirstV1(unspent.lockRoot)))
      throw new NockchainError("Input name does not bind supplied lock root");
    candidates.push(unspent.note);
  }
  const outputs: PlannedOutput[] = [],
    reviewedPayments: Payment[] = [];
  let paymentNicks = 0n;
  for (const payment of payments) {
    const amount = parseNocks(payment.amount);
    if (!amount || amount >= PRIME)
      throw new NockchainError("Invalid payment amount");
    outputs.push(PlannedOutput.payment(parseDigest(payment.address), amount));
    paymentNicks = addAmount(paymentNicks, amount);
    reviewedPayments.push({
      address: payment.address,
      amount: formatNocks(amount),
    });
  }
  const result = plan(
    {
      candidates,
      outputs,
      refund,
      chain: options.chain,
      selection: manual ? candidates.map((n) => n.name) : undefined,
      feeNicks: options.feeNicks || undefined,
    },
    new SigningKeyLockMatcher(pkh),
  );
  if (result.finalFee < result.minimumFee)
    throw new NockchainError("Fee below minimum");
  return new PreparedTransfer(
    PLAN_TOKEN,
    result.transaction,
    result.selected.map((note) => {
      if (!(note instanceof NoteV1))
        throw new NockchainError("Unexpected input version");
      return note;
    }),
    {
      inputCount: result.selected.length,
      inputNicks: result.selectedTotal,
      paymentNicks,
      feeNicks: result.finalFee,
      changeNicks: result.refunds.reduce(
        (n, [, amount]) => addAmount(n, amount),
        0n,
      ),
      changeAddress: change,
      payments: reviewedPayments,
    },
    sender.publicBytes(),
  );
}
/** Consume the supplied notes using the same planner as automatic selection. */
export function prepareTransfer(
  sender: ExtendedKey,
  records: Iterable<UnspentNote>,
  payments: Iterable<Payment>,
  options: TransferOptions = {},
): PreparedTransfer {
  return transfer(sender, records, payments, options, true);
}
/** Select sufficient notes by amount, then Base58 name, with exact fee solving. */
export function selectTransfer(
  sender: ExtendedKey,
  records: Iterable<UnspentNote>,
  payments: Iterable<Payment>,
  options: TransferOptions = {},
): PreparedTransfer {
  return transfer(sender, records, payments, options, false);
}
