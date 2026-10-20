import {
  NockchainError,
  parseDigest,
  formatDigest,
  digestEqual,
  nounEqual,
} from "./core.js";
import { cue, jam } from "./codec.js";
import { FeeParameters, ChainContext } from "./fee.js";
import { ExtendedKey } from "./keys.js";
import { LockV1, NoteName, NoteV1, newPKHLockV1 } from "./locks.js";
import { parseTransactionV1, TransactionV1 } from "./transaction.js";
import { PlannedOutput, plan } from "./planner.js";
import { SigningKeyLockMatcher } from "./lock-resolver.js";

export interface SigningPayment {
  readonly address: string;
  readonly amountNicks: string;
}
export interface SigningBundleV1 {
  readonly format: "nockchain-signing-bundle";
  readonly version: 1;
  readonly network: string;
  readonly tip: { readonly blockId: string; readonly height: string };
  readonly candidateHeight: string;
  readonly sourceAddress: string;
  readonly payments: readonly SigningPayment[];
  readonly rawTransaction: string;
  readonly inputs: readonly {
    readonly name: { readonly firstName: string; readonly lastName: string };
    readonly originPage: string;
    readonly amountNicks: string;
    readonly noteData: string;
  }[];
}
export interface SigningReviewV1 {
  readonly transactionId: string;
  readonly network: string;
  readonly tip: SigningBundleV1["tip"];
  readonly candidateHeight: string;
  readonly sourceAddress: string;
  readonly payments: readonly SigningPayment[];
  readonly changeNicks: string;
  readonly feeNicks: string;
  readonly minimumFeeNicks: string;
  readonly inputCount: number;
  readonly fullySigned: boolean;
}
function check(value: unknown, message: string): asserts value {
  if (!value) throw new NockchainError(message);
}
function object(value: unknown, fields: string): Record<string, unknown> {
  check(
    value !== null && typeof value === "object" && !Array.isArray(value),
    "Expected an object",
  );
  const allowed = fields.split(" ");
  check(
    Object.keys(value).every((key) => allowed.includes(key)),
    "Unexpected bundle field",
  );
  return value as Record<string, unknown>;
}
function integer(value: unknown): bigint {
  check(
    typeof value === "string" && /^(0|[1-9][0-9]{0,19})$/.test(value),
    "Expected an unsigned decimal integer",
  );
  const result = BigInt(value);
  check(result < 1n << 64n, "Integer exceeds u64");
  return result;
}
function address(value: unknown): string {
  check(
    typeof value === "string" && value.length > 0 && value.length <= 60,
    "Invalid digest",
  );
  check(formatDigest(parseDigest(value)) === value, "Noncanonical digest");
  return value;
}
function array(value: unknown): unknown[] {
  check(
    Array.isArray(value) && value.length > 0 && value.length <= 64,
    "Array count out of range",
  );
  return value;
}
function base64(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}
function bytes(value: unknown, maximum: number): Uint8Array {
  check(
    typeof value === "string" && value.length <= Math.ceil(maximum / 3) * 4,
    "Encoded data is too large",
  );
  let decoded: Uint8Array;
  try {
    decoded = Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
  } catch {
    throw new NockchainError("Invalid base64");
  }
  check(
    decoded.length > 0 &&
      decoded.length <= maximum &&
      base64(decoded) === value,
    "Expected bounded canonical base64",
  );
  return decoded;
}
function data(value: unknown) {
  const encoded = bytes(value, 65536),
    noun = cue(encoded);
  check(base64(jam(noun)) === value, "Noncanonical note-data JAM");
  return noun;
}

/** Validate a data-only bundle against its transaction; indexed context is not a chain proof. */
export function inspectSigningBundle(value: unknown): {
  readonly bundle: SigningBundleV1;
  readonly transaction: TransactionV1;
  readonly review: SigningReviewV1;
} {
  const input = object(
    value,
    "format version network tip candidateHeight sourceAddress payments rawTransaction inputs",
  );
  check(
    input.format === "nockchain-signing-bundle" && input.version === 1,
    "Unsupported signing bundle",
  );
  check(
    typeof input.network === "string" &&
      /^[a-z0-9][a-z0-9_-]{0,63}$/.test(input.network),
    "Invalid network",
  );
  const tip = object(input.tip, "blockId height"),
    tipHeight = integer(tip.height),
    height = integer(input.candidateHeight);
  address(tip.blockId);
  check(
    height === tipHeight + 1n,
    "Candidate height must follow the indexed tip",
  );
  const source = address(input.sourceAddress),
    sourceHash = parseDigest(source);
  const payments = array(input.payments).map((p) => {
    const payment = object(p, "address amountNicks"),
      amount = integer(payment.amountNicks);
    check(amount > 0n, "Payment must be positive");
    return {
      address: address(payment.address),
      amountNicks: amount.toString(),
    };
  });
  const notes = array(input.inputs).map((entry) => {
    const note = object(entry, "name originPage amountNicks noteData"),
      name = object(note.name, "firstName lastName");
    return new NoteV1({
      name: new NoteName(
        parseDigest(address(name.firstName)),
        parseDigest(address(name.lastName)),
      ),
      originPage: integer(note.originPage),
      nicks: integer(note.amountNicks),
      noteData: data(note.noteData),
    });
  });
  const encoded = bytes(input.rawTransaction, 262144);
  const transaction = parseTransactionV1(encoded, {
    fees: new FeeParameters({ height }),
  });
  check(
    base64(transaction.jam()) === input.rawTransaction,
    "Noncanonical transaction JAM",
  );
  transaction.validateInputs(notes, height);
  transaction.verifySignatures({ requireThreshold: false });
  const summary = transaction.summary();
  const planned = plan(
    {
      candidates: notes,
      selection: notes.map((note) => note.name),
      outputs: payments.map((payment) =>
        PlannedOutput.payment(
          parseDigest(payment.address),
          BigInt(payment.amountNicks),
        ),
      ),
      refund: PlannedOutput.payment(sourceHash, 0n),
      chain: ChainContext.atHeight(height),
    },
    new SigningKeyLockMatcher(sourceHash),
  );
  check(
    summary.feeNicks === planned.finalFee,
    "Bundle fee differs from the local plan",
  );
  const plannedSpends = new Map(
    planned.transaction
      .summary()
      .spends.map((spend) => [spend.name.key(), spend.signatureHash]),
  );
  for (const spend of summary.spends) {
    const expectedHash = plannedSpends.get(spend.name.key());
    check(
      expectedHash && digestEqual(spend.signatureHash, expectedHash),
      "Transaction differs from the local payment plan",
    );
  }
  const expected = new Map<
    string,
    { address: string; amount: bigint; lock: LockV1 }
  >();
  for (const payment of [...payments, { address: source, amountNicks: "0" }]) {
    const lock = newPKHLockV1(1, [parseDigest(payment.address)]),
      root = formatDigest(lock.root);
    const entry = expected.get(root) ?? {
      address: payment.address,
      amount: 0n,
      lock,
    };
    entry.amount += BigInt(payment.amountNicks);
    check(entry.amount < 1n << 64n, "Payment total overflow");
    expected.set(root, entry);
  }
  const actual = new Map<string, bigint>();
  for (const spend of summary.spends) {
    check(
      spend.proof !== null &&
        spend.lock instanceof LockV1 &&
        spend.lock.threshold === 1 &&
        spend.lock.authorizes(sourceHash) &&
        spend.outputs.length > 0,
      "Input is not controlled by the source address",
    );
    for (const output of spend.outputs) {
      const root = formatDigest(output.lockRoot),
        target = expected.get(root);
      check(
        target && nounEqual(output.noteData, target.lock.metadata()),
        "Undeclared output or unexpected output metadata",
      );
      actual.set(root, (actual.get(root) ?? 0n) + output.nicks);
    }
  }
  let change = 0n;
  for (const [root, target] of expected) {
    const amount = actual.get(root) ?? 0n;
    if (target.address === source) {
      check(amount >= target.amount, "Source payment amount mismatch");
      change = amount - target.amount;
    } else check(amount === target.amount, "Payment amount mismatch");
  }
  // Copy only the validated contract fields; callers cannot mutate the reviewed input.
  const bundle = JSON.parse(
    JSON.stringify({
      format: input.format,
      version: input.version,
      network: input.network,
      tip: { blockId: tip.blockId, height: tip.height },
      candidateHeight: input.candidateHeight,
      sourceAddress: source,
      payments,
      rawTransaction: input.rawTransaction,
      inputs: input.inputs,
    }),
  ) as SigningBundleV1;
  return {
    bundle,
    transaction,
    review: {
      transactionId: formatDigest(summary.id),
      network: bundle.network,
      tip: bundle.tip,
      candidateHeight: bundle.candidateHeight,
      sourceAddress: source,
      payments,
      changeNicks: change.toString(),
      feeNicks: summary.feeNicks.toString(),
      minimumFeeNicks: summary.minimumFeeNicks.toString(),
      inputCount: notes.length,
      fullySigned: summary.spends.every(
        (spend) => spend.signedKeys.length === spend.lock.threshold,
      ),
    },
  };
}

/** Revalidate before signing and return a bundle suitable for inspection or submission. */
export function signSigningBundle(
  value: unknown,
  key: ExtendedKey,
): SigningBundleV1 {
  const { bundle, transaction } = inspectSigningBundle(value);
  check(
    key.isPrivate &&
      digestEqual(
        parseDigest(key.address()),
        parseDigest(bundle.sourceAddress),
      ),
    "Signing key does not match source address",
  );
  const signed = transaction.sign(key);
  signed.verifySignatures();
  const result = { ...bundle, rawTransaction: base64(signed.jam()) };
  inspectSigningBundle(result);
  return result;
}
