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
  equalBytes,
  foldHashes,
  formatDigest,
  hashAtom,
  hashCell,
  hashNoun,
  leafCount,
  nounDigest,
  nounEqual,
  nounTuple,
  parts,
  uint,
} from "./core.js";
import type { Digest, Noun } from "./core.js";
import { cue, jam } from "./codec.js";
import { parsePoint } from "./curve.js";
import {
  metadataEntries,
  metadataHash,
  newTree,
  readTree,
  treeDigest,
  treeNoun,
  treePut,
} from "./tree.js";
import type { Tree } from "./tree.js";
import {
  ExtendedKey,
  Signature,
  publicKeyHash,
  publicNoun,
  verifyDigest,
} from "./keys.js";
import {
  LockV1,
  NoteName,
  NoteV1,
  noteFirstV1,
  parseCondition,
  timelockAllows,
} from "./locks.js";

export const MAX_TRANSFER_INPUTS = 64;
export const MAX_TRANSFER_OUTPUTS = 256;
export const MAX_NOTE_DATA_WORDS_V1 = 2048;
export function addAmount(a: bigint, b: bigint): bigint {
  return uint(a + b, undefined, "amount total");
}
export interface LockedPaymentV1 {
  readonly lock: LockV1;
  readonly nicks: bigint;
}
export interface LockedSpendPlanV1 {
  readonly note: NoteV1;
  readonly lock: LockV1;
  readonly outputs: readonly LockedPaymentV1[];
  readonly fee: bigint;
}
export class OutputV1 {
  readonly lockRoot: Digest;
  readonly noteData: Noun;
  readonly nicks: bigint;
  readonly parentHash: Digest;
  constructor(root: Digest, data: Noun, nicks: bigint, parent: Digest) {
    this.lockRoot = digest(root);
    this.noteData = data;
    this.nicks = atom(nicks);
    this.parentHash = digest(parent);
    Object.freeze(this);
  }
  /** Authenticate the policy in the metadata against the committed lock root. */
  lock(): LockV1 {
    const value = metadataEntries(this.noteData).get(0x6b636f6cn);
    if (value === undefined)
      throw new NockchainError("Output lock metadata is absent");
    const [tag, condition] = parts(value, 2);
    if (tag !== 0n)
      throw new NockchainError("Unsupported output lock metadata");
    const lock = parseCondition(condition);
    if (!digestEqual(lock.root, this.lockRoot))
      throw new NockchainError(
        "Output metadata does not authenticate its lock",
      );
    return lock;
  }
}
export interface SpendSummaryV1 {
  readonly name: NoteName;
  readonly lock: LockV1;
  readonly fee: bigint;
  readonly outputs: readonly OutputV1[];
  readonly signedKeys: readonly Digest[];
  readonly signatureHash: Digest;
}
export interface TransactionSummaryV1 {
  readonly id: Digest;
  readonly feeNicks: bigint;
  readonly outputNicks: bigint;
  readonly minimumFeeNicks: bigint;
  readonly spends: readonly SpendSummaryV1[];
}
interface SignedPKH {
  readonly pkh: Digest;
  readonly publicKey: Uint8Array;
  readonly signature: Signature;
}
interface Spend {
  readonly name: NoteName;
  readonly lock: LockV1;
  readonly fee: bigint;
  readonly seeds: Tree | null;
  readonly outputs: readonly OutputV1[];
  readonly signatures: readonly SignedPKH[];
}
function signatureHash(spend: Spend): Digest {
  return hashCell(treeDigest(spend.seeds, true), hashAtom(spend.fee));
}
function signatureTree(spend: Spend): Tree | null {
  let tree: Tree | null = null;
  for (const signed of spend.signatures) {
    const publicKey = publicNoun(parsePoint(signed.publicKey)),
      signature = signed.signature.noun();
    const hash = hashCell(
      signed.pkh,
      hashCell(hashNoun(publicKey), hashNoun(signature)),
    );
    tree = treePut(
      tree,
      newTree(
        digestNoun(signed.pkh),
        new Cell(publicKey, signature),
        hash,
        hash,
        true,
      ),
    );
  }
  return tree;
}
function witness(spend: Spend): Noun {
  return nounTuple(spend.lock.proof(), treeNoun(signatureTree(spend)), 0n, 0n);
}
function spendHash(spend: Spend): Digest {
  const hash = foldHashes(
    spend.lock.proofHash(),
    treeDigest(signatureTree(spend)),
    hashAtom(0n),
    hashAtom(0n),
  );
  return foldHashes(
    hashAtom(1n),
    hash,
    treeDigest(spend.seeds),
    hashAtom(spend.fee),
  );
}
function spendNoun(spend: Spend): Noun {
  return nounTuple(1n, witness(spend), treeNoun(spend.seeds), spend.fee);
}
function minimumFee(spends: readonly Spend[]): bigint {
  let witnessWords = 0;
  const metadata = new Map<string, Map<bigint, Noun>>();
  for (const spend of spends) {
    witnessWords +=
      leafCount(spend.lock.proof()) +
      Math.max(spend.signatures.length, spend.lock.threshold) * 35 +
      3;
    for (const output of spend.outputs) {
      const root = formatDigest(output.lockRoot);
      let entries = metadata.get(root);
      if (!entries) {
        entries = new Map();
        metadata.set(root, entries);
      }
      for (const [tag, value] of metadataEntries(output.noteData)) {
        const old = entries.get(tag);
        if (old !== undefined && !nounEqual(old, value))
          throw new NockchainError("Conflicting output metadata for one lock");
        entries.set(tag, value);
      }
    }
  }
  let dataWords = 0;
  for (const entries of metadata.values()) {
    let words = 1;
    for (const value of entries.values()) words += 1 + leafCount(value);
    if (words > MAX_NOTE_DATA_WORDS_V1)
      throw new NockchainError("Output metadata exceeds consensus word limit");
    dataWords += words;
  }
  const fee = BigInt(dataWords) * 16384n + BigInt(witnessWords) * 4096n;
  return fee > 256n ? fee : 256n;
}
const TX_TOKEN = Symbol("transaction");

/** Immutable unsigned, partially signed or signed transaction. */
export class TransactionV1 {
  readonly #spends: readonly Spend[];
  readonly #raw: Noun;
  readonly id: Digest;
  /** @internal Use prepareTransactionV1() or parseTransactionV1(). */
  constructor(token: symbol, spends: readonly Spend[], raw: Noun, id: Digest) {
    if (token !== TX_TOKEN)
      throw new NockchainError(
        "Use prepareTransactionV1 or parseTransactionV1",
      );
    this.#spends = Object.freeze(
      spends.map((spend) =>
        Object.freeze({
          ...spend,
          outputs: Object.freeze([...spend.outputs]),
          signatures: Object.freeze([...spend.signatures]),
        }),
      ),
    );
    this.#raw = raw;
    this.id = id;
    Object.freeze(this);
  }
  noun(): Noun {
    return this.#raw;
  }
  jam(): Uint8Array {
    return jam(this.#raw);
  }
  summary(): TransactionSummaryV1 {
    let feeNicks = 0n,
      outputNicks = 0n;
    const spends: SpendSummaryV1[] = [];
    for (const spend of this.#spends) {
      feeNicks = addAmount(feeNicks, spend.fee);
      for (const output of spend.outputs)
        outputNicks = addAmount(outputNicks, output.nicks);
      const signed = new Set(
        spend.signatures.map((signature) => formatDigest(signature.pkh)),
      );
      spends.push(
        Object.freeze({
          name: spend.name,
          lock: spend.lock,
          fee: spend.fee,
          outputs: spend.outputs,
          signedKeys: Object.freeze(
            spend.lock.keys.filter((key) => signed.has(formatDigest(key))),
          ),
          signatureHash: signatureHash(spend),
        }),
      );
    }
    return Object.freeze({
      id: this.id,
      feeNicks,
      outputNicks,
      minimumFeeNicks: minimumFee(this.#spends),
      spends: Object.freeze(spends),
    });
  }
  #verify(requireThreshold: boolean): void {
    for (const spend of this.#spends) {
      const count = spend.signatures.length;
      if (
        count > spend.lock.threshold ||
        (requireThreshold && count !== spend.lock.threshold)
      )
        throw new NockchainError("Signature count must equal the threshold");
      for (const signature of spend.signatures) {
        const point = parsePoint(signature.publicKey);
        if (
          !digestEqual(publicKeyHash(point), signature.pkh) ||
          !spend.lock.authorizes(signature.pkh) ||
          !verifyDigest(
            signature.publicKey,
            signatureHash(spend),
            signature.signature,
          )
        )
          throw new NockchainError("Invalid or unauthorized signature");
      }
    }
  }
  /** Check exact thresholds, every signature, authorization and minimum fee. */
  verifySignatures(): void {
    this.#verify(true);
    const review = this.summary();
    if (review.feeNicks < review.minimumFeeNicks)
      throw new NockchainError("Fee below minimum");
  }
  sign(key: ExtendedKey): TransactionV1 {
    if (!key.isPrivate)
      throw new NockchainError("Private signing key required");
    this.#verify(false);
    const publicKey = key.publicBytes(),
      pkh = publicKeyHash(parsePoint(publicKey)),
      identity = formatDigest(pkh);
    let matched = false;
    const spends = this.#spends.map((spend) => {
      const signatures = new Map(
        spend.signatures.map((signature) => [
          formatDigest(signature.pkh),
          signature,
        ]),
      );
      if (spend.lock.authorizes(pkh)) {
        matched = true;
        if (
          !signatures.has(identity) &&
          signatures.size >= spend.lock.threshold
        )
          throw new NockchainError("Input already has its required signatures");
        signatures.set(identity, {
          pkh,
          publicKey,
          signature: key.signDigest(signatureHash(spend)),
        });
      }
      return { ...spend, signatures: [...signatures.values()] };
    });
    if (!matched)
      throw new NockchainError("Key is not authorized by any input");
    const result = assemble(spends),
      review = result.summary();
    if (review.feeNicks < review.minimumFeeNicks)
      throw new NockchainError("Fee cannot cover additional signatures");
    return result;
  }
  mergeSignatures(other: TransactionV1): TransactionV1 {
    this.#verify(false);
    other.#verify(false);
    if (this.#spends.length !== other.#spends.length)
      throw new NockchainError("Different transaction plans");
    const byName = new Map(
      other.#spends.map((spend) => [spend.name.key(), spend]),
    );
    const spends = this.#spends.map((spend) => {
      const alternate = byName.get(spend.name.key());
      if (
        !alternate ||
        alternate.fee !== spend.fee ||
        !nounEqual(alternate.lock.condition, spend.lock.condition) ||
        !nounEqual(treeNoun(alternate.seeds), treeNoun(spend.seeds))
      )
        throw new NockchainError("Different transaction plans");
      const signatures = new Map(
        spend.signatures.map((signature) => [
          formatDigest(signature.pkh),
          signature,
        ]),
      );
      for (const signature of alternate.signatures) {
        const identity = formatDigest(signature.pkh),
          old = signatures.get(identity);
        if (
          old &&
          (!equalBytes(old.publicKey, signature.publicKey) ||
            !nounEqual(old.signature.noun(), signature.signature.noun()))
        )
          throw new NockchainError("Conflicting signature");
        signatures.set(identity, signature);
      }
      if (signatures.size > spend.lock.threshold)
        throw new NockchainError("Merged signatures exceed the threshold");
      return { ...spend, signatures: [...signatures.values()] };
    });
    const result = assemble(spends),
      review = result.summary();
    if (review.feeNicks < review.minimumFeeNicks)
      throw new NockchainError("Fee cannot cover merged signatures");
    return result;
  }
  /** Applications authenticate supplied records against canonical chain state. */
  validateInputs(records: Iterable<NoteV1>, height: bigint): void {
    atom(height);
    const notes = Array.from(records);
    if (notes.length !== this.#spends.length)
      throw new NockchainError("Input record count differs from transaction");
    const byName = new Map(notes.map((note) => [note.name.key(), note]));
    if (byName.size !== notes.length)
      throw new NockchainError("Duplicate input record");
    for (const spend of this.#spends) {
      const note = byName.get(spend.name.key());
      if (!note) throw new NockchainError("Missing input record");
      const parent = note.hash();
      if (
        note.originPage > height ||
        (spend.lock.timelock &&
          !timelockAllows(spend.lock.timelock, height, note.originPage))
      )
        throw new NockchainError("Input timelock or origin is not satisfied");
      let total = spend.fee;
      for (const output of spend.outputs) {
        if (!digestEqual(output.parentHash, parent))
          throw new NockchainError("Output parent does not match input note");
        total = addAmount(total, output.nicks);
      }
      if (total !== note.nicks)
        throw new NockchainError("Input value differs from outputs plus fee");
    }
  }
}
function assemble(spends: readonly Spend[]): TransactionV1 {
  if (!spends.length || spends.length > MAX_TRANSFER_INPUTS)
    throw new NockchainError("Input count out of range");
  if (
    spends.reduce((sum, spend) => sum + spend.outputs.length, 0) >
    MAX_TRANSFER_OUTPUTS
  )
    throw new NockchainError("Output count out of range");
  let tree: Tree | null = null;
  for (const spend of spends) {
    const hash = hashCell(spend.name.hash(), spendHash(spend));
    tree = treePut(
      tree,
      newTree(spend.name.noun(), spendNoun(spend), hash, hash, true),
    );
  }
  const id = hashCell(hashAtom(1n), treeDigest(tree)),
    raw = nounTuple(1n, digestNoun(id), treeNoun(tree));
  boundedNoun(raw);
  const result = new TransactionV1(TX_TOKEN, spends, raw, id);
  result.summary();
  return result;
}
export function prepareTransactionV1(
  plans: Iterable<LockedSpendPlanV1>,
): TransactionV1 {
  const list = Array.from(plans);
  if (!list.length || list.length > MAX_TRANSFER_INPUTS)
    throw new NockchainError("Input count out of range");
  const seen = new Set<string>(),
    spends: Spend[] = [];
  for (const plan of list) {
    if (!(plan.note instanceof NoteV1) || !(plan.lock instanceof LockV1))
      throw new NockchainError("Invalid input plan");
    const parent = plan.note.hash();
    atom(plan.fee);
    if (
      !digestEqual(plan.note.name.first, noteFirstV1(plan.lock.root)) ||
      seen.has(plan.note.name.key()) ||
      !plan.outputs.length
    )
      throw new NockchainError("Invalid, duplicate, or lock-mismatched input");
    seen.add(plan.note.name.key());
    const roots = new Set<string>(),
      outputs: OutputV1[] = [];
    let seeds: Tree | null = null,
      total = plan.fee;
    for (const output of plan.outputs) {
      if (!(output.lock instanceof LockV1) || atom(output.nicks) === 0n)
        throw new NockchainError("Invalid output");
      const identity = formatDigest(output.lock.root);
      if (roots.has(identity))
        throw new NockchainError("Duplicate output lock");
      roots.add(identity);
      total = addAmount(total, output.nicks);
      const metadata = output.lock.metadata();
      const regular = foldHashes(
        output.lock.root,
        metadataHash(metadata),
        hashAtom(output.nicks),
        parent,
      );
      const seed = nounTuple(
        0n,
        digestNoun(output.lock.root),
        metadata,
        output.nicks,
        digestNoun(parent),
      );
      seeds = treePut(
        seeds,
        newTree(seed, 0n, regular, hashCell(hashAtom(0n), regular), false),
      );
      outputs.push(
        new OutputV1(output.lock.root, metadata, output.nicks, parent),
      );
    }
    if (total !== plan.note.nicks)
      throw new NockchainError("Input value differs from outputs plus fee");
    spends.push({
      name: plan.note.name,
      lock: plan.lock,
      fee: plan.fee,
      seeds,
      outputs,
      signatures: [],
    });
  }
  const transaction = assemble(spends),
    review = transaction.summary();
  if (review.feeNicks < review.minimumFeeNicks)
    throw new NockchainError(
      `Fee below minimum ${review.minimumFeeNicks} nicks`,
    );
  return transaction;
}
export function minimumTransactionFeeV1(
  inputLocks: Iterable<LockV1>,
  outputLocks: Iterable<LockV1>,
): bigint {
  const inputs = Array.from(inputLocks),
    outputs = Array.from(outputLocks);
  if (
    !inputs.length ||
    inputs.length > MAX_TRANSFER_INPUTS ||
    !outputs.length ||
    outputs.length > MAX_TRANSFER_OUTPUTS
  )
    throw new NockchainError("Transaction size out of range");
  if (![...inputs, ...outputs].every((lock) => lock instanceof LockV1))
    throw new NockchainError("Invalid lock");
  const zero = digest([0n, 0n, 0n, 0n, 0n]);
  const spends: Spend[] = inputs.map((lock) => ({
    name: new NoteName(zero, zero),
    lock,
    fee: 0n,
    seeds: null,
    outputs: [],
    signatures: [],
  }));
  spends[0] = {
    ...spends[0],
    outputs: outputs.map(
      (lock) => new OutputV1(lock.root, lock.metadata(), 0n, zero),
    ),
  };
  return minimumFee(spends);
}
function parsePublic(noun: Noun): Uint8Array {
  const [x, y, marker] = parts(noun, 3);
  if (marker !== 1n) throw new NockchainError("Invalid public point marker");
  const encoded = concatBytes(
    new Uint8Array([1]),
    ...[y, x].flatMap((coordinate) =>
      parts(coordinate, 6)
        .reverse()
        .map((value) => bigintBytes(atomValue(value), 8)),
    ),
  );
  parsePoint(encoded);
  return encoded;
}
function parseSignature(noun: Noun): Signature {
  const [challenge, response] = parts(noun, 2);
  const result = new Signature(
    parts(challenge, 8).map(atomValue),
    parts(response, 8).map(atomValue),
  );
  if (!result.valid()) throw new NockchainError("Invalid signature scalar");
  return result;
}
/** Parse supported canonical V1 structure and embedded ID; verification is explicit. */
export function parseTransactionV1(data: Uint8Array): TransactionV1 {
  const raw = cue(data);
  boundedNoun(raw);
  const [version, embedded, spendMap] = parts(raw, 3);
  if (version !== 1n)
    throw new NockchainError("Unsupported transaction version");
  const id = nounDigest(embedded),
    spends: Spend[] = [];
  readTree(spendMap, true, MAX_TRANSFER_INPUTS, (key, value) => {
    const [first, last, terminator] = parts(key, 3);
    if (terminator !== 0n) throw new NockchainError("Invalid note name");
    const name = new NoteName(nounDigest(first), nounDigest(last));
    const [version, witness, seedsNoun, fee] = parts(value, 4);
    if (version !== 1n) throw new NockchainError("Unsupported spend version");
    const [proof, signatureMap, hax, time] = parts(witness, 4);
    if (hax !== 0n || time !== 0n)
      throw new NockchainError("Unsupported witness");
    const [tag, condition, axis] = parts(proof, 4);
    if (tag !== 0x6c6c7566n || axis !== 1n)
      throw new NockchainError("Unsupported lock proof");
    const lock = parseCondition(condition);
    if (!nounEqual(proof, lock.proof()))
      throw new NockchainError("Lock proof does not match its root");
    if (!digestEqual(name.first, noteFirstV1(lock.root)))
      throw new NockchainError("Note name does not bind input lock");
    const signatures: SignedPKH[] = [],
      outputs: OutputV1[] = [];
    readTree(signatureMap, true, 32, (key, value) => {
      const pkh = nounDigest(key),
        [publicKey, signature] = parts(value, 2);
      const encoded = parsePublic(publicKey),
        sig = parseSignature(signature);
      if (!digestEqual(hashNoun(publicKey), pkh) || !lock.authorizes(pkh))
        throw new NockchainError("Unauthorized signature key");
      signatures.push({ pkh, publicKey: encoded, signature: sig });
      const hash = hashCell(
        pkh,
        hashCell(hashNoun(publicKey), hashNoun(signature)),
      );
      return [hash, hash];
    });
    if (seedsNoun === 0n)
      throw new NockchainError("Each input requires an output seed");
    const seeds = readTree(seedsNoun, false, MAX_TRANSFER_OUTPUTS, (key) => {
      const [source, rootNoun, metadata, value, parentNoun] = parts(key, 5);
      if (source !== 0n)
        throw new NockchainError("Unsupported source-constrained output");
      const root = nounDigest(rootNoun),
        parent = nounDigest(parentNoun),
        amount = atomValue(value);
      if (amount === 0n) throw new NockchainError("Zero output seed");
      const hash = foldHashes(
        root,
        metadataHash(metadata),
        hashAtom(amount),
        parent,
      );
      outputs.push(new OutputV1(root, metadata, amount, parent));
      return [hash, hashCell(hashAtom(0n), hash)];
    });
    const spend = {
      name,
      lock,
      fee: atomValue(fee),
      seeds,
      outputs,
      signatures,
    };
    spends.push(spend);
    const hash = hashCell(name.hash(), spendHash(spend));
    return [hash, hash];
  });
  const transaction = assemble(spends);
  if (!digestEqual(transaction.id, id))
    throw new NockchainError("Transaction ID does not match contents");
  return transaction;
}
