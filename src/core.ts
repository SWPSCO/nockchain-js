/** Bounded immutable based nouns, TIP5 and exact native amounts. */
import { LOOKUP, ROUND_CONSTANTS } from "./constants.js";

export const PRIME = 0xffffffff00000001n;
export const UINT64_MAX = (1n << 64n) - 1n;
export const MAX_NOUN_NODES = 1 << 20;
export const MAX_JAM_BYTES = 16 << 20;
export const NICKS_PER_NOCK = 65536n;
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MDS = [
  61402n,
  17845n,
  26798n,
  59689n,
  12021n,
  40901n,
  41351n,
  27521n,
  56951n,
  12034n,
  53865n,
  43244n,
  7454n,
  33823n,
  28750n,
  1108n,
];
const R = 0xffffffffn;
const R_INV = modPow(R, PRIME - 2n, PRIME);

export class NockchainError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NockchainError";
  }
}

export function uint(
  value: bigint,
  maximum = UINT64_MAX,
  label = "integer",
): bigint {
  if (typeof value !== "bigint" || value < 0n || value > maximum)
    throw new NockchainError(`Invalid ${label}`);
  return value;
}
export function count(value: number, maximum: number, label = "count"): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum)
    throw new NockchainError(`Invalid ${label}`);
  return value;
}
export function modPow(
  value: bigint,
  exponent: bigint,
  modulus: bigint,
): bigint {
  let result = 1n;
  for (; exponent > 0n; exponent >>= 1n, value = (value * value) % modulus) {
    if (exponent & 1n) result = (result * value) % modulus;
  }
  return result;
}

export type Noun = bigint | Cell;
/** Atoms remain exact bigint values; field overflow is rejected, never reduced. */
export function atom(value: bigint): bigint {
  return uint(value, PRIME - 1n, "noun atom");
}
function checkNode(value: Noun): void {
  if (!(value instanceof Cell)) atom(value);
}
/** Frozen cells may share children safely. JavaScript GC owns their lifetime. */
export class Cell {
  readonly head: Noun;
  readonly tail: Noun;
  constructor(head: Noun, tail: Noun) {
    checkNode(head);
    checkNode(tail);
    this.head = head;
    this.tail = tail;
    Object.freeze(this);
  }
}
export function nounTuple(...values: Noun[]): Noun {
  if (!values.length) return 0n;
  let result = values[values.length - 1];
  checkNode(result);
  for (let i = values.length - 2; i >= 0; i--)
    result = new Cell(values[i], result);
  return result;
}
export function nounList(...values: Noun[]): Noun {
  return nounTuple(...values, 0n);
}
export function nounEqual(a: Noun, b: Noun): boolean {
  const stack: [Noun, Noun][] = [[a, b]];
  const seen = new WeakMap<Cell, WeakSet<Cell>>();
  let nodes = 0;
  while (stack.length) {
    const [x, y] = stack.pop()!;
    if (x === y) continue;
    if (x instanceof Cell && y instanceof Cell) {
      let matches = seen.get(x);
      if (matches?.has(y)) continue;
      if (!matches) {
        matches = new WeakSet();
        seen.set(x, matches);
      }
      matches.add(y);
      if (++nodes > MAX_NOUN_NODES)
        throw new NockchainError("Noun equality exceeds node limit");
      stack.push([x.head, y.head], [x.tail, y.tail]);
    } else return false;
  }
  return true;
}
export function parts(noun: Noun, size: number): Noun[] {
  const result: Noun[] = [];
  for (let i = 1; i < size; i++) {
    if (!(noun instanceof Cell))
      throw new NockchainError("Malformed noun tuple");
    result.push(noun.head);
    noun = noun.tail;
  }
  result.push(noun);
  return result;
}
export function atomValue(noun: Noun): bigint {
  if (typeof noun !== "bigint")
    throw new NockchainError("Expected a noun atom");
  return atom(noun);
}
export function boundedNoun(
  noun: Noun,
  maximum = 65536,
  depthLimit = 256,
): void {
  const stack: [Noun, number][] = [[noun, 0]];
  let nodes = 0;
  while (stack.length) {
    const [current, depth] = stack.pop()!;
    if (++nodes > maximum || depth > depthLimit)
      throw new NockchainError("Noun exceeds inspection limits");
    if (current instanceof Cell)
      stack.push([current.head, depth + 1], [current.tail, depth + 1]);
    else atom(current);
  }
}
export function bigintBytes(value: bigint, size?: number): Uint8Array {
  if (value < 0n) throw new NockchainError("Negative byte integer");
  const result: number[] = [];
  for (; value; value >>= 8n) result.push(Number(value & 255n));
  if (size !== undefined) {
    if (result.length > size) throw new NockchainError("Byte integer overflow");
    while (result.length < size) result.push(0);
  }
  return Uint8Array.from(result.reverse());
}
export function bytesBigint(data: Uint8Array): bigint {
  let value = 0n;
  for (const byte of data) value = (value << 8n) | BigInt(byte);
  return value;
}
export function concatBytes(...values: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(
    values.reduce((sum, value) => sum + value.length, 0),
  );
  let offset = 0;
  for (const value of values) {
    out.set(value, offset);
    offset += value.length;
  }
  return out;
}
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
export function encodeBase58(data: Uint8Array): string {
  let zeros = 0,
    result = "",
    value = bytesBigint(data);
  while (zeros < data.length && data[zeros] === 0) zeros++;
  while (value) {
    result = ALPHABET[Number(value % 58n)] + result;
    value /= 58n;
  }
  return "1".repeat(zeros) + result;
}
export function decodeBase58(text: string): Uint8Array {
  let value = 0n;
  for (const char of text) {
    const index = ALPHABET.indexOf(char);
    if (index < 0) throw new NockchainError("Invalid Base58 encoding");
    value = value * 58n + BigInt(index);
  }
  let zeros = 0;
  while (zeros < text.length && text[zeros] === "1") zeros++;
  return concatBytes(new Uint8Array(zeros), bigintBytes(value));
}
export type Digest = readonly [bigint, bigint, bigint, bigint, bigint];
export function digest(values: Iterable<bigint>): Digest {
  const limbs = Array.from(values);
  if (limbs.length !== 5) throw new NockchainError("A digest has five limbs");
  limbs.forEach(atom);
  return Object.freeze(limbs) as unknown as Digest;
}
export function digestEqual(a: Digest, b: Digest): boolean {
  return a.every((value, i) => value === b[i]);
}
export function digestCompare(a: Digest, b: Digest): number {
  for (let i = 4; i >= 0; i--) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}
export function formatDigest(value: Digest): string {
  value = digest(value);
  let number = 0n;
  for (let i = 4; i >= 0; i--) number = number * PRIME + value[i];
  return encodeBase58(bigintBytes(number));
}
export function parseDigest(text: string): Digest {
  if (typeof text !== "string" || text.length < 1 || text.length > 55)
    throw new NockchainError("Invalid Nockchain digest");
  let value = bytesBigint(decodeBase58(text));
  const limbs: bigint[] = [];
  for (let i = 0; i < 5; i++) {
    limbs.push(value % PRIME);
    value /= PRIME;
  }
  const result = digest(limbs);
  if (value || formatDigest(result) !== text)
    throw new NockchainError("Noncanonical or overflowing digest");
  return result;
}
export function digestNoun(value: Digest): Noun {
  return nounTuple(...value);
}
export function nounDigest(value: Noun): Digest {
  return digest(parts(value, 5).map(atomValue));
}
function permute(state: bigint[]): void {
  for (let round = 0; round < 7; round++) {
    const values = state.map((value, i) => {
      if (i < 4) {
        let substituted = 0n;
        for (let j = 0; j < 8; j++)
          substituted |=
            BigInt(LOOKUP[Number((value >> BigInt(j * 8)) & 255n)]) <<
            BigInt(j * 8);
        return substituted % PRIME;
      }
      const square = (value * value) % PRIME;
      return (((((square * square) % PRIME) * square) % PRIME) * value) % PRIME;
    });
    for (let i = 0; i < 16; i++) {
      let value = ROUND_CONSTANTS[round * 16 + i] * R;
      for (let j = 0; j < 16; j++) value += MDS[(j - i + 16) % 16] * values[j];
      state[i] = value % PRIME;
    }
  }
}
/** Variable-length TIP5 with replace absorption. */
export function hashWords(words: Iterable<bigint>): Digest {
  const values = Array.from(words);
  values.forEach(atom);
  const state = Array<bigint>(16).fill(0n);
  let offset = 0;
  while (values.length - offset >= 10) {
    for (let i = 0; i < 10; i++) state[i] = (values[offset + i] * R) % PRIME;
    permute(state);
    offset += 10;
  }
  for (let i = 0; i < 10; i++) state[i] = 0n;
  for (let i = offset; i < values.length; i++)
    state[i - offset] = (values[i] * R) % PRIME;
  state[values.length - offset] = R;
  permute(state);
  return digest(state.slice(0, 5).map((value) => (value * R_INV) % PRIME));
}
export function hashCell(a: Digest, b: Digest): Digest {
  const state = [...a, ...b]
    .map((value) => (value * R) % PRIME)
    .concat(Array<bigint>(6).fill(R));
  permute(state);
  return digest(state.slice(0, 5).map((value) => (value * R_INV) % PRIME));
}
export function hashAtom(value: bigint): Digest {
  return hashWords([1n, value]);
}
export function foldHashes(...values: Digest[]): Digest {
  let result = values[values.length - 1];
  for (let i = values.length - 2; i >= 0; i--)
    result = hashCell(values[i], result);
  return result;
}
export function hashNoun(noun: Noun, maximum = MAX_NOUN_NODES): Digest {
  count(maximum, MAX_NOUN_NODES, "noun node limit");
  if (!maximum) throw new NockchainError("Invalid noun node limit");
  const stack: [Noun, boolean][] = [[noun, false]];
  const leaves: bigint[] = [],
    shape: bigint[] = [];
  let nodes = 0;
  while (stack.length) {
    const [current, afterHead] = stack.pop()!;
    if (afterHead) {
      shape.push(1n);
      stack.push([current, false]);
      continue;
    }
    if (++nodes > maximum)
      throw new NockchainError("Noun exceeds logical node limit");
    if (current instanceof Cell) {
      shape.push(0n);
      stack.push([current.tail, true], [current.head, false]);
    } else leaves.push(atom(current));
  }
  return hashWords([BigInt(leaves.length), ...leaves, ...shape]);
}
export function hashEach(noun: Noun): Digest {
  return noun instanceof Cell
    ? hashCell(hashEach(noun.head), hashEach(noun.tail))
    : hashAtom(noun);
}
export function leafCount(noun: Noun): number {
  const stack = [noun];
  let count = 0;
  while (stack.length) {
    const current = stack.pop()!;
    if (current instanceof Cell) stack.push(current.head, current.tail);
    else count++;
  }
  return count;
}
export function parseNocks(text: string): bigint {
  if (
    typeof text !== "string" ||
    text.length > 40 ||
    !/^[0-9]+(?:\.[0-9]{1,16})?$/.test(text)
  )
    throw new NockchainError("Invalid NOCK amount");
  const [whole, fraction = ""] = text.split(".");
  const numerator = BigInt(whole + fraction) * NICKS_PER_NOCK,
    denominator = 10n ** BigInt(fraction.length);
  if (numerator % denominator)
    throw new NockchainError("NOCK amount has sub-nick precision");
  return uint(numerator / denominator, UINT64_MAX, "NOCK amount");
}
export function formatNocks(nicks: bigint): string {
  uint(nicks);
  const whole = nicks / NICKS_PER_NOCK,
    remainder = nicks % NICKS_PER_NOCK;
  return remainder
    ? `${whole}.${(remainder * 152587890625n).toString().padStart(16, "0").replace(/0+$/, "")}`
    : whole.toString();
}
