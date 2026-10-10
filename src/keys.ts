import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { randomBytes } from "@noble/hashes/utils.js";
import {
  Cell,
  NockchainError,
  PRIME,
  bigintBytes,
  bytesBigint,
  concatBytes,
  count,
  decodeBase58,
  digest,
  encodeBase58,
  equalBytes,
  formatDigest,
  hashAtom,
  hashCell,
  hashNoun,
  hashWords,
  nounTuple,
  uint,
} from "./core.js";
import type { Digest, Noun } from "./core.js";
import { GENERATOR, ORDER, Point, parsePoint } from "./curve.js";

const INSPECT = Symbol.for("nodejs.util.inspect.custom");
const KEY_TOKEN = Symbol("key");
const encoder = new TextEncoder();
export function publicNoun(point: Point): Noun {
  const p = point.affine();
  return nounTuple(nounTuple(...p.x), nounTuple(...p.y), 1n);
}
export function publicKeyHash(point: Point): Digest {
  return hashNoun(publicNoun(point));
}
export function lockRoot(pkh: Digest): Digest {
  pkh = digest(pkh);
  const nil = hashAtom(0n),
    tree = hashCell(pkh, hashCell(nil, nil));
  return hashCell(
    hashCell(hashAtom(0x686b70n), hashCell(hashAtom(1n), tree)),
    nil,
  );
}
function checksum(data: Uint8Array): Uint8Array {
  return sha256(sha256(data)).slice(0, 4);
}
function limbs(value: bigint): readonly bigint[] {
  return Object.freeze(
    Array.from(
      { length: 8 },
      (_, i) => (value >> BigInt(32 * i)) & 0xffffffffn,
    ),
  );
}
function scalar(values: readonly bigint[]): bigint {
  return values.reduce(
    (total, value, i) => total + (value << BigInt(32 * i)),
    0n,
  );
}
function digestScalar(value: Digest): bigint {
  return (
    value
      .slice(0, 4)
      .reduce((total, limb, i) => total + limb * PRIME ** BigInt(i), 0n) % ORDER
  );
}
function pointWords(point: Point): bigint[] {
  const p = point.affine();
  return [...p.x, ...p.y];
}

export class Signature {
  readonly challenge: readonly bigint[];
  readonly response: readonly bigint[];
  constructor(challenge: Iterable<bigint>, response: Iterable<bigint>) {
    this.challenge = Object.freeze(Array.from(challenge));
    this.response = Object.freeze(Array.from(response));
    for (const values of [this.challenge, this.response]) {
      if (values.length !== 8)
        throw new NockchainError("Signature scalar requires eight limbs");
      values.forEach((value) => uint(value, 0xffffffffn, "signature limb"));
    }
    Object.freeze(this);
  }
  noun(): Noun {
    return new Cell(nounTuple(...this.challenge), nounTuple(...this.response));
  }
  /** Scalar ranges are checked separately so callers can inspect invalid signatures. */
  valid(): boolean {
    return [scalar(this.challenge), scalar(this.response)].every(
      (value) => value > 0n && value < ORDER,
    );
  }
}

/** Immutable SLIP-10 key. Only zprv() explicitly exports private authority. */
export class ExtendedKey {
  readonly #secret: Uint8Array | null;
  readonly #pub: Point;
  readonly #chain: Uint8Array;
  readonly #depth: number;
  readonly #index: number;
  readonly #parent: Uint8Array;
  /** @internal Use master(), generate(), or parseExtendedKey(). */
  constructor(
    token: symbol,
    secret: Uint8Array | null,
    pub: Point,
    chain: Uint8Array,
    depth = 0,
    index = 0,
    parent: Uint8Array = new Uint8Array(4),
  ) {
    if (token !== KEY_TOKEN)
      throw new NockchainError("Use master or parseExtendedKey");
    this.#secret = secret?.slice() ?? null;
    this.#pub = pub;
    this.#chain = chain.slice();
    this.#depth = depth;
    this.#index = index;
    this.#parent = parent.slice();
    Object.freeze(this);
  }
  get isPrivate(): boolean {
    return this.#secret !== null;
  }
  toString(): string {
    return this.isPrivate
      ? "Nockchain key (private)"
      : "Nockchain key (public)";
  }
  toJSON(): string {
    return this.toString();
  }
  [INSPECT](): string {
    return this.toString();
  }
  public(): ExtendedKey {
    return new ExtendedKey(
      KEY_TOKEN,
      null,
      this.#pub,
      this.#chain,
      this.#depth,
      this.#index,
      this.#parent,
    );
  }
  publicBytes(): Uint8Array {
    return this.#pub.toBytes();
  }
  address(): string {
    return formatDigest(publicKeyHash(this.#pub));
  }
  lockAddress(): string {
    return formatDigest(lockRoot(publicKeyHash(this.#pub)));
  }
  child(index: number): ExtendedKey {
    count(index, 0xffffffff, "child index");
    if (this.#depth === 255)
      throw new NockchainError("Derivation depth exceeds 255");
    const encodedIndex = bigintBytes(BigInt(index), 4);
    let data: Uint8Array;
    if (index >= 2 ** 31) {
      if (!this.#secret)
        throw new NockchainError("Hardened child requires private key");
      data = concatBytes(new Uint8Array([0]), this.#secret);
    } else data = this.publicBytes();
    data = concatBytes(data, encodedIndex);
    for (let retry = 0; retry < 1024; retry++) {
      const material = hmac(sha512, this.#chain, data);
      let value = bytesBigint(material.subarray(0, 32));
      if (value > 0n && value < ORDER) {
        let secret: Uint8Array | null = null,
          point: Point;
        if (this.#secret) {
          value = (value + bytesBigint(this.#secret)) % ORDER;
          point = GENERATOR.times(value).affine();
          secret = bigintBytes(value, 32);
        } else point = this.#pub.plus(GENERATOR.times(value)).affine();
        if (!point.infinity) {
          const fingerprint = bigintBytes(
            hashWords(pointWords(this.#pub))[0],
            8,
          ).slice(0, 4);
          return new ExtendedKey(
            KEY_TOKEN,
            secret,
            point,
            material.slice(32),
            this.#depth + 1,
            index,
            fingerprint,
          );
        }
      }
      data = concatBytes(
        new Uint8Array([1]),
        material.subarray(32),
        encodedIndex,
      );
    }
    throw new NockchainError("Child derivation failed");
  }
  /** Follow m/... relative to this key; apostrophes harden indices. */
  derive(path: string): ExtendedKey {
    if (typeof path !== "string" || path.length > 4096)
      throw new NockchainError("Invalid derivation path");
    const components = path.split("/");
    if (components[0] !== "m")
      throw new NockchainError("Derivation path must begin with m");
    let result: ExtendedKey = this;
    for (const component of components.slice(1)) {
      if (!/^(0|[1-9][0-9]*)'?$/.test(component))
        throw new NockchainError("Invalid derivation index");
      const hard = component.endsWith("'"),
        value = Number(hard ? component.slice(0, -1) : component);
      count(value, 2 ** 31 - 1, "derivation index");
      result = result.child(value + (hard ? 2 ** 31 : 0));
    }
    return result;
  }
  #serialize(privateKey: boolean): string {
    let prefix = 0x0c0ebb09n,
      data = this.publicBytes();
    if (privateKey) {
      if (!this.#secret) throw new NockchainError("Private key is unavailable");
      prefix = 0x01106331n;
      data = concatBytes(new Uint8Array([0]), this.#secret);
    }
    const payload = concatBytes(
      bigintBytes(prefix, 4),
      new Uint8Array([1, this.#depth]),
      this.#parent,
      bigintBytes(BigInt(this.#index), 4),
      this.#chain,
      data,
    );
    return encodeBase58(concatBytes(payload, checksum(payload)));
  }
  zpub(): string {
    return this.#serialize(false);
  }
  zprv(): string {
    return this.#serialize(true);
  }
  /** Deterministic secret-bound V1 Schnorr; variable-time, intended for offline tools. */
  signDigest(message: Digest): Signature {
    message = digest(message);
    if (!this.#secret) throw new NockchainError("Private signing key required");
    const secret = bytesBigint(this.#secret);
    const nonce = digestScalar(
      hashWords([...pointWords(this.#pub), ...message, ...limbs(secret)]),
    );
    if (!nonce) throw new NockchainError("Zero signing nonce");
    const challenge = digestScalar(
      hashWords([
        ...pointWords(GENERATOR.times(nonce)),
        ...pointWords(this.#pub),
        ...message,
      ]),
    );
    const response = (nonce + challenge * secret) % ORDER;
    if (!challenge || !response)
      throw new NockchainError("Zero signature scalar");
    return new Signature(limbs(challenge), limbs(response));
  }
}

export function master(seed: Uint8Array): ExtendedKey {
  if (!(seed instanceof Uint8Array) || seed.length !== 64)
    throw new NockchainError("Nockchain seed must contain 64 bytes");
  const salt = encoder.encode("Nockchain seed");
  let material = hmac(sha512, salt, seed);
  for (let retry = 0; retry < 1024; retry++) {
    const value = bytesBigint(material.subarray(0, 32));
    if (value > 0n && value < ORDER)
      return new ExtendedKey(
        KEY_TOKEN,
        material.slice(0, 32),
        GENERATOR.times(value).affine(),
        material.slice(32),
      );
    material = hmac(sha512, salt, material);
  }
  throw new NockchainError("Master derivation failed");
}
export function generate(): ExtendedKey {
  return master(randomBytes(64));
}
export function parseExtendedKey(text: string): ExtendedKey {
  if (typeof text !== "string" || !text.length || text.length > 210)
    throw new NockchainError("Invalid extended key length");
  const encoded = decodeBase58(text);
  if (encoded.length !== 83 && encoded.length !== 147)
    throw new NockchainError("Invalid extended key length");
  const payload = encoded.slice(0, -4);
  if (
    encodeBase58(encoded) !== text ||
    !equalBytes(encoded.slice(-4), checksum(payload)) ||
    payload[4] !== 1
  )
    throw new NockchainError("Invalid V1 extended key");
  const prefix = bytesBigint(payload.subarray(0, 4)),
    depth = payload[5],
    parent = payload.slice(6, 10);
  const index = Number(bytesBigint(payload.subarray(10, 14))),
    chain = payload.slice(14, 46);
  if (!depth && (index || parent.some((value) => value !== 0)))
    throw new NockchainError("Invalid master metadata");
  let secret: Uint8Array | null = null,
    point: Point;
  if (prefix === 0x01106331n && payload.length === 79 && payload[46] === 0) {
    secret = payload.slice(47);
    const value = bytesBigint(secret);
    if (value <= 0n || value >= ORDER)
      throw new NockchainError("Invalid private scalar");
    point = GENERATOR.times(value).affine();
  } else if (prefix === 0x0c0ebb09n && payload.length === 143)
    point = parsePoint(payload.slice(46));
  else throw new NockchainError("Invalid extended key type");
  return new ExtendedKey(KEY_TOKEN, secret, point, chain, depth, index, parent);
}
export function parsePublicKey(text: string): ExtendedKey {
  const key = parseExtendedKey(text);
  if (key.isPrivate)
    throw new NockchainError("Watch-only configuration requires a zpub");
  return key;
}
export function verifyDigest(
  publicKey: Uint8Array,
  message: Digest,
  signature: Signature,
): boolean {
  try {
    message = digest(message);
    if (!(signature instanceof Signature) || !signature.valid()) return false;
    const point = parsePoint(publicKey),
      challenge = scalar(signature.challenge),
      response = scalar(signature.response);
    const r = GENERATOR.times(response)
      .plus(point.times(ORDER - challenge))
      .affine();
    return (
      !r.infinity &&
      digestScalar(
        hashWords([...pointWords(r), ...pointWords(point), ...message]),
      ) === challenge
    );
  } catch (error) {
    if (
      error instanceof NockchainError ||
      error instanceof TypeError ||
      error instanceof RangeError
    )
      return false;
    throw error;
  }
}
export interface ReceiveAddress {
  readonly index: number;
  readonly address: string;
  readonly lockRoot: string;
}
export function deriveReceiveAddress(
  zpub: string,
  index: number,
): ReceiveAddress {
  const child = parsePublicKey(zpub).child(index);
  return Object.freeze({
    index,
    address: child.address(),
    lockRoot: child.lockAddress(),
  });
}
