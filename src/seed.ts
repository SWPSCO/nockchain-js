import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { NockchainError, bigintBytes, bytesBigint } from "./core.js";
import { ExtendedKey, master } from "./keys.js";
import { WORDS } from "./english.js";

const INDEX = new Map(WORDS.map((word, i) => [word, i]));
const encoder = new TextEncoder();
const INSPECT = Symbol.for("nodejs.util.inspect.custom");

export class RecoveryPhrase {
  readonly #words: string;
  constructor(words: string) {
    this.#words = words;
    Object.freeze(this);
  }
  /** Explicitly export the recovery secret for an offline backup. */
  words(): string {
    return this.#words;
  }
  toString(): string {
    return "Nockchain recovery phrase (redacted)";
  }
  toJSON(): string {
    return this.toString();
  }
  [INSPECT](): string {
    return this.toString();
  }
}
export class Seed {
  readonly #data: Uint8Array;
  constructor(data: Uint8Array) {
    if (!(data instanceof Uint8Array) || data.length !== 64)
      throw new NockchainError("Seed must contain 64 bytes");
    this.#data = data.slice();
    Object.freeze(this);
  }
  /** Explicitly export a copy of the raw spending seed. */
  toBytes(): Uint8Array {
    return this.#data.slice();
  }
  key(): ExtendedKey {
    return master(this.#data);
  }
  toString(): string {
    return "Nockchain seed (redacted)";
  }
  toJSON(): string {
    return this.toString();
  }
  [INSPECT](): string {
    return this.toString();
  }
}
export function generateSeed(): Seed {
  return new Seed(randomBytes(64));
}
export function mnemonicFromEntropy(entropy: Uint8Array): RecoveryPhrase {
  if (
    !(entropy instanceof Uint8Array) ||
    ![16, 20, 24, 28, 32].includes(entropy.length)
  )
    throw new NockchainError(
      "Entropy must be 128 to 256 bits in 32-bit increments",
    );
  const checksumBits = entropy.length / 4;
  const bits =
    (bytesBigint(entropy) << BigInt(checksumBits)) |
    BigInt(sha256(entropy)[0] >> (8 - checksumBits));
  const count = (entropy.length * 8 + checksumBits) / 11;
  const words: string[] = [];
  for (let i = count - 1; i >= 0; i--)
    words.push(WORDS[Number((bits >> BigInt(11 * i)) & 2047n)]);
  return new RecoveryPhrase(words.join(" "));
}
export function generateMnemonic(): RecoveryPhrase {
  return mnemonicFromEntropy(randomBytes(32));
}
export function seedFromMnemonic(phrase: string, passphrase = ""): Seed {
  if (
    typeof phrase !== "string" ||
    typeof passphrase !== "string" ||
    encoder.encode(phrase).length > 1024 ||
    encoder.encode(passphrase).length > 4096
  )
    throw new NockchainError("Invalid or oversized mnemonic/passphrase");
  const words = phrase.normalize("NFKD").trim().split(/\s+/u);
  if (![12, 15, 18, 21, 24].includes(words.length))
    throw new NockchainError("Invalid BIP39 word count");
  let bits = 0n;
  for (const word of words) {
    const index = INDEX.get(word);
    if (index === undefined)
      throw new NockchainError("Invalid English BIP39 word");
    bits = (bits << 11n) | BigInt(index);
  }
  const entropySize = (words.length * 11 * 32) / 33 / 8,
    checksumBits = entropySize / 4;
  const entropy = bigintBytes(bits >> BigInt(checksumBits), entropySize);
  if (
    (bits & ((1n << BigInt(checksumBits)) - 1n)) !==
    BigInt(sha256(entropy)[0] >> (8 - checksumBits))
  )
    throw new NockchainError("Invalid BIP39 checksum");
  return new Seed(
    pbkdf2(
      sha512,
      encoder.encode(words.join(" ")),
      encoder.encode("mnemonic" + passphrase.normalize("NFKD")),
      { c: 2048, dkLen: 64 },
    ),
  );
}
/** A wrong passphrase produces a different valid wallet. */
export function restoreWallet(phrase: string, passphrase = ""): ExtendedKey {
  return seedFromMnemonic(phrase, passphrase).key();
}
export function generateWallet(
  passphrase = "",
): Readonly<{ key: ExtendedKey; recovery: RecoveryPhrase }> {
  const recovery = generateMnemonic();
  return Object.freeze({
    key: restoreWallet(recovery.words(), passphrase),
    recovery,
  });
}
