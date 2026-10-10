import { test } from "node:test";
import assert from "node:assert/strict";
import { inspect } from "node:util";
import * as n from "../dist/index.js";
import {
  reference,
  load,
  fromHex,
  hex,
  keyFor,
  makeNoun,
} from "./fixtures.mjs";

test("TIP5 word and noun corpus, exact jam encodings", () => {
  for (const value of reference.hashes)
    assert.deepEqual(n.hashWords(value.words), value.digest);
  for (const value of reference.nouns) {
    const noun = makeNoun(value.noun);
    assert.deepEqual(n.hashNoun(noun), value.digest);
    assert.equal(hex(n.jam(noun)), value.jam);
    assert.ok(n.nounEqual(noun, n.cue(fromHex(value.jam))));
  }
  for (const value of [-1n, n.PRIME, 1, true])
    assert.throws(() => n.hashWords([value]), n.NockchainError);
});

test("all 35 Rust wallet vectors, public derivation and strict paths", () => {
  for (const value of reference.keys) {
    const key = keyFor(value.seed, value.path);
    assert.equal(key.zpub(), value.zpub);
    assert.equal(key.zprv(), value.zprv);
    assert.equal(hex(key.publicBytes()), value.public);
    assert.equal(key.address(), value.address);
    assert.equal(key.lockAddress(), value.lock);
    assert.equal(n.parseExtendedKey(value.zprv).zpub(), value.zpub);
    const publicKey = n.parsePublicKey(value.zpub);
    assert.equal(publicKey.isPrivate, false);
    assert.equal(publicKey.child(7).zpub(), key.child(7).public().zpub());
    assert.throws(() => n.parsePublicKey(value.zprv), n.NockchainError);
    assert.throws(() => publicKey.child(2 ** 31), n.NockchainError);
    assert.equal(n.formatDigest(n.parseDigest(value.address)), value.address);
    for (const formatted of [
      String(key),
      inspect(key, { showHidden: true }),
      JSON.stringify(key),
    ]) {
      assert.ok(!formatted.includes(value.secret));
      assert.ok(!formatted.includes(value.zprv));
    }
    const bytes = key.publicBytes();
    bytes.fill(0);
    assert.equal(hex(key.publicBytes()), value.public);
  }
  const key = keyFor(reference.keys[0].seed);
  for (const path of [
    "x/0",
    "m/",
    "m/01",
    "m/-1",
    "m/+1",
    "m/2147483648",
    "m/1h",
  ])
    assert.throws(() => key.derive(path), n.NockchainError);
  assert.equal(
    key.derive("m/0'/7").zprv(),
    key
      .child(2 ** 31)
      .child(7)
      .zprv(),
  );
  assert.throws(() => key.child(1n), n.NockchainError);
});

test("all 105 deterministic Schnorr signatures and invalid signatures", () => {
  for (const value of reference.signatures) {
    const key = keyFor(value.seed, value.path),
      message = n.digest(value.message),
      signature = key.signDigest(message);
    assert.deepEqual(signature.challenge, value.challenge);
    assert.deepEqual(signature.response, value.response);
    assert.ok(n.verifyDigest(key.publicBytes(), message, signature));
  }
  const key = keyFor(reference.keys[0].seed),
    message = n.digest([1n, 2n, 3n, 4n, 5n]);
  const signature = key.signDigest(message);
  assert.equal(n.verifyDigest(new Uint8Array(97), message, signature), false);
  assert.equal(
    n.verifyDigest(
      key.publicBytes(),
      n.digest([5n, 4n, 3n, 2n, 1n]),
      signature,
    ),
    false,
  );
  assert.equal(
    n.verifyDigest(
      key.publicBytes(),
      message,
      new n.Signature(Array(8).fill(0n), Array(8).fill(0n)),
    ),
    false,
  );
});

test("BIP39 recovery, Unicode normalization, randomness and redaction", () => {
  for (const [entropy, phrase, seed] of load("bip39.json")) {
    const recovery = n.mnemonicFromEntropy(fromHex(entropy));
    assert.equal(recovery.words(), phrase);
    assert.ok(!inspect(recovery, { showHidden: true }).includes(phrase));
    const derived = n.seedFromMnemonic(phrase, "TREZOR");
    assert.equal(hex(derived.toBytes()), seed);
    const bytes = derived.toBytes();
    bytes.fill(0);
    assert.equal(hex(derived.toBytes()), seed);
    assert.ok(!JSON.stringify(derived).includes(seed));
  }
  const phrase = n.generateMnemonic().words();
  assert.equal(phrase.split(" ").length, 24);
  assert.deepEqual(
    n.seedFromMnemonic(phrase, "é").toBytes(),
    n.seedFromMnemonic(phrase, "e\u0301").toBytes(),
  );
  assert.throws(
    () => n.seedFromMnemonic("abandon ".repeat(12)),
    n.NockchainError,
  );
});

test("exact amounts beyond JavaScript Number range", () => {
  for (const value of [
    0n,
    1n,
    65535n,
    65536n,
    (1n << 53n) + 1n,
    (1n << 64n) - 1n,
  ])
    assert.equal(n.parseNocks(n.formatNocks(value)), value);
  for (const value of [
    "",
    "-1",
    "+1",
    "1e3",
    " 1",
    "1.",
    ".5",
    "0.1",
    "0.00000000000000001",
    "281474976710656",
  ])
    assert.throws(() => n.parseNocks(value), n.NockchainError);
  assert.throws(() => n.formatNocks(65536), n.NockchainError);
});

test("immutable shared nouns, deep iterative traversal and bounded decoding", () => {
  let deep = 0n;
  for (let i = 0; i < 2000; i++) deep = new n.Cell(0n, deep);
  assert.ok(n.nounEqual(deep, n.cue(n.jam(deep))));
  let a = 0n,
    b = 0n;
  for (let i = 0; i < 60; i++) {
    a = new n.Cell(a, a);
    b = new n.Cell(b, b);
  }
  assert.ok(n.nounEqual(a, b));
  assert.throws(() => n.hashNoun(a, 100), n.NockchainError);
  const cell = new n.Cell(0n, 0n);
  assert.throws(() => {
    cell.head = 1n;
  }, TypeError);
  for (const bytes of [[], [0], [255], [2, 0], [130], [3]])
    assert.throws(() => n.cue(Uint8Array.from(bytes)), n.NockchainError);
});
