import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import * as n from "../dist/index.js";
import { decodeBase58, encodeBase58, bigintBytes } from "../dist/core.js";
import { reference, keyFor } from "./fixtures.mjs";

function sharedJam(depth) {
  const data = [];
  let bit = 0;
  const write = (value, size) => {
    for (let i = 0; i < size; i++, bit++) {
      if (Math.floor(bit / 8) === data.length) data.push(0);
      data[Math.floor(bit / 8)] |=
        Number((value >> BigInt(i)) & 1n) << (bit % 8);
    }
  };
  const mat = (value) => {
    if (!value) {
      write(1n, 1);
      return;
    }
    const length = value.toString(2).length,
      size = length.toString(2).length;
    write(0n, size);
    write(1n, 1);
    write(BigInt(length), size - 1);
    write(value, length);
  };
  const emit = (level) => {
    if (level === 0) {
      write(0n, 1);
      mat(1n);
    } else {
      write(1n, 2);
      const position = bit;
      emit(level - 1);
      write(3n, 2);
      mat(BigInt(position));
    }
  };
  emit(depth);
  return Uint8Array.from(data);
}
test("shared backreferences preserve identity and reject logical expansion bombs", () => {
  const noun = n.cue(sharedJam(5));
  assert.equal(noun.head, noun.tail);
  assert.deepEqual(n.hashNoun(noun), n.hashNoun(n.cue(n.jam(noun))));
  assert.throws(() => n.cue(sharedJam(21)), n.NockchainError);
});
test("keys reject invalid fields despite valid checksums", () => {
  const key = keyFor(reference.keys[0].seed),
    payload = decodeBase58(key.zpub()).slice(0, -4);
  const mutations = [
    [4, [0]],
    [0, [payload[0] ^ 1]],
    [46, [0]],
    [47, bigintBytes(n.PRIME, 8)],
    [60, [payload[60] ^ 1]],
    [10, [1]],
  ];
  const sha = (data) => createHash("sha256").update(data).digest();
  for (const [offset, replacement] of mutations) {
    const changed = payload.slice();
    changed.set(replacement, offset);
    const encoded = new Uint8Array([
      ...changed,
      ...sha(sha(changed)).subarray(0, 4),
    ]);
    assert.throws(
      () => n.parseExtendedKey(encodeBase58(encoded)),
      n.NockchainError,
    );
  }
  for (const value of ["", "1111", "0", "z".repeat(56)])
    assert.throws(() => n.parseDigest(value), n.NockchainError);
});
test("policy construction copies mutable inputs and enforces inclusive ranges", () => {
  const key = keyFor(reference.keys[0].seed),
    pkh = n.parseDigest(key.address());
  const keys = [[...pkh]],
    time = { relative: { min: 5n, max: 10n } };
  const lock = new n.LockV1(1, keys, time);
  keys[0][0] = 0n;
  time.relative.min = 999n;
  assert.deepEqual(lock.keys[0], pkh);
  assert.equal(lock.timelock.relative.min, 5n);
  assert.equal(n.timelockAllows(lock.timelock, 105n, 100n), true);
  assert.equal(n.timelockAllows(lock.timelock, 110n, 100n), true);
  assert.equal(n.timelockAllows(lock.timelock, 111n, 100n), false);
  for (const [threshold, values] of [
    [0, [pkh]],
    [2, [pkh]],
    [1, [pkh, pkh]],
    [true, [pkh]],
  ])
    assert.throws(() => new n.LockV1(threshold, values), n.NockchainError);
  for (const [min, max] of [
    [10n, 9n],
    [-1n, null],
    [null, n.PRIME],
  ])
    assert.throws(
      () => new n.LockV1(1, [pkh], { relative: { min, max } }),
      n.NockchainError,
    );
});
