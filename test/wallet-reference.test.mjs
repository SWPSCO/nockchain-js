import test from "node:test";
import assert from "node:assert/strict";
import { keyFor } from "./fixtures.mjs";
import { readFileSync } from "node:fs";
import * as n from "../dist/index.js";
const vectors = JSON.parse(
  readFileSync(
    new URL("../testdata/wallet/reference.json", import.meta.url),
    "utf8",
  ),
);
const decode = (value) => n.cue(Buffer.from(value, "hex"));
const hex = (value) => Buffer.from(n.jam(value)).toString("hex");
const digest = (value) => n.digest(value.map(BigInt));
test("canonical JAM matches all official payload bytes", () => {
  const payloads = [
    ...vectors.raw.map((r) => r.jam),
    ...vectors.noteData.map((r) => r.data),
    ...vectors.fees.map((r) => r.spends),
    ...vectors.withdrawals.map((r) => r.spends),
    ...vectors.locks.flatMap((r) => [
      r.form,
      ...r.proofs.flatMap((p) => [p.stub, p.full]),
    ]),
  ];
  for (const value of payloads) assert.equal(hex(decode(value)), value);
});
test("all 31 tagged lock leaves match Hoon roots, proof bytes and hashes", () => {
  let count = 0;
  for (const row of vectors.locks) {
    const lock = n.parseLock(decode(row.form));
    assert.deepEqual(lock.root, digest(row.root));
    assert.equal(hex(lock.noun()), row.form);
    for (const item of row.proofs) {
      for (const full of [false, true]) {
        const kind = full ? "full" : "stub",
          proof = n.buildLockMerkleProof(lock, item.index, full);
        assert.equal(hex(proof.noun()), item[kind]);
        assert.deepEqual(proof.hash(), digest(item[kind + "Hash"]));
        assert.equal(
          proof.check(n.noteFirstV1(lock.root)),
          item[kind + "Valid"],
        );
        assert.equal(
          hex(n.LockMerkleProof.fromNoun(decode(item[kind])).noun()),
          item[kind],
        );
        assert.equal(n.validStubAxis(proof), full || proof.axis === 1n);
        assert(n.validStubAxis(proof, true));
        assert.equal(
          new n.LockMerkleProof(
            proof.condition,
            0n,
            proof.root,
            proof.path,
            full,
          ).check(n.noteFirstV1(lock.root)),
          false,
        );
        assert.equal(
          new n.LockMerkleProof(
            proof.condition,
            proof.axis,
            proof.root,
            [...proof.path, lock.root],
            full,
          ).check(n.noteFirstV1(lock.root)),
          false,
        );
      }
      count++;
    }
  }
  assert.equal(count, 31);
});
test("typed and raw metadata match Hoon hashes and words", () => {
  for (const row of vectors.noteData) {
    const data = n.NoteData.fromNoun(decode(row.data));
    assert.deepEqual(data.hash(), digest(row.hash), row.case);
    assert.equal(data.words(), Number(row.words), row.case);
    assert.equal(hex(data.noun()), row.data);
    for (const entry of data.decoded()) {
      const payload = entry.payload,
        value = payload.noun ? payload.noun() : payload;
      assert.equal(hex(value), hex(new Map(data.entries).get(entry.key)));
    }
  }
});
test("fee words and arithmetic match Hoon across activation", () => {
  for (const row of vectors.fees) {
    const words = n.transactionWords(decode(row.spends), {
      mergeByLockRoot: BigInt(row.height) >= 10n,
    });
    assert.deepEqual(words, {
      seedWords: BigInt(row.seedWords),
      witnessWords: BigInt(row.witnessWords),
    });
    const fees = new n.FeeParameters({
      height: BigInt(row.height),
      bythosPhase: 10n,
      baseFee: BigInt(row.base),
      inputFeeDivisor: BigInt(row.divisor),
      minFee: BigInt(row.minimum),
    });
    assert.equal(
      n.computeMinimumFee(words.seedWords, words.witnessWords, fees).minimumFee,
      BigInt(row.fee),
    );
  }
  for (const row of vectors.withdrawals) {
    const words = n.transactionWords(decode(row.spends), {
      mergeByLockRoot: BigInt(row.height) >= 10n,
      estimateSignatures: true,
    });
    assert.deepEqual(words, {
      seedWords: BigInt(row.seedWords),
      witnessWords: BigInt(row.witnessWords),
    });
    assert.equal(
      n.computeMinimumFee(
        words.seedWords,
        words.witnessWords,
        new n.FeeParameters({
          height: BigInt(row.height),
          bythosPhase: 10n,
          baseFee: 256n,
          minFee: 0n,
        }),
      ).minimumFee,
      BigInt(row.fee),
    );
  }
});

test("planner bytes, selection, fees and refunds match the pinned Rust core", () => {
  const parts = (noun, n) => {
    const values = [];
    while (--n) {
      values.push(noun.head);
      noun = noun.tail;
    }
    return [...values, noun];
  };
  const nounDigest = (noun) => n.digest(parts(noun, 5));
  const name = (wire) => {
    const [first, last] = parts(decode(wire), 3);
    return new n.NoteName(nounDigest(first), nounDigest(last));
  };
  const output = (o) =>
    new n.PlannedOutput(digest(o.root), decode(o.data), BigInt(o.amount));
  for (const row of vectors.plans) {
    const candidates = row.candidates.map((wire) => {
      const [version, origin, ident, data, amount] = parts(decode(wire), 5);
      assert.equal(version, 1n);
      const [first, last] = parts(ident, 3);
      return new n.NoteV1({
        originPage: origin,
        name: new n.NoteName(nounDigest(first), nounDigest(last)),
        noteData: data,
        nicks: amount,
      });
    });
    const result = n.plan(
      {
        candidates,
        outputs: row.outputs.map(output),
        refund: output(row.refund),
        chain: n.ChainContext.atHeight(BigInt(row.height)),
        selection: row.selection?.map(name),
        order: row.order,
        feeNicks: row.exactFee === null ? undefined : BigInt(row.exactFee),
        sweep: row.sweep === null ? undefined : output(row.sweep),
      },
      new n.SigningKeyLockMatcher(digest(row.signer)),
    );
    assert.equal(
      Buffer.from(result.transaction.jam()).toString("hex"),
      row.jam,
      row.case,
    );
    assert.deepEqual(
      result.selected.map((n) => n.name),
      row.selected.map(name),
    );
    assert.equal(result.selectedTotal, BigInt(row.selectedTotal));
    assert.equal(result.finalFee, BigInt(row.fee));
    assert.equal(result.minimumFee, BigInt(row.minimumFee));
    assert.deepEqual(result.wordCounts, {
      seedWords: BigInt(row.seedWords),
      witnessWords: BigInt(row.witnessWords),
    });
    assert.deepEqual(
      result.refunds,
      row.refunds.map((r) => [name(r.name), BigInt(r.amount)]),
    );
  }
});

test("migration parents, planner bytes and signed bytes match the Rust core", () => {
  const output = (o) =>
    new n.PlannedOutput(digest(o.root), decode(o.data), BigInt(o.amount));
  for (const row of vectors.migrations) {
    const notes = row.candidates.map((wire) => n.NoteV0.fromNoun(decode(wire)));
    notes.forEach((note, i) => {
      assert.equal(hex(note.noun()), row.candidates[i]);
      assert.deepEqual(note.hash(), digest(row.parents[i]));
    });
    const result = n.plan(
      {
        candidates: notes,
        outputs: row.outputs.map(output),
        refund: output(row.refund),
        chain: n.ChainContext.atHeight(BigInt(row.height)),
        version: 0,
        sweep: row.sweep === null ? undefined : output(row.sweep),
      },
      new n.SigningKeyLockMatcher(digest(row.signer)),
    );
    assert.equal(
      Buffer.from(result.transaction.jam()).toString("hex"),
      row.jam,
      row.case,
    );
    assert.equal(result.finalFee, BigInt(row.fee));
    assert.equal(result.minimumFee, BigInt(row.minimumFee));
    assert.deepEqual(result.wordCounts, {
      seedWords: BigInt(row.seedWords),
      witnessWords: BigInt(row.witnessWords),
    });
    const signed = result.transaction.sign(keyFor(row.seed));
    assert.equal(
      Buffer.from(signed.jam()).toString("hex"),
      row.signedJam,
      row.case,
    );
    signed.verifySignatures();
    signed.validateInputs(result.selected, BigInt(row.height));
    assert.throws(() => n.parseTransactionV1(signed.jam()));
    const parsed = n.parseTransactionV1(signed.jam(), {
      fees: new n.FeeParameters({ height: BigInt(row.height) }),
      migrationNotes: notes,
    });
    parsed.verifySignatures();
    parsed.validateInputs(result.selected, BigInt(row.height));
    assert.deepEqual(parsed.jam(), signed.jam());
    assert.deepEqual(parsed.mergeSignatures(signed).jam(), signed.jam());
    assert.throws(() =>
      signed.validateInputs(
        result.selected.map(
          (note) =>
            new n.NoteV0({ ...note, source: n.digest([1n, 2n, 3n, 4n, 5n]) }),
        ),
        BigInt(row.height),
      ),
    );
  }
});

test("canonical JAM ignores object sharing and rejects logical expansion and cycles", () => {
  let cell = new n.Cell(42n, 43n);
  assert.deepEqual(
    n.jam(new n.Cell(cell, cell)),
    n.jam(new n.Cell(new n.Cell(42n, 43n), new n.Cell(42n, 43n))),
  );
  for (let i = 0; i < 21; i++) cell = new n.Cell(cell, cell);
  assert.throws(() => n.jam(cell), /node limit/);
  const cyclic = Object.create(n.Cell.prototype);
  cyclic.head = 0n;
  cyclic.tail = cyclic;
  assert.throws(() => n.jam(cyclic), /Cyclic/);
});

test("fee saturation, bridge rounding and EVM address bounds", () => {
  const maximum = (1n << 64n) - 1n;
  assert.equal(
    n.computeMinimumFee(
      0n,
      2n,
      new n.FeeParameters({ baseFee: maximum, minFee: 0n }),
    ).minimumFee,
    maximum / 4n,
  );
  assert.equal(
    n.computeMinimumFee(
      2n,
      0n,
      new n.FeeParameters({ height: 0n, baseFee: maximum, minFee: 0n }),
    ).minimumFee,
    maximum,
  );
  assert.equal(n.computeBridgeFee(65537n, 7n), 14n);
  assert.equal(n.computeBridgeFee(0n, maximum), 0n);
  assert.equal(n.computeBridgeFee(maximum, maximum), maximum);
  const payload = new n.BridgeDepositDataPayload(new Uint8Array(20).fill(255));
  assert.deepEqual(
    n.BridgeDepositDataPayload.fromNoun(payload.noun()).noun(),
    payload.noun(),
  );
  assert.throws(() => new n.BridgeDepositDataPayload(new Uint8Array(21)));
  assert.throws(() =>
    n.BridgeDepositDataPayload.fromNoun(
      n.nounTuple(0n, 0x65736162n, 0n, 0n, n.PRIME - 1n),
    ),
  );
});
