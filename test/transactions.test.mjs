import { test } from "node:test";
import assert from "node:assert/strict";
import * as n from "../dist/index.js";
import { parts, digestNoun } from "../dist/core.js";
import {
  reference,
  consensus,
  oracle,
  fromHex,
  hex,
  keyFor,
  noteFrom,
  lockFrom,
} from "./fixtures.mjs";

test("single-key construction, inspection and canonical Hoon oracle", () => {
  assert.equal(consensus.commit, "1eac02083a053c104b6a1299e80a8a51447017dc");
  for (const value of reference.transactions) {
    const plans = value.plans.map((plan) => ({
      note: noteFrom(plan.note),
      lockRoot: n.digest(plan.lockRoot),
      fee: plan.fee,
      outputs: plan.outputs.map((output) => ({
        recipient: n.digest(output.recipient),
        nicks: output.nicks,
      })),
    }));
    const tx = n.signTransferV1(keyFor(value.seed), plans);
    assert.equal(hex(tx.jam()), value.jam);
    assert.equal(n.formatDigest(tx.id), value.id);
    assert.equal(tx.summary().minimumFeeNicks, oracle.get(value.id).minimumFee);
    const notes = plans.map((plan) => plan.note);
    assert.deepEqual(
      notes.map((note) => note.hash()),
      oracle.get(value.id).parentHashes,
    );
    const parsed = n.parseTransactionV1(tx.jam());
    assert.deepEqual(parsed.jam(), tx.jam());
    parsed.verifySignatures();
    parsed.validateInputs(notes, 105n);
    for (const spend of parsed.summary().spends)
      for (const output of spend.outputs)
        assert.deepEqual(output.lock().root, output.lockRoot);
  }
});

test("multisig partial bytes, independent merge, timelocks and immutable reviews", () => {
  for (const value of reference.multisig) {
    const lock = lockFrom(value),
      note = noteFrom(value.note),
      keys = value.seeds.map((seed) => keyFor(seed));
    assert.deepEqual(lock.root, value.root);
    assert.deepEqual(note.hash(), value.parent);
    const plan = {
      note,
      lock,
      outputs: [{ lock, nicks: value.gift }],
      fee: value.fee,
    };
    const unsigned = n.prepareTransactionV1([plan]);
    assert.throws(() => unsigned.verifySignatures(), n.NockchainError);
    let a = unsigned.sign(keys[0]);
    assert.equal(hex(a.jam()), value.partialJam);
    assert.throws(() => a.verifySignatures(), n.NockchainError);
    a = n.parseTransactionV1(a.jam());
    const b = unsigned.sign(keys[1]),
      signed = a.mergeSignatures(b);
    assert.equal(hex(signed.jam()), value.jam);
    assert.equal(n.formatDigest(signed.id), value.id);
    assert.equal(
      signed.summary().minimumFeeNicks,
      oracle.get(value.id).minimumFee,
    );
    assert.equal(
      n.minimumTransactionFeeV1([lock], [lock]),
      oracle.get(value.id).minimumFee,
    );
    signed.verifySignatures();
    const parsed = n.parseTransactionV1(signed.jam());
    parsed.verifySignatures();
    parsed.validateInputs([note], 105n);
    if (value.timed) {
      for (const height of [99n, 100n, 104n, 151n, 201n])
        assert.throws(
          () => parsed.validateInputs([note], height),
          n.NockchainError,
        );
      parsed.validateInputs([note], 150n);
    }
    for (const bad of [
      new n.NoteV1({ ...note, originPage: note.originPage + 1n }),
      new n.NoteV1({ ...note, nicks: note.nicks + 1n }),
    ])
      assert.throws(() => parsed.validateInputs([bad], 110n), n.NockchainError);
    assert.throws(() => signed.sign(keys[2]), n.NockchainError);
    assert.throws(
      () => signed.mergeSignatures(unsigned.sign(keys[2])),
      n.NockchainError,
    );
    assert.deepEqual(signed.sign(keys[0]).jam(), signed.jam());
    assert.equal(unsigned.summary().spends[0].signedKeys.length, 0);
    assert.equal(a.summary().spends[0].signedKeys.length, 1);
    const different = n.prepareTransactionV1([
      {
        ...plan,
        fee: plan.fee + 1n,
        outputs: [{ lock, nicks: value.gift - 1n }],
      },
    ]);
    assert.throws(
      () => a.mergeSignatures(different.sign(keys[1])),
      n.NockchainError,
    );
    assert.throws(() => {
      signed.summary().spends[0].outputs[0].nicks = 1n;
    }, TypeError);
    assert.throws(() => {
      lock.keys[0][0] = 1n;
    }, TypeError);
    plan.outputs[0].nicks = 1n;
    assert.equal(hex(signed.jam()), value.jam);
  }
});

test("coin selection, change fee gap, explicit fees and signing identity", () => {
  const key = keyFor(reference.keys[0].seed),
    pkh = n.parseDigest(key.address()),
    root = n.lockRoot(pkh);
  const note = (nicks, last) => ({
    note: new n.NoteV1({
      originPage: 100n,
      name: new n.NoteName(
        n.noteFirstV1(root),
        n.digest([last, 2n, 3n, 4n, 5n]),
      ),
      noteData: 0n,
      nicks,
    }),
    lockRoot: [...root],
  });
  const destination = reference.keys[1].address;
  const notes = [
    note(1_000_000n, 1n),
    note(4_000_000n, 2n),
    note(2_000_000n, 3n),
  ];
  const payments = [
    { address: destination, amount: n.formatNocks(1_000_000n) },
  ];
  const selected = n.selectTransfer(key.public(), notes, payments);
  assert.equal(selected.summary().inputCount, 1);
  assert.equal(selected.notes()[0].nicks, 4_000_000n);
  notes[1].lockRoot[0] = 0n;
  payments[0].amount = "0";
  const signed = selected.sign(key);
  signed.verifySignatures();
  signed.validateInputs(selected.notes(), 100n);
  const fee = n.minimumTransferFeeV1(1, [n.parseDigest(destination)]);
  const gap = n.prepareTransfer(
    key.public(),
    [note(1_000_000n + fee + 10n, 4n)],
    [{ address: destination, amount: n.formatNocks(1_000_000n) }],
  );
  assert.equal(gap.summary().changeNicks, 0n);
  assert.equal(gap.summary().feeNicks, fee + 10n);
  gap.sign(key).verifySignatures();
  assert.throws(() => selected.sign(key.child(1)), n.NockchainError);
  assert.throws(
    () =>
      n.selectTransfer(
        key,
        [notes[0], notes[0]],
        [{ address: destination, amount: "1" }],
      ),
    n.NockchainError,
  );
  assert.throws(
    () =>
      n.prepareTransfer(
        key,
        [note(10_000_000n, 8n)],
        [{ address: destination, amount: "1" }],
        { feeNicks: 1n },
      ),
    n.NockchainError,
  );
});

test("complete metadata commitment and nonempty output requirement", () => {
  const value = reference.multisig[0],
    lock = lockFrom(value),
    note = noteFrom(value.note);
  assert.throws(
    () =>
      n.prepareTransactionV1([{ note, lock, outputs: [], fee: note.nicks }]),
    n.NockchainError,
  );
  const full = new n.NoteV1({ ...note, noteData: lock.metadata() });
  const tx = n.prepareTransactionV1([
    {
      note: full,
      lock,
      outputs: [{ lock, nicks: value.gift }],
      fee: value.fee,
    },
  ]);
  tx.validateInputs([full], 100n);
  assert.throws(() => tx.validateInputs([note], 100n), n.NockchainError);
  const output = tx.summary().spends[0].outputs[0];
  const wrong = new n.OutputV1(
    n.digest([1n, 2n, 3n, 4n, 5n]),
    output.noteData,
    output.nicks,
    output.parentHash,
  );
  assert.throws(() => wrong.lock(), n.NockchainError);
});

test("malformed IDs, unsupported proofs, truncated and random jam", () => {
  const value = reference.transactions[0],
    wire = fromHex(value.jam);
  const [version, id, tree] = parts(n.cue(wire), 3);
  const malformed = [
    wire.slice(0, -1),
    new Uint8Array([...wire, 0]),
    n.jam(
      n.nounTuple(version, digestNoun(n.digest([1n, 2n, 3n, 4n, 5n])), tree),
    ),
    n.jam(0n),
  ];
  const [entry, left, right] = parts(tree, 3),
    [name, spend] = parts(entry, 2);
  const [spVersion, witness, seeds, fee] = parts(spend, 4),
    [proof, signatures, hax, time] = parts(witness, 4);
  const [tag, condition, axis, commitment] = parts(proof, 4);
  for (const badProof of [
    n.nounTuple(tag, condition, 2n, commitment),
    n.nounTuple(123n, condition, axis, commitment),
  ]) {
    const badSpend = n.nounTuple(
      spVersion,
      n.nounTuple(badProof, signatures, hax, time),
      seeds,
      fee,
    );
    malformed.push(
      n.jam(
        n.nounTuple(
          version,
          id,
          n.nounTuple(new n.Cell(name, badSpend), left, right),
        ),
      ),
    );
  }
  for (const data of malformed)
    assert.throws(() => n.parseTransactionV1(data), n.NockchainError);
  let state = 0xc0ffee;
  const random = () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
  for (let i = 0; i < 250; i++) {
    const data = Uint8Array.from(
      { length: (random() % 127) + 1 },
      () => random() & 255,
    );
    try {
      const noun = n.cue(data);
      assert.ok(n.nounEqual(noun, n.cue(n.jam(noun))));
    } catch (error) {
      if (!(error instanceof n.NockchainError)) throw error;
    }
    try {
      n.parseTransactionV1(data);
    } catch (error) {
      if (!(error instanceof n.NockchainError)) throw error;
    }
  }
});
