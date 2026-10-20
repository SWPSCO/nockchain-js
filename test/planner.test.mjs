import test from "node:test";
import assert from "node:assert/strict";
import * as n from "../dist/index.js";
import { hashEach } from "../dist/core.js";
import { keyFor, reference } from "./fixtures.mjs";
const key = keyFor(reference.keys[0].seed),
  pkh = n.parseDigest(key.address()),
  lock = new n.LockV1(1, [pkh]);
const refund = new n.PlannedOutput(lock.root, lock.metadata(), 0n),
  payment = n.PlannedOutput.payment(n.digest([7n, 8n, 9n, 10n, 11n]), 1000000n);
const note = (
  amount,
  last = 1n,
  policy = lock,
  origin = 100n,
  first = n.noteFirstV1(policy.root),
) =>
  new n.NoteV1({
    originPage: origin,
    name: new n.NoteName(first, n.digest([last, 2n, 3n, 4n, 5n])),
    noteData: policy.metadata(),
    nicks: amount,
  });
test("planner selects, solves phase-aware fees and conserves complete input commitments", () => {
  const notes = [note(2000000n), note(4000000n, 2n)],
    request = {
      candidates: notes,
      outputs: [payment],
      refund,
      chain: n.ChainContext.atHeight(54000n),
    };
  const result = n.plan(request, new n.SigningKeyLockMatcher(pkh));
  assert.deepEqual(result.selected, [notes[1]]);
  assert.equal(
    result.selectedTotal,
    result.outputs.reduce((v, o) => v + o.amount, 0n) + result.finalFee,
  );
  const signed = result.transaction.sign(key);
  signed.verifySignatures();
  signed.validateInputs(result.selected, 54000n);
  assert.deepEqual(n.parseTransactionV1(signed.jam()).jam(), signed.jam());
  const changedContext = n.parseTransactionV1(signed.jam(), {
    fees: new n.FeeParameters({ minFee: 257n }),
  });
  assert.throws(() => signed.mergeSignatures(changedContext), /context/);
  const before = n.plan(
    { ...request, chain: n.ChainContext.atHeight(53999n) },
    new n.SigningKeyLockMatcher(pkh),
  );
  assert(before.minimumFee > result.minimumFee);
  assert.equal(before.transaction.summary().spends[0].proof.full, false);
  assert.throws(() =>
    n.plan(
      { ...request, selection: [notes[0].name, notes[0].name] },
      new n.SigningKeyLockMatcher(pkh),
    ),
  );
});
test("tagged hashlock proof requires its preimage and preserves refund policy", () => {
  const claim = new n.LockV1(1, [pkh], null, [hashEach(42n)]),
    tree = new n.LockTreeV1([claim, lock]),
    input = note(8000000n, 1n, tree);
  const request = {
    candidates: [input],
    outputs: [payment],
    refund: new n.PlannedOutput(tree.root, tree.metadata(), 0n),
    chain: n.ChainContext.atHeight(170000n),
  };
  assert.throws(() =>
    n.plan(request, new n.LockRootLockMatcher(tree.root, { lock: tree })),
  );
  const matcher = new n.LockRootLockMatcher(tree.root, {
      lock: tree,
      preimages: [42n],
    }),
    result = n.plan(request, matcher),
    signed = result.transaction.sign(key);
  signed.verifySignatures();
  signed.validateInputs(result.selected, 170000n);
  const parsed = n.parseTransactionV1(signed.jam());
  assert.deepEqual(parsed.jam(), signed.jam());
  assert.equal(parsed.summary().spends[0].proof.axis, 6n);
  const change = parsed
    .summary()
    .spends[0].outputs.find((o) => n.digestEqual(o.lockRoot, tree.root));
  assert(change.lock() instanceof n.LockTreeV1);
  assert.deepEqual(change.lock().root, tree.root);
  assert.throws(() =>
    n.plan({ ...request, chain: n.ChainContext.atHeight(53999n) }, matcher),
  );
});
test("fund admission uses configured authoritative identity and candidate maturity", () => {
  const policy = new n.FundLockPolicy(
    lock.root,
    n.digest([99n, 2n, 3n, 4n, 5n]),
    new n.FundMaturityPolicy(170000n, 100n),
  );
  const input = note(5000000n, 1n, lock, 169950n, policy.firstName),
    request = {
      candidates: [input],
      outputs: [payment],
      refund,
      chain: n.ChainContext.atHeight(169999n),
    },
    matcher = new n.LockRootLockMatcher(lock.root, {
      lock,
      fundPolicy: policy,
    });
  n.plan(request, matcher);
  n.plan(
    {
      ...request,
      chain: new n.ChainContext(
        169999n,
        new n.FeeParameters({ height: 170000n }),
      ),
    },
    matcher,
  );
  assert.throws(() =>
    n.plan(
      {
        ...request,
        chain: new n.ChainContext(
          170000n,
          new n.FeeParameters({ height: 169999n }),
        ),
      },
      matcher,
    ),
  );
  assert.throws(() =>
    n.plan({ ...request, chain: n.ChainContext.atHeight(170000n) }, matcher),
  );
  const result = n.plan(
      { ...request, chain: n.ChainContext.atHeight(170050n) },
      matcher,
    ),
    signed = result.transaction.sign(key);
  signed.validateInputs([input], 170050n);
  assert(new n.FundMaturity(10n, null).admits(11n));
  assert.equal(new n.FundMaturity(10n, 0n).admits(11n), false);
  assert.throws(() => n.parseTransactionV1(signed.jam()));
  n.parseTransactionV1(signed.jam(), { fundPolicy: policy }).validateInputs(
    [input],
    170050n,
  );
});
test("sweep consumes all inputs and leaves every input a positive seed", () => {
  const notes = [note(3000000n), note(4000000n, 2n)],
    result = n.plan(
      {
        candidates: notes,
        outputs: [],
        refund,
        chain: n.ChainContext.atHeight(54000n),
        order: "ascending",
        sweep: payment.withAmount(0n),
      },
      new n.SigningKeyLockMatcher(pkh),
    );
  assert.deepEqual(result.selected, notes);
  assert.deepEqual(result.refunds, []);
  assert.equal(
    result.outputs.reduce((v, o) => v + o.amount, 0n) + result.finalFee,
    7000000n,
  );
  assert(result.transaction.summary().spends.every((s) => s.outputs.length));
});
