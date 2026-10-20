import test from "node:test";
import assert from "node:assert/strict";
import {
  readFileSync,
  mkdtempSync,
  writeFileSync,
  existsSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import * as n from "../dist/index.js";

const fixture = JSON.parse(
  readFileSync(new URL("../testdata/signing-bundles.json", import.meta.url)),
);
const key = n.master(Uint8Array.from(Buffer.from(fixture.seed, "hex")));
const sample = fixture.cases[0].response.bundle;
const copy = (value = sample) => structuredClone(value);
const encode = (bytes) => Buffer.from(bytes).toString("base64");
const note = (record) =>
  new n.NoteV1({
    name: new n.NoteName(
      n.parseDigest(record.name.firstName),
      n.parseDigest(record.name.lastName),
    ),
    originPage: BigInt(record.originPage),
    nicks: BigInt(record.amountNicks),
    noteData: n.cue(Buffer.from(record.noteData, "base64")),
  });

test("Rust bundles produce identical locally reviewed and signed transactions", () => {
  for (const entry of fixture.cases) {
    const { bundle, review } = entry.response;
    const checked = n.inspectSigningBundle(bundle);
    assert.equal(
      checked.review.transactionId,
      review.transactionId,
      entry.name,
    );
    assert.equal(checked.review.feeNicks, review.feeNicks, entry.name);
    assert.equal(
      checked.review.minimumFeeNicks,
      review.minimumFeeNicks,
      entry.name,
    );
    assert.equal(checked.review.fullySigned, false);
    const signed = n.signSigningBundle(bundle, key);
    assert.equal(signed.rawTransaction, entry.signedRawTransaction, entry.name);
    const signedReview = n.inspectSigningBundle(signed).review;
    assert.equal(signedReview.transactionId, entry.signedTransactionId);
    assert.equal(signedReview.fullySigned, true);
    assert.notEqual(signedReview.transactionId, checked.review.transactionId);
  }
});

test("bundle validation rejects altered intent, input commitments and unsafe encoding", () => {
  for (const mutate of [
    (b) => {
      b.payments[0].amountNicks = "999999";
    },
    (b) => {
      b.payments[0].address = n.formatDigest(n.digest([1n, 2n, 3n, 4n, 5n]));
    },
    (b) => {
      b.inputs[0].amountNicks = "40000001";
    },
    (b) => {
      b.inputs[0].originPage = "53899";
    },
    (b) => {
      b.inputs[0].noteData = encode(n.jam(0n));
    },
    (b) => {
      b.sourceAddress = b.payments[0].address;
    },
    (b) => {
      b.rawTransaction += "\n";
    },
    (b) => {
      b.rawTransaction = encode(
        Uint8Array.from([...Buffer.from(b.rawTransaction, "base64"), 0]),
      );
    },
    (b) => {
      b.candidateHeight = "18446744073709551616";
    },
    (b) => {
      b.payments[0].amountNicks = "01";
    },
    (b) => {
      b.inputs = [];
    },
    (b) => {
      b.inputs[0].privateKey = "unexpected";
    },
    (b) => {
      b.network = "mainnet\nPAY SOMEBODY ELSE";
    },
  ]) {
    const bundle = copy();
    mutate(bundle);
    assert.throws(() => n.inspectSigningBundle(bundle));
  }
  const wrongKey = n.master(new Uint8Array(64).fill(42));
  assert.throws(() => n.signSigningBundle(sample, wrongKey), /source address/);
  assert.throws(
    () => n.signSigningBundle(sample, key.public()),
    /source address/,
  );
});

test("a canonical transaction with a valid input commitment cannot raise the planned fee", () => {
  const bundle = copy(),
    checked = n.inspectSigningBundle(bundle);
  const spend = checked.transaction.summary().spends[0];
  const sourceRoot = n.newPKHLockV1(1, [
    n.parseDigest(bundle.sourceAddress),
  ]).root;
  const changed = n.prepareTransactionV1(
    [
      {
        note: note(bundle.inputs[0]),
        lock: spend.lock,
        fee: spend.fee + 1n,
        outputs: spend.outputs.map((output) => ({
          lock: output.lock(),
          noteData: output.noteData,
          nicks:
            output.nicks -
            (n.digestEqual(output.lockRoot, sourceRoot) ? 1n : 0n),
        })),
      },
    ],
    { fees: new n.FeeParameters({ height: BigInt(bundle.candidateHeight) }) },
  );
  changed.validateInputs(
    bundle.inputs.map(note),
    BigInt(bundle.candidateHeight),
  );
  changed.verifySignatures({ requireThreshold: false });
  bundle.rawTransaction = encode(changed.jam());
  assert.throws(() => n.inspectSigningBundle(bundle), /fee differs/);
});

test("CLI inspects without secrets and refuses signing without interactive approval", () => {
  const dir = mkdtempSync(join(tmpdir(), "nockchain-cli-"));
  try {
    const input = join(dir, "bundle.json"),
      out = join(dir, "signed.json");
    writeFileSync(input, JSON.stringify(sample));
    const cli = new URL("../bin/nockchain.mjs", import.meta.url).pathname;
    const inspected = spawnSync(process.execPath, [cli, "inspect", input], {
      encoding: "utf8",
    });
    assert.equal(inspected.status, 0, inspected.stderr);
    assert.equal(
      JSON.parse(inspected.stdout).transactionId,
      fixture.cases[0].response.review.transactionId,
    );
    const rejected = spawnSync(
      process.execPath,
      [
        cli,
        "sign",
        input,
        "--out",
        out,
        "--key-file",
        join(dir, "missing-key"),
      ],
      { encoding: "utf8" },
    );
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /interactive terminal/);
    assert.equal(existsSync(out), false);
  } finally {
    rmSync(dir, { recursive: true });
  }
});
