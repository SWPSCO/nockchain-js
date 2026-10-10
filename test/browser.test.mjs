import { test } from "node:test";
import assert from "node:assert/strict";
import { runInNewContext } from "node:vm";
import { webcrypto } from "node:crypto";
import { build } from "esbuild";
import { reference, oracle } from "./fixtures.mjs";

test("browser bundle runs without Node globals or native modules", async () => {
  const bundle = await build({
    entryPoints: ["src/index.ts"],
    bundle: true,
    platform: "browser",
    format: "iife",
    globalName: "Nockchain",
    target: "es2022",
    write: false,
  });
  const vector = reference.transactions[0];
  const context = {
    TextEncoder,
    TextDecoder,
    crypto: webcrypto,
    expectedAddress: reference.keys[0].address,
    transactionHex: vector.jam,
    expectedId: vector.id,
    expectedFee: oracle.get(vector.id).minimumFee.toString(),
  };
  const result = runInNewContext(
    bundle.outputFiles[0].text +
      `
    (() => {
      if (typeof process !== 'undefined' || typeof Buffer !== 'undefined' || typeof require !== 'undefined') throw Error('Unexpected Node global');
      const n = Nockchain;
      const key = n.master(Uint8Array.from({ length: 64 }, (_, i) => i));
      if (key.address() !== expectedAddress) throw Error('Browser derivation mismatch');
      const tx = n.parseTransactionV1(Uint8Array.from(transactionHex.match(/../g), pair => parseInt(pair, 16)));
      tx.verifySignatures();
      if (n.formatDigest(tx.id) !== expectedId || tx.summary().minimumFeeNicks.toString() !== expectedFee) throw Error('Browser transaction mismatch');
      if (n.generateMnemonic().words().split(' ').length !== 24) throw Error('Browser randomness failed');
      return n.formatNocks(n.parseNocks('1.25'));
    })();`,
    context,
    { timeout: 30000 },
  );
  assert.equal(result, "1.25");
});
