#!/usr/bin/env node
import { open } from "node:fs/promises";
import { parseArgs } from "node:util";
import { createHash } from "node:crypto";
import { createInterface } from "node:readline/promises";
import { Writable } from "node:stream";
import {
  inspectSigningBundle,
  signSigningBundle,
  parseExtendedKey,
  restoreWallet,
} from "../dist/index.js";

const usage = `Usage:
  nockchain inspect BUNDLE.json
  nockchain sign BUNDLE.json --out SIGNED.json [--key-file FILE]
  nockchain sign BUNDLE.json --out SIGNED.json --mnemonic --path "m/..." [--passphrase]

Signing requires an interactive terminal. Keys and recovery phrases stay local.
--key-file reads a plain-text zprv (or recovery phrase with --mnemonic).
--path derives the explicitly named child key. Recovery phrases require --path.
The command never broadcasts a transaction.`;

async function readBounded(path, maximum) {
  const file = await open(path, "r");
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > maximum)
      throw new Error("Expected a bounded regular file");
    const buffer = Buffer.alloc(maximum + 1);
    let size = 0;
    while (size <= maximum) {
      const { bytesRead } = await file.read(buffer, size, maximum + 1 - size);
      if (bytesRead === 0) break;
      size += bytesRead;
    }
    if (size > maximum) throw new Error("File is too large");
    return buffer.subarray(0, size).toString("utf8");
  } finally {
    await file.close();
  }
}

async function prompt(text, hidden = false) {
  const output = hidden
    ? new Writable({
        write(_chunk, _encoding, callback) {
          callback();
        },
      })
    : process.stderr;
  const reader = createInterface({
    input: process.stdin,
    output,
    terminal: true,
  });
  const abort = () => {
    reader.close();
    process.exitCode = 130;
  };
  reader.on("SIGINT", abort);
  if (hidden) process.stderr.write(text);
  try {
    return await reader.question(hidden ? "" : text);
  } finally {
    reader.close();
    if (hidden) process.stderr.write("\n");
  }
}

async function main() {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: {
      out: { type: "string" },
      "key-file": { type: "string" },
      mnemonic: { type: "boolean" },
      path: { type: "string" },
      passphrase: { type: "boolean" },
      help: { type: "boolean", short: "h" },
    },
  });
  if (values.help) {
    console.log(usage);
    return;
  }
  const [command, file] = positionals;
  if (positionals.length !== 2 || !["inspect", "sign"].includes(command))
    throw new Error(usage);
  if (command === "inspect" && Object.keys(values).length)
    throw new Error("inspect accepts only the bundle path");
  if (values.mnemonic && !values.path)
    throw new Error("--mnemonic requires an explicit --path");
  if (values.passphrase && !values.mnemonic)
    throw new Error("--passphrase requires --mnemonic");
  const text = await readBounded(file, 8 * 1024 * 1024);
  const { bundle, review } = inspectSigningBundle(JSON.parse(text));
  if (command === "inspect") {
    console.log(JSON.stringify(review, null, 2));
    return;
  }
  if (!values.out) throw new Error("sign requires --out");
  if (!process.stdin.isTTY || !process.stderr.isTTY)
    throw new Error(
      "Signing requires an interactive terminal for review and approval",
    );
  process.stderr.write(`${JSON.stringify(review, null, 2)}\n`);
  process.stderr.write(
    "Network and tip are indexed context, not proof that inputs are unspent.\n",
  );
  const fingerprint = createHash("sha256").update(text).digest("hex");
  process.stderr.write(`Bundle SHA-256: ${fingerprint}\n`);
  const approval = await prompt(
    "Check recipients, amounts and fee. Type SIGN to approve: ",
  );
  if (approval !== "SIGN")
    throw new Error("Signing declined; no output written");
  const secret = values["key-file"]
    ? (await readBounded(values["key-file"], 16384)).trim()
    : await prompt(
        values.mnemonic ? "Recovery phrase (hidden): " : "zprv (hidden): ",
        true,
      );
  const passphrase = values.passphrase
    ? await prompt("Passphrase (hidden): ", true)
    : "";
  let key = values.mnemonic
    ? restoreWallet(secret, passphrase)
    : parseExtendedKey(secret);
  if (values.path) key = key.derive(values.path);
  const signed = signSigningBundle(bundle, key);
  const output = await open(values.out, "wx", 0o600);
  try {
    await output.writeFile(`${JSON.stringify(signed, null, 2)}\n`);
  } finally {
    await output.close();
  }
  console.log(
    JSON.stringify(
      {
        output: values.out,
        transactionId: inspectSigningBundle(signed).review.transactionId,
        fullySigned: true,
      },
      null,
      2,
    ),
  );
}

main().catch((error) => {
  process.stderr.write(`nockchain: ${error.message}\n`);
  process.exitCode = 1;
});
