# @swpsco/nockchain

Native TypeScript tools for Nockchain V1 wallets and transactions. Derive public
receiving addresses, review payments, select coins, and sign single-key or
multisig spends in Node and browsers. No Go or WebAssembly runtime is required.

```sh
npm install @swpsco/nockchain
```

ES modules; Node 22+ or a modern browser with `BigInt` and Web Crypto. TypeScript
declarations are included. Browser applications can bundle the package with their
usual build tool. The only runtime dependency is `@noble/hashes` for SHA-2, HMAC,
PBKDF2, and secure random bytes.

## Receive from a public branch

```ts
import { deriveReceiveAddress, parsePublicKey } from "@swpsco/nockchain";

const branch = parsePublicKey(zpub); // rejects private extended keys
const receive = deriveReceiveAddress(branch.zpub(), 42);
console.log(receive.address, receive.lockRoot);
```

Reserve each index durably before issuing its address. Use a dedicated
non-hardened receiving branch and retain the derivation path and allocated-index
range for recovery. `address` is the destination a sending wallet accepts;
`lockRoot` is its output lock commitment. A zpub is privacy-sensitive.

## Wallets and recovery

```ts
import { generateWallet, restoreWallet } from "@swpsco/nockchain";

const { key, recovery } = generateWallet(""); // optional BIP39 passphrase
// Back up recovery.words() privately before receiving funds. Never log it.
const restored = restoreWallet(recovery.words(), "");
const publicBranch = key.derive("m/44'/0'/0'/9000").public().zpub();
```

`generateMnemonic()` creates a 24-word English BIP39 phrase. Recovery supports
12–24 words, checksum validation, and NFKD Unicode normalization. A wrong
passphrase produces a different valid wallet. `generateSeed()` makes a raw
64-byte seed; `master(seedBytes)` accepts one. Raw seeds have no recovery phrase.
`zprv()`, `words()`, and `Seed.toBytes()` explicitly export spending authority.
String, JSON, and Node inspection of secret-bearing objects are redacted.

Derivation paths start with `m` and are relative to the supplied key. Apostrophes
mark hardened indices, which require a private parent. `public()` removes private
material. Public-point parsing enforces canonical coordinates and the Cheetah
prime-order subgroup.

## Exact amounts and payment planning

```ts
import { parseNocks, formatNocks, selectTransfer } from "@swpsco/nockchain";

const nicks = parseNocks("1.25"); // 81920n
const plan = selectTransfer(sender.public(), verifiedUnspentNotes, [
  { address: destination, amount: "1.25" },
]);
const review = plan.summary();
// Present the review and obtain the wallet user's authorization before signing.
const signed = plan.sign(sender);
const wire = signed.jam();
```

**Amounts, heights, digest limbs, and noun atoms use `bigint`.** Counts and child
indices use `number`. `1 NOCK = 65,536 nicks`; inexact decimal amounts are rejected.
Never convert protocol amounts or field values to JavaScript `number`. For JSON,
encode bigint values as decimal strings with an explicit schema.

`selectTransfer()` chooses a sufficient subset using largest amounts first and
stable note-name ties. `prepareTransfer()` consumes all supplied records. Both
merge repeated recipients, estimate fees, and send change to the sender unless
`changeAddress` is set. `feeNicks` supplies an explicit fee; zero selects automatic
fees. A remainder too small to pay for change metadata becomes part of the fee,
shown exactly in the review. Plain 1-of-1 inputs are supported by these helpers.
`signTransferV1()` accepts explicit per-input output and fee allocations.

An `UnspentNote` contains `{ note: NoteV1, lockRoot: Digest }`:

```ts
import { NoteV1, NoteName, cue, parseDigest } from "@swpsco/nockchain";

const note = new NoteV1({
  originPage: 100n,
  name: new NoteName(parseDigest(first), parseDigest(last)),
  noteData: cue(storedMetadataJam),
  nicks: 10_000_000n,
});
```

Supply the complete authenticated record. Parent commitments include version,
origin, name, **all stored metadata**, and value. Empty metadata is `0n` only when
the stored note actually has none. The library does not establish that a record
exists, is unspent, or has reached finality.

## Multisig, timelocks, and independent signing

```ts
import {
  LockV1,
  minimumTransactionFeeV1,
  prepareTransactionV1,
} from "@swpsco/nockchain";

const lock = new LockV1(2, [alicePKH, bobPKH, carolPKH], {
  relative: { min: 10n },
  absolute: { max: 500_000n },
});
const fee = minimumTransactionFeeV1([lock], [recipientLock]);
const unsigned = prepareTransactionV1([
  {
    note: verifiedNote,
    lock,
    fee,
    outputs: [{ lock: recipientLock, nicks: verifiedNote.nicks - fee }],
  },
]);
// Each signer independently reviews the same unsigned plan.
const alice = unsigned.sign(aliceKey);
const bob = unsigned.sign(bobKey);
const signed = alice.mergeSignatures(bob);
signed.verifySignatures();
signed.validateInputs([verifiedNote], chainHeight);
```

Locks require **exactly m signatures**, with up to 32 distinct authorized keys.
Extra signatures are rejected. Timelock bounds are inclusive; omitted or null
endpoints are unbounded. Relative heights measure age since the input's origin.
Signing does not establish timelock satisfaction. Each added signature changes
the transaction ID. Partial transactions travel as jam bytes; merging rejects
changed plans and conflicting signatures.

## Inspect and validate

```ts
import { parseTransactionV1, formatDigest } from "@swpsco/nockchain";

const tx = parseTransactionV1(wire);
const review = tx.summary();
tx.verifySignatures();
tx.validateInputs(verifiedNotes, chainHeight);
console.log(formatDigest(tx.id));
```

| Operation              | What it establishes                                                               |
| ---------------------- | --------------------------------------------------------------------------------- |
| `parseTransactionV1()` | Supported structure, canonical trees, proof roots, key encoding, and embedded ID  |
| `summary()`            | Committed amounts, fees, outputs, signature hashes, and present signers           |
| `OutputV1.lock()`      | Metadata authenticates the output's committed lock policy                         |
| `verifySignatures()`   | Every signature, authorization, exact threshold, and minimum fee                  |
| `validateInputs()`     | Complete supplied records, parent hashes, balances, origin heights, and timelocks |

The application authenticates chain state, confirmations, and unspent status,
and handles submission. The package performs no network requests or broadcasts.

## Nouns and scope

`Noun` is a field-valued `bigint` atom or a frozen `Cell`. Use `atom()`,
`new Cell(head, tail)`, `nounTuple()`, and `nounList()` to construct nouns;
`hashWords()`, `hashNoun()`, `jam()`, and `cue()` implement the protocol primitives.
Cells share immutable children and rely on JavaScript garbage collection.
Equality memoizes visited pairs, and iterative encoding, decoding, and noun
hashing avoid recursion on untrusted deep input. Jam backreferences preserve
sharing; logical expansion limits still count each occurrence.

This representation is informed by
[urbit/nockjs](https://github.com/urbit/nockjs/tree/0720c5996c9f2ade94296bb4fdc13400ccfb3a63).
It does not include a Nock interpreter or manual memory arena. Atoms must be below
the Goldilocks prime; the codec is for Nockchain based nouns, not arbitrary-size
Nock atoms.

Transactions support full axis-1 PKH proofs, optional conjunctive timelocks, and
ordinary output seeds. Other Merkle proofs, hashlocks, burn locks,
source-constrained outputs, and bridge construction are outside this API.

Limits: 64 inputs, 256 output seeds, 32 keys per lock, 64 metadata entries,
2,048 flattened metadata words per output lock, 65,536 transaction nodes, and
depth 256. Each input retains at least one nonzero output seed. General noun
operations allow up to 1,048,576 logical nodes and 16 MiB jam input/output.
Fees use the pinned mainnet V1 schedule, merging metadata per output lock and
rejecting conflicting values. Applications track network rule changes.

Private-key arithmetic is **variable-time**. Use trusted offline signing tools.
JavaScript cannot guarantee erasure of secret copies. See [SECURITY.md](SECURITY.md).

## Develop and verify

```sh
npm ci
npm test
npm run check
npm pack
```

Tests check all 35 wallet vectors, 105 signatures, 24 BIP39 vectors, 13 TIP5
vectors, seven noun encodings, four single-key transactions, and two multisig
transactions, including exact partial and signed wire bytes. The separate
canonical Hoon corpus checks IDs, complete parent commitments, and minimum fees.
Tests cover malformed inputs, immutable reviews, timelock boundaries, and a
browser bundle executed without Node globals. CI runs Node 22 and 24.

The source of truth is
[zorp-corp/nockchain at `1eac020`](https://github.com/zorp-corp/nockchain/tree/1eac02083a053c104b6a1299e80a8a51447017dc).
The port follows
[nockchain-go v0.1.0](https://github.com/yapishu/nockchain-go/tree/v0.1.0).
Public interoperability fixtures come from
[tx-types at `5f9ab2b`](https://github.com/SWPSCO/tx-types/tree/5f9ab2b38f1685a908f19a0e8f18e7845b3e7f35),
[nockster at `d621105`](https://github.com/SWPSCO/nockster/tree/d62110560dd005827ae8a46126c9841c86db0d6a),
and [Trezor BIP39 vectors](https://github.com/trezor/python-mnemonic/blob/master/vectors.json).
The fixture generators live in the Go repository; normal tests are offline.
**Never send funds to public test-vector addresses.**

MIT licensed. BIP39 wordlist attribution is in [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES).
