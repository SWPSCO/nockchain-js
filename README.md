# @swpsco/nockchain

Native TypeScript tools for Nockchain wallet planning and transactions. Derive public
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
shown exactly in the review. These helpers use the signing-key matcher; supply a chain context for mature coinbase inputs.
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

## Pure planning and lock policies

```ts
import {
  ChainContext,
  PlannedOutput,
  SigningKeyLockMatcher,
  plan,
} from "@swpsco/nockchain";

const result = plan(
  {
    candidates: verifiedNotes,
    outputs: [PlannedOutput.payment(recipientPKH, 1_000_000n)],
    refund: new PlannedOutput(senderLock.root, senderLock.metadata(), 0n),
    chain: ChainContext.atHeight(chainHeight),
  },
  new SigningKeyLockMatcher(senderPKH),
);
const review = result.transaction.summary();
// Review selected inputs, finalFee, minimumFee, refunds, and wordCounts.
const signed = result.transaction.sign(sender);
```

Use `selection`, `order`, `feeNicks`, or `sweep` in `PlanRequest` to control
selection and allocation. `LockRootLockMatcher` supplies `lock`, `leafNumber`,
`preimages`, and an optional `fundPolicy`. `LockTreeV1`, `LockMerkleProof`, and
`buildLockMerkleProof` expose the same policies at the transaction boundary.

The pure planner selects eligible notes, reserves a positive seed for every
input, assigns payments and refunds, and solves the fee from the encoded
transaction. Selection sorts by amount and then Base58 note name. An explicit
selection requires every chosen note to be eligible. A sweep consumes all
eligible candidates into one destination. An exact fee remains visible in the
review even when it is below the required minimum; signing rejects an underfunded
transaction.

The signing-key matcher handles single-signature PKH policies and the coinbase
relative-age policy. The root matcher selects a specific leaf of a disclosed
lock, checks hashlock preimages, and can use an explicitly configured fund root,
authoritative first name, and maturity policy. Fund maturity uses the candidate
height. Fee parameters independently select the fee schedule; the height helper
sets both together. With no candidate height, timed and fund inputs are ineligible.

Lock trees contain up to 16 leaves and pad to a power of two with burn conditions.
Leaf numbers start at 1. Conditions support PKH, timelock, hashlock, and burn
primitives; a burn condition cannot be spent. Proofs preserve the outer tree tag,
axis, and sibling path. Before Bythos, ordinary inputs use single-leaf stub proofs;
at Bythos they use full proofs. Refund metadata preserves the entire chosen
output policy, including trees and custom entries.

## Metadata, bridge payloads, and V0 migration

`NoteData` provides canonical metadata maps, hashing, word counts, and typed
`LockData`, `BridgeDepositDataPayload`, and `BridgeWithdrawalDataPayload` values.
Deposit addresses are exactly 20 big-endian bytes. Unknown versions and networks
remain raw nouns. `computeBridgeFee` rounds up to whole NOCK before applying the
rate and saturates at uint64 limits. Construct an opaque output with a `Digest`
as `lock` and explicit `noteData`; full lock forms disclose their metadata by
default. Ethereum transaction construction and submission belong to the caller.

`NoteV0.fromNoun` reads complete V0 records, including public-key policy, source,
coinbase flag, and optional timelock. Set `version: 0` in `PlanRequest` to migrate
those notes into V1 outputs. When parsing a migration transaction, supply
`{ migrationNotes: verifiedV0Notes, fees }` to `parseTransactionV1`; the wire
witness does not contain the V0 input policy. Parent validation commits to the
complete supplied record. V0 and V1 candidates are selected separately.

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

Transactions support V1 lock proofs and V0-to-V1 migration spends. Outputs have
unconstrained source fields.

Limits: 64 inputs, 256 output seeds, 32 keys per lock, 64 metadata entries,
2,048 flattened metadata words per output lock, 65,536 transaction nodes, and
depth 256. Each input retains at least one nonzero output seed. General noun
operations allow up to 1,048,576 logical nodes and 16 MiB jam input/output.
Fee parameters control the phase height, base rate, witness divisor, and minimum.
At Bythos, metadata is merged per output lock and the witness discount applies.
Before Bythos, metadata is counted per seed and the base rate doubles. The default
fee context is height 54,000; provide the actual chain context when planning.
Conflicting metadata is rejected. Applications track network rule changes.

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

Wallet behavior is checked against the official Hoon source at
[`9bcc26c`](https://github.com/zorp-corp/nockchain/tree/9bcc26c6c57019dfde7f83aad9a9dd4ed5cd7902)
and the shared Rust wallet core at
[`02d1946`](https://github.com/SWPSCO/tx-types/tree/02d194605c475013745cc65b26f1413cd098932e).
The wallet corpus covers all 31 tagged lock leaves, metadata and bridge payloads,
phase-dependent fees, seven planner scenarios, and four V0 migration scenarios
with exact unsigned and signed bytes. Fixture files retain their source pins and
SHA-256 checksums. The Go repository contains the reproducible generators;
normal SDK tests use checked-in data and run offline.

**Never send funds to public test-vector addresses.**

MIT licensed. BIP39 wordlist attribution is in [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES).
