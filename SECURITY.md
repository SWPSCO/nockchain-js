# Security

Use a dedicated public receiving branch for online address allocation. Public
extended keys are privacy-sensitive; a non-hardened child private key together
with its parent zpub can expose the parent's spending key.

Cheetah arithmetic uses variable-time BigInt operations. Private derivation and
signing belong in trusted offline tools, not remotely exposed signing services.
Neither JavaScript nor the garbage collector guarantees secret erasure. Explicit
exports (`zprv()`, `words()`, `toBytes()`) and all copies carry spending authority.
Diagnostic formatting is redacted; callers remain responsible for logging,
storage, backups, and access control.

Nouns, lock policies, notes and transaction reviews are immutable. Decoding has
byte, logical-node and depth limits. Canonical structure does not imply valid
signatures or chain validity: call `verifySignatures()` and `validateInputs()`
explicitly, and authenticate the input records, chain height, unspent status and
confirmation policy through a trusted chain-state source.

V1 condition trees and V0 migration inputs are supported. Fund inputs require an
explicit authoritative identity and maturity policy. Migration parsing requires
complete V0 records. Bridge payload codecs do not establish cross-chain finality
or submit Ethereum transactions. This package is not a full consensus validator,
chain client, or broadcaster. Applications supply correct height and fee contexts.
Native NOCK units are nicks (2^16 per NOCK); Base ERC-20 units differ.

Tests use public Hoon, Rust and BIP39 fixtures. No independent cryptographic audit
is claimed. Report vulnerabilities privately to the repository maintainers using
GitHub private reporting when available. Never attach real seeds, private keys,
API credentials, or identifying wallet data to an issue.
