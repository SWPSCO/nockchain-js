/** Nockchain V1 wallets and transactions. No chain access or broadcasting. */
export {
  PRIME,
  MAX_NOUN_NODES,
  MAX_JAM_BYTES,
  NICKS_PER_NOCK,
  NockchainError,
  Cell,
  atom,
  nounTuple,
  nounList,
  nounEqual,
  digest,
  digestEqual,
  formatDigest,
  parseDigest,
  hashWords,
  hashNoun,
  parseNocks,
  formatNocks,
} from "./core.js";
export type { Noun, Digest } from "./core.js";
export { jam, cue } from "./codec.js";
export {
  ExtendedKey,
  Signature,
  master,
  generate,
  parseExtendedKey,
  parsePublicKey,
  lockRoot,
  verifyDigest,
  deriveReceiveAddress,
} from "./keys.js";
export type { ReceiveAddress } from "./keys.js";
export {
  Seed,
  RecoveryPhrase,
  generateSeed,
  generateMnemonic,
  mnemonicFromEntropy,
  seedFromMnemonic,
  restoreWallet,
  generateWallet,
} from "./seed.js";
export {
  LockV1,
  NoteName,
  NoteV1,
  newPKHLockV1,
  noteFirstV1,
  timelockAllows,
} from "./locks.js";
export type {
  HeightRange,
  TimelockV1,
  TimelockPolicy,
  RequiredPkhPolicy,
  NoteRecordV1,
} from "./locks.js";
export {
  MAX_TRANSFER_INPUTS,
  MAX_TRANSFER_OUTPUTS,
  MAX_NOTE_DATA_WORDS_V1,
  OutputV1,
  TransactionV1,
  prepareTransactionV1,
  parseTransactionV1,
  minimumTransactionFeeV1,
} from "./transaction.js";
export type {
  LockedPaymentV1,
  LockedSpendPlanV1,
  SpendSummaryV1,
  TransactionSummaryV1,
  TransactionOptions,
} from "./transaction.js";
export {
  PreparedTransfer,
  minimumTransferFeeV1,
  signTransferV1,
  prepareTransfer,
  selectTransfer,
} from "./wallet.js";
export type {
  UnspentNote,
  Payment,
  PaymentV1,
  SpendPlanV1,
  TransferOptions,
  TransferSummary,
} from "./wallet.js";

export {
  LockTreeV1,
  LockMerkleProof,
  buildLockMerkleProof,
  parseLock,
  validStubAxis,
} from "./lock-tree.js";
export type { LockFormV1 } from "./lock-tree.js";
export {
  NoteData,
  LockData,
  BridgeDepositDataPayload,
  BridgeWithdrawalDataPayload,
} from "./note-data.js";
export type { NoteDataPayload, DecodedNoteDataEntry } from "./note-data.js";
export {
  FeeParameters,
  ChainContext,
  computeMinimumFee,
  computeBridgeFee,
  transactionWords,
  noteDataWords,
} from "./fee.js";
export type {
  FeeParametersOptions,
  FeeBreakdown,
  WordCountBreakdown,
} from "./fee.js";
export {
  FundMaturity,
  FundMaturityPolicy,
  FundLockPolicy,
  LockResolution,
  SigningKeyLockMatcher,
  LockRootLockMatcher,
} from "./lock-resolver.js";
export type { LockMatcher } from "./lock-resolver.js";
export { PlannedOutput, plan } from "./planner.js";
export type { PlanRequest, PlanResult } from "./planner.js";

export { LockV0, NoteV0, noteFirstV0 } from "./migration.js";
export type { NoteRecordV0 } from "./migration.js";
