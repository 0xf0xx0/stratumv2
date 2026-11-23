package stratumv2

// flags
const (
// none yet
)

// The [CoinbaseOutputConstraints] message is used to indicate that some additional space and sigops
// in the block/coinbase transaction be reserved for the Client use
// (while always assuming the entirety of available coinbase space and sigops will be used).
//
// Client MUST discover the maximum serialized size of the additional outputs and sigops which will
// be added by the Pool(s) it intends to use this work with (in case of Job Declaration, discovered
// via [AllocateMiningJobTokenSuccess]). It then MUST communicate it to the Template Provider
// via [CoinbaseOutputConstraints].
//
// The Template Provider MUST NOT provide [NewTemplate] messages which would represent consensus-invalid
// blocks once this additional size and sigops — along with a maximally-sized (100 byte) coinbase
// script field — is added.
//
// Current sigops limit per block in bitcoin is 80_000 (as defined in BIP141).
// We are not aware of any use cases where a coinbase transaction has more than 65_535 sigops,
// so CoinbaseOutputMaxAdditionalSigops is a U16. Note that taproot outputs consume 0 sigops.
type CoinbaseOutputConstraints struct {
	CoinbaseOutputMaxAdditionalSize   uint32 // The maximum additional serialized bytes which Pool or JDC will add in coinbase transaction outputs.
	CoinbaseOutputMaxAdditionalSigops uint16 // The maximum additional sigops which Pool or JDC will add in coinbase transaction outputs.
}

// The primary template-providing message.
// Note that the [NewTemplate.CoinbaseTxOutputs] bytes will appear as is at the end of the coinbase transaction.
//
// Please note that differently from [SetCustomMiningJob.CoinbaseOutputs] and
// [AllocateMiningJobTokenSuccess.CoinbaseTxOutputs], [NewTemplate.CoinbaseTxOutputs] MUST NOT be
// serialized as a CompactSize-prefixed array. This field must simply carry the ordered sequence of
// consensus-serialized outputs, but the number of outputs MUST be inferred from
// [NewTemplate.CoinbaseTxOutputsCount]. This is the equivalent of taking a CompactSize-prefixed array
// and dropping its (outer) prefix.
//
// Please also note that if the block contains any SegWit transactions, [NewTemplate.CoinbaseTxOutputs]
// MUST carry the OP_RETURN output with the witness commitment. For blocks without SegWit transactions,
// the witness commitment output MAY still be included. The witness reserved value (Coinbase witness)
// used for calculating this witness commitment is assumed to be 32 bytes of 0x00, as it currently holds
// no consensus-critical meaning. This may change in future soft-forks.
type NewTemplate struct {
	// Server’s identification of the template.
	// Strictly increasing, the current UNIX time may be used in place of an ID.
	TemplateId uint64
	// True if the template is intended for a future [TemplateSetNewPrevHash] message.
	// If False, the template relates to the most recently received [TemplateSetNewPrevHash] message,
	// and the client SHOULD begin working on it immediately.
	FutureTemplate bool
	// Valid header version field that reflects the current network consensus.
	// The general purpose bits (as specified in BIP323) can be freely manipulated by the downstream node.
	// The downstream node MUST NOT rely on the upstream node to set the BIP323 bits to any particular value.
	Version           uint32
	CoinbaseTxVersion uint32 // The coinbase transaction nVersion field.
	// The leading bytes of the coinbase transaction's scriptSig, placed before the extranonce.
	// It MUST begin with the block height push required by BIP34.
	// The sender MUST NOT send a CoinbasePrefix longer than 8 bytes, excluding the B0_255 length prefix.
	CoinbasePrefix          B0_255
	CoinbaseTxInputSequence uint32 // The coinbase transaction input's nSequence field.
	// The value, in satoshis, available for spending in coinbase outputs added by the client.
	// Includes both transaction fees and block subsidy.
	CoinbaseTxValueRemaining uint64
	CoinbaseTxOutputsCount   uint32 // The number of transaction outputs included in [NewTemplate.CoinbaseTxOutputs].
	CoinbaseTxOutputs        B0_64K // Bitcoin transaction outputs to be included as the last outputs in the coinbase transaction.
	CoinbaseTxLocktime       uint32 // The locktime field in the coinbase transaction.
	MerklePath               []U256 // Merkle path hashes ordered from deepest.
}

// TD SetNewPrevHash, not mining protocol.
//
// Upon successful validation of a new best block, the server MUST immediately provide a [TemplateSetNewPrevHash] message.
//
// Prior to that, the server MUST send at least one, but potentially multiple [NewTemplate] messages
// with [NewTemplate.FutureTemplate] flag set. The client SHOULD keep track of all of them, and convert
// them into [NewMiningJob] and [NewExtendedMiningJob] messages (with empty ntime_start) in case it's
// also acting as a server under the Mining Protocol.
//
// If a [NewMiningJob] or [NewExtendedMiningJob] message has previously been sent with an empty
// ntime_start, and it is valid work based on the [TemplateSetNewPrevHash.PrevHash] contained in this
// message, the [TemplateSetNewPrevHash.TemplateId] field MUST be matched to the corresponding
// [NewTemplate] message that generated the [NewMiningJob] or [NewExtendedMiningJob], and a Mining
// Protocol [SetNewPrevHash] message MUST be sent indicating the client MUST begin mining on that job
// as soon as possible.
//
// After that, the future templates that were being kept in memory can be discarded,
// leaving room for future templates relative to the next [TemplateSetNewPrevHash].
type TemplateSetNewPrevHash struct {
	TemplateId uint64 // TemplateId referenced in a previous [NewTemplate] message.
	PrevHash   U256   // Previous block’s hash, as it must appear in the next block's header.
	// The nTime field in the block header at which hashing starts, usually the current time
	// when this message was produced. This is not the consensus minimum.
	NtimeStart uint32
	// The nBits field as it must appear in the candidate block's header.
	// Across a difficulty adjustment, this differs from the previous block's nBits.
	NBits uint32
	// The maximum double-SHA256 hash value which would represent a valid block.
	// Note that this may be lower than the target implied by nBits in several cases,
	// including weak-block based block propagation.
	Target U256
}

// A request sent by the Job Declarator to the Template Provider which requests the set of transaction
// data for all transactions (excluding the coinbase transaction) included in a block,
// as well as any additional data which may be required by the Pool to validate the work.
type RequestTransactionData struct {
	TemplateId uint64 // The TemplateId corresponding to a [NewTemplate] message.
}

// A response to [RequestTransactionData] which contains the set of full transaction data and excess data required for validation.
// For practical purposes, the excess data is usually the SegWit commitment, however the Job Declarator
// MUST NOT parse or interpret the excess data in any way.
// Note that the transaction data MUST be treated as opaque blobs and MUST include any SegWit or other
// data which the Pool may require to verify the transaction.
// For practical purposes, the transaction data is likely the witness-encoded transaction today.
// However, to ensure backward compatibility, the transaction data MAY be encoded in a way that is
// different from the consensus serialization of Bitcoin transactions.
//
// Ultimately, having some method of negotiating the specific format of transactions between the
// Template Provider and the Pool’s Template verification node would be overly burdensome, thus the
// following requirements are made explicit. The [RequestTransactionDataSuccess] sender MUST ensure
// that the data is provided in a forwards- and backwards-compatible way to ensure the end receiver
// of the data can interpret it, even in the face of new, consensus-optional data. This allows
// significantly more flexibility on both the [RequestTransactionDataSuccess]-generating and
// -interpreting sides during upgrades, at the cost of breaking some potential optimizations which
// would require version negotiation to provide support for previous versions. For practical purposes,
// and as a non-normative suggested implementation for Bitcoin Core, this implies that additional
// consensus-optional data be appended at the end of transaction data. It will simply be ignored by
// versions which do not understand it.
type RequestTransactionDataSuccess struct {
	TemplateId      uint64   // The TemplateId corresponding to a [NewTemplate] or [RequestTransactionData] message.
	ExcessData      B0_64K   // Extra data which the Pool may require to validate the work.
	TransactionList []B0_16M // Full transactions from the referenced template, excluding the coinbase transaction, in block order.
}

// An error response to [RequestTransactionData].
type RequestTransactionDataError struct {
	TemplateId uint64   // The TemplateId corresponding to a [NewTemplate] or [RequestTransactionData] message.
	ErrorCode  STR0_255 // Reason why no transaction data has been provided.
}

// Upon finding a coinbase transaction/nonce pair which double-SHA256 hashes at or below
// [TemplateSetNewPrevHash.Target], the client MUST immediately send this message, and the server
// MUST then immediately construct the corresponding full block and attempt to propagate it to the
// Bitcoin network.
//
// Differently from [NewExtendedMiningJob], if the original coinbase is a SegWit transaction,
// [SubmitSolution.CoinbaseTx] MUST NOT be stripped of BIP141 fields (marker, flag, witness count,
// witness length and witness reserved value).
type SubmitSolution struct {
	TemplateId uint64 // The TemplateId field as it appeared in [NewTemplate].
	// The version field in the block header.
	// Bits not defined by BIP323 as additional nonce MUST be the same as they appear in the
	// [NewTemplate] message, other bits may be set to any value.
	Version uint32
	// The nTime field in the block header.
	// This MUST be greater than or equal to the NtimeStart field in the latest [TemplateSetNewPrevHash] message.
	// No protocol-level upper bound is imposed: network rules already reject a block header nTime
	// too far in the future.
	Ntime      uint32
	Nonce      uint32 // The nonce field in the header.
	CoinbaseTx B0_64K // The full serialized coinbase transaction, meeting all the requirements of the [NewTemplate] message.
}
