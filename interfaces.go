package stratumv2

// MAYBE: merge into types.go

// most structs implement this interface
type Codable interface {
	Encode() ([]byte, error)
	Decode([]byte) error
	// DecodeFromReader(r io.Reader) error
	// MAYBE: String() string for pretty-printing?
}

// implemented by [NoiseFrame]
type Encryptable interface {
	Encrypt() ([]byte, error)
}

// implemented by [NoiseFrame]
type Decryptable interface {
	Decrypt([]byte) error
}

// implemented by [NoiseFrame]
type Cryptable interface {
	Encryptable
	Decryptable
}
