package stratumv2

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/btcsuite/btcd/btcec/v2/ellswift"
	"github.com/flynn/noise"
)

type NoiseFrame struct {
	Header  []byte
	Payload []byte
	Frame   Frame // decoded header + payload, populated by Decrypt
}

// Encrypt encrypts the frame into the header and payload.
func (n *NoiseFrame) Encrypt() ([]byte, error) {
	panic("UNIMPL")
}

// Decrypt decrypts the full frame and stores it in [NoiseFrame.Frame].
func (n *NoiseFrame) Decrypt(b []byte) error {
	// while rem >=65535, read, decrypt, append, then read any rem?
	if err := n.DecryptHeader(b); err != nil {
		return err
	}
	return n.DecryptPayload(b)
}

// DecryptPayload decrypts just the payload and stores it in [NoiseFrame.Frame].
// Must be called after [NoiseFrame.DecryptHeader].
func (n *NoiseFrame) DecryptPayload(b []byte) error {
	n.Payload = make([]byte, plainTextLenToCipherTextLen(int(n.Frame.MessageLength)))
	copy(n.Payload, b[NoiseHeaderSize:])
	/// TODO: decrypt payload
	rem := len(n.Payload)
	plainTextPayload := make([]byte, 0, int(n.Frame.MessageLength))
	for rem >= MaxNoiseFrameSize {
		// decrypt
		plainTextPayload = append(plainTextPayload)
	}
	if rem > 0 {
		// decrypt remaining payload
		plainTextPayload = append(plainTextPayload)
	}
	n.Frame.Payload = plainTextPayload
	return nil
}

// DecryptHeader decrypts just the header and stores it in [NoiseFrame.Frame].
func (n *NoiseFrame) DecryptHeader(b []byte) error {
	panic("UNIMPL")
}

// TODO: decrypt header, read MessageLength, convert to encrypted len, read payload, decrypt
func (n *NoiseFrame) DecryptFromReader(r io.Reader) error {
	var err error

	header := make([]byte, NoiseHeaderSize)
	if _, err = r.Read(header); err != nil {
		return err
	}

	if err = n.DecryptHeader(header); err != nil {
		return err
	}
	return nil
}

// for [Codable], just calls [NoiseFrame.Encrypt]
func (n *NoiseFrame) Encode() ([]byte, error) {
	return n.Encrypt()
}

// for [Codable], just calls [NoiseFrame.Decrypt]
func (n *NoiseFrame) Decode(b []byte) error {
	return n.Decrypt(b)
}

// for [Codable], just calls [NoiseFrame.DecryptFromReader]
func (n *NoiseFrame) DecodeFromReader(r io.Reader) error {
	return n.DecryptFromReader(r)
}

type SIGNATURE_NOISE_MESSAGE struct {
	Version       uint16 // Version of the certificate format
	ValidFrom     uint32 // Validity start time (unix timestamp)
	NotValidAfter uint32 // Signature is invalid after this point in time (unix timestamp)
	Signature     []byte // Certificate signature
}

func (m *SIGNATURE_NOISE_MESSAGE) Encode() ([]byte, error) {
	return NewBinaryBuilder().
		Grow(74).
		AddU16(m.Version).
		AddU32(m.ValidFrom).
		AddU32(m.NotValidAfter).
		AddBytes(m.Signature).
		Bytes()
}

func plainTextLenToCipherTextLen(plainTextLen int) int {
	rem := plainTextLen % MaxPlainFrameSize
	if rem > 0 {
		rem += MacLen
	}
	return plainTextLen/MaxPlainFrameSize*MaxNoiseFrameSize + rem
}

// hi hello this is NOTHING BUT BULLSHIT
// im figurin it out ;w; cwypto hawd
func InitCipherState() {
	/// 4.5.1
	hash := sha256.New()
	hash.Write([]byte(ProtocolName))
	digest := hash.Sum(nil)
	chainingKey := digest[:]
	hash.Reset()
	hash.Write(digest)
	hashOutput := hash.Sum(nil)

	var e, re noise.DHKey
	var s, rs noise.DHKey

	var buf bytes.Buffer
	buf.Grow(2048)

	pawshake, err := noise.NewHandshakeState(noise.Config{
		/// FIXME:wrong dhfunc? make one from btcd funcs?
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeNX,
		Initiator:   true,
	})
	if err != nil {
		panic(err)
	}

	// 4.5.1.1
	e = pawshake.LocalEphemeral()
	// TODO: get ellswift pubkey

	cipherSuite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

	_ = e
	_ = cipherSuite
	_ = pawshake
	_ = buf
	_ = hash
	_ = hashOutput
	_ = k
	_ = chainingKey
}

func GenerateKeypair() {
	b := make([]byte, 32)
	rand.Read(b)
	sk, pkb, _ := ellswift.EllswiftCreate()
}

func mixHash(a, b []byte) []byte {
	hash := sha256.Sum256(append(a, b...))
	return hash[:]
}
