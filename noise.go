package stratumv2

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/ascii85"
	"errors"
	"io"

	"github.com/btcsuite/btcd/address/v2/base58"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ellswift"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/minio/sha256-simd"
	"golang.org/x/crypto/chacha20poly1305"
)

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

type Keypair struct {
	privkey *btcec.PrivateKey
	pubkey  [64]byte // EllSwift encoded serialization of the X-coordinate of EC point
}

func GenerateKeypair() (kp *Keypair, err error) {
	b := make([]byte, 32)
	rand.Read(b)
	secret_key, serialized_pubkey, err := ellswift.EllswiftCreate()
	if err != nil {
		return nil, err
	}
	return &Keypair{privkey: secret_key, pubkey: serialized_pubkey}, nil
}

type HandshakeState struct {
	cs    *CipherState
	h     [32]byte // handshake hash. Accumulated hash of all handshake data that has been sent and received so far during the handshake process
	ck    [32]byte // chaining key. Accumulated hash of all previous ECDH outputs. At the end of the handshake `ck` is used to derive encryption key `k`.
	e, re Keypair  // ephemeral keys. Ephemeral key and remote party's ephemeral key, respectively.
	s, rs Keypair  // static keys. Static key and remote party's static key, respectively.
}

func (hs *HandshakeState) PerformHandshakeInitiator(r io.Reader, w io.Writer) (*CipherState, *CipherState, error) {
	c1 := &CipherState{}
	c2 := &CipherState{}

	/// 4.5.1
	initialChainingKey, hashOutput := handshakeInit()
	ephemeralKeys, err := GenerateKeypair()
	if err != nil {
		return nil, nil, err
	}
	handshake := &HandshakeState{
		ck: [32]byte(initialChainingKey),
		h:  [32]byte(hashOutput),
		cs: &CipherState{},
		e:  *ephemeralKeys,
	}

	/// 4.5.1.1
	buf := make([]byte, 0, 512)
	buf = append(buf, handshake.e.pubkey[:]...)
	handshake.MixHash(handshake.e.pubkey[:])
	handshake.EncryptAndHash([]byte{})
	w.Write(buf)

	/// 4.5.2.2
	buf = make([]byte, 170)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return nil, nil, err
	}
	bufidx := 64
	handshake.re.pubkey = [64]byte(buf[:bufidx])
	handshake.MixHash(handshake.re.pubkey[:])
	handshake.MixKey(handshake.ECDH(handshake.e, handshake.re.pubkey, true))

	serverStaticPub, err := handshake.DecryptAndHash(buf[bufidx : bufidx+80])
	bufidx += 80
	if err != nil {
		return nil, nil, err
	}
	handshake.rs.pubkey = [64]byte(serverStaticPub)
	handshake.MixKey(handshake.ECDH(handshake.e, handshake.rs.pubkey, true))

	sigbytes, err := handshake.DecryptAndHash(buf[bufidx : bufidx+90])
	bufidx += 90
	if err != nil {
		return nil, nil, err
	}
	m := &SIGNATURE_NOISE_MESSAGE{}
	err = m.Decode(sigbytes)
	if err != nil {
		return nil, nil, err
	}

	tempk1, tempk2 := HKDF(handshake.ck[:], []byte{})

	c1.InitializeKey(tempk1)
	c2.InitializeKey(tempk2)

	return c1, c2, nil
}
func (hs *HandshakeState) PerformHandshakeResponder(r io.Reader, cert *SIGNATURE_NOISE_MESSAGE, staticKeys *Keypair) (*CipherState, *CipherState, error) {
	c2s := &CipherState{}
	s2c := &CipherState{}

	/// 4.5.1
	initialChainingKey, hashOutput := handshakeInit()

	ephemeralKeys, err := GenerateKeypair()
	if err != nil {
		return nil, nil, err
	}
	handshake := &HandshakeState{
		ck: [32]byte(initialChainingKey),
		h:  [32]byte(hashOutput),
		cs: &CipherState{},
		e:  *ephemeralKeys,
		s:  *staticKeys,
	}

	/// 4.5.1.2
	remoteEPubkey := make([]byte, 64)
	_, err = io.ReadFull(r, remoteEPubkey)
	if err != nil {
		return nil, nil, err
	}
	handshake.re.pubkey = [64]byte(remoteEPubkey)
	handshake.MixHash(remoteEPubkey)
	_, err = handshake.DecryptAndHash([]byte{})
	if err != nil {
		return nil, nil, err
	}

	/// 4.5.2.1
	buf := make([]byte, 0, 512)
	buf = append(buf, handshake.e.pubkey[:]...)
	handshake.MixHash(handshake.e.pubkey[:])
	handshake.MixKey(handshake.ECDH(handshake.e, handshake.re.pubkey, false))

	/// static keys come from user
	buf = append(buf, handshake.EncryptAndHash(handshake.s.pubkey[:])...)
	handshake.MixKey(handshake.ECDH(handshake.s, handshake.re.pubkey, false))
	certBytes, err := cert.Encode()
	if err != nil {
		return nil, nil, err
	}

	buf = append(buf, handshake.EncryptAndHash(certBytes)...)
	tempk1, tempk2 := HKDF(handshake.ck[:], []byte{})

	c2s.InitializeKey(tempk1)
	s2c.InitializeKey(tempk2)

	// initiator->responder, responder->initiator
	// (c2s, s2c)
	return c2s, s2c, nil
}

func (hs *HandshakeState) EncryptAndHash(plaintext []byte) []byte {
	var ciphertext []byte
	if len(hs.cs.k) != 0 {
		ciphertext = hs.cs.EncryptWithAd(hs.h[:], plaintext)
	} else {
		ciphertext = plaintext
	}
	hs.MixHash(ciphertext)
	return ciphertext
}
func (hs *HandshakeState) DecryptAndHash(ciphertext []byte) ([]byte, error) {
	var plaintext []byte
	var err error
	if len(hs.cs.k) != 0 {
		plaintext, err = hs.cs.DecryptWithAd(hs.h[:], ciphertext)
		if err != nil {
			return nil, err
		}
	} else {
		plaintext = ciphertext
	}
	hs.MixHash(plaintext)
	return plaintext, err
}
func (hs *HandshakeState) MixHash(data []byte) {
	hs.h = sha256.Sum256(append(hs.h[:], data...))
}
func (hs *HandshakeState) MixKey(inputKeyMaterial []byte) {
	ck, temp := HKDF(hs.ck[:], inputKeyMaterial)
	hs.ck = [32]byte(ck)
	hs.cs.InitializeKey(temp)
}
func (hs *HandshakeState) ECDH(k Keypair, rk [64]byte, initiator bool) []byte {
	hash, err := ellswift.V2Ecdh(k.privkey, rk, k.pubkey, initiator)
	if err != nil {
		panic(err)
	}
	return hash[:]
}

// Object that encapsulates encryption and decryption operations with underlying AEAD mode
// cipher functions using 32-byte encryption key `k` and 8-byte nonce `n`.
type CipherState struct {
	k   []byte // encryption key
	n   uint64
	gcm cipher.AEAD
}

func (cs *CipherState) InitializeKey(k []byte) {
	cs.k = k[:]
	cs.n = 0
	var err error
	cs.gcm, err = chacha20poly1305.New(cs.k)
	if err != nil {
		panic(err)
	}
}
func (cs *CipherState) getNonce() []byte {
	/// "...with nonce n encoded as 32 zero bits, followed by a little-endian 64-bit value."
	nonce := make([]byte, 12)
	ble.PutUint64(nonce[4:], cs.n)
	cs.n++
	return nonce
}
func (cs *CipherState) EncryptWithAd(ad, plaintext []byte) []byte {
	/// TODO: this may need a new output slice to store the larger ciphertext
	return cs.gcm.Seal(plaintext[:0], cs.getNonce(), plaintext, ad)
}
func (cs *CipherState) DecryptWithAd(ad, ciphertext []byte) ([]byte, error) {
	out, err := cs.gcm.Open(ciphertext[:0], cs.getNonce(), ciphertext, ad)
	if err != nil {
		cs.n--
		return nil, err
	}
	return out, nil
}

func (cs *CipherState) EncryptFrame(frame Frame) ([]byte, error) {
	encoded, err := frame.Encode()
	if err != nil {
		return nil, err
	}
	header := cs.EncryptWithAd([]byte{}, encoded[:FrameHeaderSize])
	payload := cs.EncryptWithAd([]byte{}, encoded[FrameHeaderSize:])

	return append(header, payload...), nil
}
func (cs *CipherState) DecryptFrame(r io.Reader) (Frame, error) {
	frame := Frame{}
	/// decrypt the header
	header := make([]byte, NoiseHeaderSize)
	read, err := r.Read(header)
	if err != nil {
		return Frame{}, err
	}
	if read < NoiseHeaderSize {
		return Frame{}, errors.New("ciphertext too short")
	}
	decrypted, err := cs.DecryptWithAd([]byte{}, header)
	if err != nil {
		return Frame{}, err
	}
	frame.DecodeHeader(decrypted)

	/// now decrypt payload
	payloadLen := plainTextLenToCipherTextLen(int(frame.MessageLength))
	payload := make([]byte, payloadLen)
	read, err = r.Read(payload)
	if err != nil {
		return Frame{}, err
	}
	if read < payloadLen {
		return Frame{}, errors.New("ciphertext too short")
	}
	decrypted, err = cs.DecryptWithAd([]byte{}, payload)
	if err != nil {
		return Frame{}, err
	}
	frame.Payload = decrypted
	return frame, nil
}

/// util funcs

func plainTextLenToCipherTextLen(plainTextLen int) int {
	rem := plainTextLen % MaxPlainFrameSize
	if rem > 0 {
		rem += MacLen
	}
	return plainTextLen/MaxPlainFrameSize*MaxNoiseFrameSize + rem
}

// TODO: authority key struct?
func SerializeAuthorityKey(pubkey []byte) string {
	/// NOTE: workaround for checkencode only accepting 1 version byte
	/// sv2 wants uint16 prefix of [1, 0], so prefix the 0 to the pubkey and send
	/// 1 to checkencode to get the correct output
	pfx := []byte{0}
	return base58.CheckEncode(append(pfx, pubkey...), byte(1))
}
func DeserializeAuthorityKey(pubkey string) ([]byte, error) {
	decoded, version, err := base58.CheckDecode(pubkey)
	if err != nil {
		return nil, err
	}
	if version != 1 || decoded[0] != 0 {
		return nil, errors.New("invalid pubkey base58check version, not [1, 0]")
	}
	return decoded[1:], nil
}

// idk where this is in the docs
// copied from public-pool
func NewAuthoritySignature(authorityPrivkey *btcec.PrivateKey, staticPubkey []byte, validFrom, notValidAfter uint32) (*SIGNATURE_NOISE_MESSAGE, error) {
	m := &SIGNATURE_NOISE_MESSAGE{
		Version:       CertificateFormatVersion,
		ValidFrom:     validFrom,
		NotValidAfter: notValidAfter,
	}
	buf, err := m.Encode()
	if err != nil {
		return nil, err
	}
	buf = append(buf, staticPubkey...)
	hash := sha256.Sum256(buf)
	sig, err := schnorr.Sign(authorityPrivkey, hash[:])
	if err != nil {
		return nil, err
	}
	m.Signature = sig.Serialize()
	return m, nil
}

func hmacHash(key, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}
func HKDF(chainingKey, inputKeyMaterial []byte) ([]byte, []byte) {
	temp := hmacHash(chainingKey, inputKeyMaterial)
	out1 := hmacHash(temp, []byte{0x01})
	out2 := hmacHash(temp, append(out1, 0x02))
	return out1, out2
}

func handshakeInit() ([]byte, []byte) {
	hash := sha256.New()
	dst := make([]byte, len(ProtocolName))
	ascii85.Encode(dst, []byte(ProtocolName))
	hash.Write(dst)
	digest := hash.Sum(nil)
	initialChainingKey := digest[:]
	hash.Reset()
	hash.Write(digest)
	hashOutput := hash.Sum(nil)
	return initialChainingKey, hashOutput
}
