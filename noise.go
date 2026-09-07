// a Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256 implementation.
package stratumv2

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"time"

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

func (m *SIGNATURE_NOISE_MESSAGE) Decode(data []byte) error {
	if len(data) != 74 {
		return errors.New("invalid signature noise message length")
	}
	r := NewBinaryReader(data)
	m.Version = r.ReadU16()
	m.ValidFrom = r.ReadU32()
	m.NotValidAfter = r.ReadU32()
	m.Signature = r.ReadBytes(64)
	return nil
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
	Private        *btcec.PrivateKey
	Public         *btcec.PublicKey
	publicX        []byte   // X-coordinate of the public key
	PublicEllswift [64]byte // EllSwift encoded serialization of the X-coordinate of EC point
}

func (kp *Keypair) SerializeEllswift() []byte {
	return kp.PublicEllswift[:]
}
func (kp *Keypair) PublicKeyBytes() []byte {
	if kp.publicX != nil {
		return kp.publicX
	}
	kp.publicX = kp.Public.X().FillBytes(make([]byte, 32))
	return kp.publicX
}

type HandshakeState struct {
	cs    *CipherState
	h     [32]byte // handshake hash. Accumulated hash of all handshake data that has been sent and received so far during the handshake process
	ck    [32]byte // chaining key. Accumulated hash of all previous ECDH outputs. At the end of the handshake `ck` is used to derive encryption key `k`.
	e, re Keypair  // ephemeral keys. Ephemeral key and remote party's ephemeral key, respectively.
	s, rs Keypair  // static keys. Static key and remote party's static key, respectively.
}

func (hs *HandshakeState) AuthServerCertificate(cert *SIGNATURE_NOISE_MESSAGE, staticPubkey []byte, authorityPubkey [32]byte) (bool, error) {
	return VerifyServerCertificate(cert, authorityPubkey, staticPubkey)
}

func VerifyServerCertificate(cert *SIGNATURE_NOISE_MESSAGE, authorityPubkey [32]byte, staticPubkey []byte) (bool, error) {
	now := time.Now()
	if cert.Version != CertificateFormatVersion {
		return false, errors.New("unsupported certificate format version")
	}
	if cert.ValidFrom > uint32(now.Unix()) {
		return false, errors.New("certificate is not yet valid")
	}
	if cert.NotValidAfter < uint32(now.Unix()) {
		return false, errors.New("certificate has expired")
	}

	sigBytes := cert.Signature[:]
	cert.Signature = nil

	buf, err := cert.Encode()
	if err != nil {
		return false, err
	}
	cert.Signature = sigBytes
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return false, err
	}
	pub, err := schnorr.ParsePubKey(authorityPubkey[:])
	if err != nil {
		return false, err
	}

	buf = append(buf, staticPubkey...)
	hash := sha256.Sum256(buf)
	return sig.Verify(hash[:], pub), nil
}
func (hs *HandshakeState) PerformHandshakeInitiator(rw io.ReadWriter, authorityPubkey [32]byte) (send, recv *CipherState, err error) {
	send = &CipherState{}
	recv = &CipherState{}

	/// 4.5.1 Handshake Act 1: NX-handshake part 1
	ck, h := handshakeInit()
	hs.cs = &CipherState{}
	hs.ck = [32]byte(ck)
	hs.h = [32]byte(h)
	ck = nil
	h = nil

	// println(fmt.Sprintf("[Initiator] Init ck=%x", hs.ck))
	// println(fmt.Sprintf("[Initiator] Init  h=%x", hs.h))

	/// 4.5.1.1
	/// "initializes empty output buffer"
	out := bytes.Buffer{}
	/// "generates ephemeral keypair e, appends e.public_key.serializeEllSwift() to the buffer (64 bytes plaintext EllSwift encoded public key)"
	ephemeral := GenerateKeypair()
	// println(fmt.Sprintf("[Initiatior] ellswift: %x", ephemeral.SerializeEllswift()))
	out.Write(ephemeral.SerializeEllswift())

	/// "calls MixHash(e.public_key)"
	/// ellswift ig?
	hs.MixHash(ephemeral.SerializeEllswift())
	// println(fmt.Sprintf("[Initiatior] After MixHash(e): h=%x", hs.h))
	/// "calls EncryptAndHash() with empty payload and appends the ciphertext to the buffer"
	/// could be hs.MixHash([]byte{})
	hs.EncryptAndHash([]byte{})
	// println(fmt.Sprintf("[Initiatior] After EncryptAndHash(empty): h=%x", hs.h))

	rw.Write(out.Bytes())
	out.Reset()

	/// 4.5.2.2
	pt2 := make([]byte, 234)
	rw.Read(pt2)
	remoteEphemeral := pt2[:64]
	encryptedStatic := pt2[64:144]
	encryptedCert := pt2[144:]

	hs.MixHash(remoteEphemeral)
	// println(fmt.Sprintf("[Initiatior] got se: %x", remoteEphemeral))
	// println(fmt.Sprintf("[Initiatior] got es: %x", encryptedStatic))
	// println(fmt.Sprintf("[Initiatior] After MixHash(se): h=%x", hs.h))

	sharedeeDH := hs.ECDH(ephemeral, [64]byte(remoteEphemeral), true)
	// println(fmt.Sprintf("[Initiatior] ee DH shared secret: %x", sharedeeDH))
	hs.MixKey(sharedeeDH)

	// println(fmt.Sprintf("[Initiatior] h=%x", hs.h))
	plainStatic, err := hs.DecryptAndHash(encryptedStatic)
	if err != nil {
		return nil, nil, err
	}
	// println(fmt.Sprintf("[Initiatior] h=%x", hs.h))

	// println(fmt.Sprintf("[Initiatior] decrypted se: %x", plainStatic))

	sharedesDH := hs.ECDH(ephemeral, [64]byte(plainStatic), true)
	// println(fmt.Sprintf("[Initiatior] es DH shared secret: %x", sharedesDH))
	hs.MixKey(sharedesDH)
	// println(fmt.Sprintf("[Initiatior] After MixKey(es): ck=%x", hs.ck))
	// println(fmt.Sprintf("[Initiatior] h (AD for decrypt cert): h=%x", hs.h))

	// fmt.Println(SerializeAuthorityKey(plainStatic))
	plainCert, err := hs.DecryptAndHash(encryptedCert)
	if err != nil {
		return nil, nil, err
	}
	cert := &SIGNATURE_NOISE_MESSAGE{}
	if err := cert.Decode(plainCert); err != nil {
		println(len(encryptedCert))
		return nil, nil, err
	}
	// println(fmt.Sprintf("[Initiatior] got cert: %+v", cert))

	temp_k1, temp_k2 := HKDF(hs.ck[:], []byte{})
	// println(fmt.Sprintf("[Initiator] k1=%x, k2=%x", temp_k1, temp_k2))

	send.InitializeKey(temp_k1)
	recv.InitializeKey(temp_k2)
	return send, recv, nil
}
func (hs *HandshakeState) PerformHandshakeResponder(rw io.ReadWriter, cert *SIGNATURE_NOISE_MESSAGE, staticKeys *Keypair) (send, recv *CipherState, err error) {
	send = &CipherState{}
	recv = &CipherState{}

	/// 4.5.1 Handshake Act 1: NX-handshake part 1
	ck, h := handshakeInit()
	hs.cs = &CipherState{}
	hs.ck = [32]byte(ck)
	hs.h = [32]byte(h)
	ck = nil
	h = nil

	// println(fmt.Sprintf("[Responder] Init ck=%x", hs.ck))
	// println(fmt.Sprintf("[Responder] Init  h=%x", hs.h))

	/// 4.5.1.2
	remoteEphemeral := make([]byte, 64)
	rw.Read(remoteEphemeral)
	// println(fmt.Sprintf("[Responder] got ie: %x", remoteEphemeral))
	hs.MixHash(remoteEphemeral)
	// println(fmt.Sprintf("[Responder] After MixHash(ie): h=%x", hs.h))

	hs.DecryptAndHash([]byte{})
	// println(fmt.Sprintf("[Responder] After DecryptAndHash(empty): h=%x", hs.h))

	/// 4.5.2 Handshake Act 2: NX-handshake part 2
	/// 4.5.2.1
	out := bytes.Buffer{}
	ephemeral := GenerateKeypair()
	// println(fmt.Sprintf("[Responder] se: %x", ephemeral.SerializeEllswift()))
	out.Write(ephemeral.SerializeEllswift())

	hs.MixHash(ephemeral.SerializeEllswift())
	// println(fmt.Sprintf("[Responder] After MixHash(se): h=%x", hs.h))

	sharedeeDH := hs.ECDH(ephemeral, [64]byte(remoteEphemeral), false)
	// println(fmt.Sprintf("[Responder] ee DH shared secret: %x", sharedeeDH))
	hs.MixKey(sharedeeDH)
	// println(fmt.Sprintf("[Responder] After MixKey(ee): ck=%x", hs.ck))

	// println(fmt.Sprintf("[Responder] h (AD for encrypt static): h=%x", hs.h))
	// println(fmt.Sprintf("[Responder] Static pub (plaintext): %x", staticKeys.SerializeEllswift()))

	out.Write(hs.EncryptAndHash(staticKeys.SerializeEllswift()))
	// println(fmt.Sprintf("[Responder] Encrypted static (%d bytes): %x", len(x), x))

	sharedesDH := hs.ECDH(staticKeys, [64]byte(remoteEphemeral), false)
	// println(fmt.Sprintf("[Responder] es DH shared secret (responder): %x", sharedesDH))

	hs.MixKey(sharedesDH)
	// println(fmt.Sprintf("[Responder] After MixKey(es): ck=%x", hs.ck))

	certBytes, err := cert.Encode()
	if err != nil {
		return nil, nil, err
	}

	// println(fmt.Sprintf("[Responder] h (AD for encrypt cert): h=%x", hs.h))
	// println(fmt.Sprintf("[Responder] Cert payload (%d bytes): %x", len(certBytes), certBytes))

	out.Write(hs.EncryptAndHash(certBytes))
	rw.Write(out.Bytes())
	out.Reset()

	temp_k1, temp_k2 := HKDF(hs.ck[:], []byte{})
	// println(fmt.Sprintf("[Responder] k1=%x, k2=%x", temp_k1, temp_k2))

	send.InitializeKey(temp_k1)
	recv.InitializeKey(temp_k2)
	// initiator->responder, responder->initiator
	// (c2s, s2c)
	return send, recv, nil
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
	hs.MixHash(ciphertext)
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
func (hs *HandshakeState) ECDH(k *Keypair, rk [64]byte, initiator bool) []byte {
	hash, err := ellswift.V2Ecdh(k.Private, rk, [64]byte(k.SerializeEllswift()), initiator)
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

// TODO: only for testing, remove
func (cs *CipherState) GetKey() []byte {
	return cs.k
}
func (cs *CipherState) GetNonce() []byte {
	nonce := make([]byte, 12)
	ble.PutUint64(nonce[4:], cs.n)
	return nonce
}

func (cs *CipherState) InitializeKey(k []byte) error {
	cs.k = k[:]
	cs.n = 0
	var err error
	cs.gcm, err = chacha20poly1305.New(cs.k)
	if err != nil {
		return err
	}
	return nil
}
func (cs *CipherState) getNonce() []byte {
	/// "...with nonce n encoded as 32 zero bits, followed by a little-endian 64-bit value."
	nonce := make([]byte, 12)
	ble.PutUint64(nonce[4:], cs.n)
	cs.n++
	return nonce
}
func (cs *CipherState) EncryptWithAd(ad, plaintext []byte) []byte {
	if len(cs.k) == 0 {
		return plaintext
	}
	return cs.gcm.Seal(make([]byte, 0, PlainTextLenToCipherTextLen(len(plaintext))), cs.getNonce(), plaintext, ad)
}
func (cs *CipherState) DecryptWithAd(ad, ciphertext []byte) ([]byte, error) {
	if len(cs.k) == 0 {
		return ciphertext, nil
	}
	/// FIXME: why cant we reuse ciphertext here?
	out, err := cs.gcm.Open(make([]byte, 0, len(ciphertext)), cs.getNonce(), ciphertext, ad)
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
	out := cs.EncryptWithAd([]byte{}, encoded[FrameHeaderSize:])

	return append(header, out...), nil
}
func (cs *CipherState) DecryptFrame(r io.Reader) (Frame, error) {
	frame := Frame{}
	/// decrypt the header
	header := make([]byte, NoiseHeaderSize)
	read, err := io.ReadFull(r, header)

	if err != nil {
		return Frame{}, fmt.Errorf("error while reading header: %s", err)
	}
	if read < NoiseHeaderSize {
		return Frame{}, errors.New("ciphertext too short")
	}

	decrypted, err := cs.DecryptWithAd([]byte{}, header)
	if err != nil {
		return Frame{}, fmt.Errorf("error while decrypting header: %s", err)
	}

	frame.DecodeHeader(decrypted)

	/// now decrypt payload
	payloadLen := PlainTextLenToCipherTextLen(int(frame.MessageLength))
	payload := make([]byte, payloadLen)
	read, err = io.ReadFull(r, payload)

	if err != nil {
		return Frame{}, fmt.Errorf("error while reading payload: %s", err)
	}
	if read < payloadLen {
		return Frame{}, errors.New("ciphertext too short")
	}
	decrypted, err = cs.DecryptWithAd([]byte{}, payload)
	if err != nil {
		return Frame{}, fmt.Errorf("error while decrypting payload: %s", err)
	}
	frame.Payload = decrypted
	return frame, nil
}

/// util funcs

func PlainTextLenToCipherTextLen(plainTextLen int) int {
	rem := plainTextLen % MaxPlaintextChunkSize
	if rem > 0 {
		rem += MacLen
	}
	return plainTextLen/MaxPlaintextChunkSize*MaxNoiseFrameSize + rem
}

// TODO: authority key struct?
// TODO: load auth keypair somehow? surely theres a standard...
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

// create and sign a [SIGNATURE_NOISE_MESSAGE]
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

func HmacHash(key, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}
func HKDF(chainingKey, inputKeyMaterial []byte) ([]byte, []byte) {
	temp := HmacHash(chainingKey, inputKeyMaterial)
	out1 := HmacHash(temp, []byte{0x01})
	out2 := HmacHash(temp, append(out1, 0x02))
	return out1, out2
}
func TaggedHash(a, b, c []byte) []byte {
	hash := sha256.New()
	/// SHA256("bip324_ellswift_xonly_ecdh")
	tag := hash.Sum([]byte("bip324_ellswift_xonly_ecdh"))[:]
	hash.Reset()
	/// SHA256(concatenate(tag, tag, a, b, c))
	hash.Write(tag)
	hash.Write(tag)
	hash.Write(a)
	hash.Write(b)
	hash.Write(c)
	return hash.Sum(nil)[:]
}
func handshakeInit() ([]byte, []byte) {
	hash := sha256.New()
	hash.Write([]byte(ProtocolName))
	digest := hash.Sum(nil)
	initialChainingKey := digest[:]
	hash.Reset()
	hash.Write(digest)
	hashOutput := hash.Sum(nil)
	return initialChainingKey, hashOutput
}

// generates and returns a fresh secp256k1 [Keypair]
func GenerateKeypair() *Keypair {
	/// only error comes from crypto/rand Read, which never errors
	priv, ellswiftPub, _ := ellswift.EllswiftCreate()
	return &Keypair{
		Private:        priv,
		Public:         priv.PubKey(),
		PublicEllswift: ellswiftPub,
	}
}
