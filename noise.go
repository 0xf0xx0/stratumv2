// a Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256 implementation.
package stratumv2

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/hex"
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
func (hs *HandshakeState) PerformHandshakeInitiator(rw io.ReadWriter, authorityPubkey [32]byte) (*CipherState, *CipherState, error) {
	c1 := &CipherState{}
	c2 := &CipherState{}

	/// 4.5.1 Handshake Act 1: NX-handshake part 1
	ck, h := handshakeInit()
	hs.cs = &CipherState{}
	hs.ck = [32]byte(ck)
	hs.h = [32]byte(h)

	/// 4.5.1.1
	/// "initializes empty output buffer"
	out := bytes.Buffer{}
	/// "generates ephemeral keypair e, appends e.public_key.serializeEllSwift() to the buffer (64 bytes plaintext EllSwift encoded public key)"
	// ephemeral := GenerateKeypair()
	ephemeral := GenerateKeypairFromBytes([32]byte(hexDec("751811a408603c54c4a07cd8d24757760d9f86e76192265bf1961452df5923c6")))
	println(fmt.Sprintf("initiatior ellswift: %x", ephemeral.SerializeEllswift()))
	out.Write(ephemeral.SerializeEllswift())

	/// "calls MixHash(e.public_key)"
	hs.MixHash(ephemeral.PublicKeyBytes())
	/// "calls EncryptAndHash() with empty payload and appends the ciphertext to the buffer"
	/// could be hs.MixHash([]byte{})
	hs.EncryptAndHash([]byte{})

	rw.Write(out.Bytes())
	out.Reset()

	/// 4.5.2.2
	pt2 := make([]byte, 234)
	rw.Read(pt2)
	remoteEphemeral := pt2[:64]
	encryptedStatic := pt2[64:144]
	encryptedCert := pt2[144:]

	hs.MixHash(remoteEphemeral)
	hs.MixKey(hs.ECDH(ephemeral, [64]byte(remoteEphemeral), true))
	plainStatic, err := hs.DecryptAndHash(encryptedStatic)
	if err != nil {
		return nil, nil, err
	}
	fmt.Println(SerializeAuthorityKey(plainStatic))
	plainCert, err := hs.DecryptAndHash(encryptedCert)
	cert := &SIGNATURE_NOISE_MESSAGE{}
	cert.Decode(plainCert)
	fmt.Printf("%+v", cert)

	temp_k1, temp_k2 := HKDF(hs.ck[:], []byte{})

	c1.InitializeKey(temp_k1)
	c2.InitializeKey(temp_k2)
	return c1, c2, nil
}
func (hs *HandshakeState) PerformHandshakeResponder(rw io.ReadWriter, cert *SIGNATURE_NOISE_MESSAGE, staticKeys *Keypair) (c2s *CipherState, s2c *CipherState, err error) {
	c2s = &CipherState{}
	s2c = &CipherState{}

	/// 4.5.1 Handshake Act 1: NX-handshake part 1
	ck, h := handshakeInit()
	hs.cs = &CipherState{}
	hs.ck = [32]byte(ck)
	hs.h = [32]byte(h)

	println(fmt.Sprintf("Init ck=%x", hs.ck))
	println(fmt.Sprintf("Init  h=%x", hs.h))

	/// 4.5.1.2
	remoteEphemeral := make([]byte, 64)
	rw.Read(remoteEphemeral)
	println(fmt.Sprintf("got initiator ellswift: %x", remoteEphemeral))
	hs.MixHash(remoteEphemeral)
	println(fmt.Sprintf("After MixHash(re): h=%x", hs.h))

	hs.DecryptAndHash([]byte{})
	println(fmt.Sprintf("After DecryptAndHash(empty): h=%x", hs.h))

	/// 4.5.2 Handshake Act 2: NX-handshake part 2
	/// 4.5.2.1
	out := bytes.Buffer{}
	// ephemeral := GenerateKeypair()
	ephemeral := GenerateKeypairFromBytes([32]byte(hexDec("8550d0f282bef7572b3786fa204b032d8ca647d5c7b4e997a47f7bf6d67dcd2f")))

	hs.MixHash(ephemeral.PublicKeyBytes())
	println(fmt.Sprintf("After MixHash(se): h=%x", hs.h))

	hs.MixKey(hs.ECDH(ephemeral, [64]byte(remoteEphemeral), false))
	println(fmt.Sprintf("After MixKey(ee): ck=%x", hs.ck))

	println(fmt.Sprintf("h (AD for encrypt static): h=%x", hs.h))
	println(fmt.Sprintf("Static pub (plaintext): %x", staticKeys.SerializeEllswift()))

	x := hs.EncryptAndHash(staticKeys.SerializeEllswift())
	out.Write(x)
	println(fmt.Sprintf("Encrypted static (%d bytes): %x", len(x), x))

	hs.MixKey(hs.ECDH(staticKeys, [64]byte(remoteEphemeral), false))
	println(fmt.Sprintf("After MixKey(es): ck=%x", hs.ck))

	certBytes, err := cert.Encode()
	if err != nil {
		return nil, nil, err
	}

	println(fmt.Sprintf("h (AD for encrypt cert): h=%x", hs.h))
	println(fmt.Sprintf("Cert payload (%d bytes): %x", len(certBytes), certBytes))

	x1 := hs.EncryptAndHash(certBytes)
	out.Write(x1)
	println(fmt.Sprintf("Encrypted cert (%d bytes)", len(x1)))

	rw.Write(out.Bytes())
	out.Reset()

	temp_k1, temp_k2 := HKDF(ck, []byte{})

	c2s.InitializeKey(temp_k1)
	s2c.InitializeKey(temp_k2)
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
	return cs.gcm.Seal(plaintext[:0], cs.getNonce(), plaintext, ad)
}
func (cs *CipherState) DecryptWithAd(ad, ciphertext []byte) ([]byte, error) {
	if len(cs.k) == 0 {
		return ciphertext, nil
	}
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
	payloadLen := PlainTextLenToCipherTextLen(int(frame.MessageLength))
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

func PlainTextLenToCipherTextLen(plainTextLen int) int {
	rem := plainTextLen % ChunkSize
	if rem > 0 {
		rem += MacLen
	}
	return plainTextLen/ChunkSize*MaxNoiseFrameSize + rem
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

// func DecodeAuthorityPrivkey(privkey []byte) (*btcec.PrivateKey, error) {
// 	priv := btcec.PrivKeyFromBytes(privkey)
// 	pub := ellswift.	return
// }

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

// generates and returns a fresh secp256k1 keypair
func GenerateKeypair() *Keypair {
	/// only error comes from crypto/rand Read, which never errors
	priv, ellswiftPub, _ := ellswift.EllswiftCreate()
	return &Keypair{
		Private:        priv,
		Public:         priv.PubKey(),
		PublicEllswift: ellswiftPub,
	}
}

// TODO: only for testing?
func GenerateKeypairFromBytes(b [32]byte) *Keypair {
	priv, _ := btcec.PrivKeyFromBytes(b[:])

	// Fetch the x-coordinate of the public key.
	x := getXCoord(priv)

	// Get the ElligatorSwift encoding of the public key.
	// FIXME: non-deterministic
	u, t, err := ellswift.XElligatorSwift(x)
	if err != nil {
		return nil
	}

	uBytes := u.Bytes()
	tBytes := t.Bytes()

	// ellswift_pub = bytes(u) || bytes(t), its encoding as 64 bytes
	var ellswiftPub [64]byte
	copy(ellswiftPub[0:32], (*uBytes)[:])
	copy(ellswiftPub[32:64], (*tBytes)[:])

	return &Keypair{
		Private:        priv,
		Public:         priv.PubKey(),
		PublicEllswift: ellswiftPub,
	}
}
func getXCoord(privKey *btcec.PrivateKey) *btcec.FieldVal {
	var result btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&privKey.Key, &result)
	result.ToAffine()
	return &result.X
}
func hexDec(s string) []byte {
	x, _ := hex.DecodeString(s)
	return x
}
