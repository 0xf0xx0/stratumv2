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

// guhhhhhhhhhhhhhhhhhhhhhhhhhhh
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
func (m *SIGNATURE_NOISE_MESSAGE) EncodeNoSig() ([]byte, error) {
	return NewBinaryBuilder().
		Grow(10).
		AddU16(m.Version).
		AddU32(m.ValidFrom).
		AddU32(m.NotValidAfter).
		Bytes()
}

// Keypair stores a secp256k1 key and its ElligatorSwift-encoded public key.
type Keypair struct {
	Private        *btcec.PrivateKey
	Public         *btcec.PublicKey
	publicX        []byte   // X-coordinate of the public key
	publicEllswift [64]byte // EllSwift encoded serialization of the X-coordinate of EC point
}

// SerializeEllswift returns the ElligatorSwift-encoded public key as an [EllswiftPubkey].
func (kp *Keypair) SerializeEllswift() EllswiftPubkey {
	return kp.publicEllswift
}

// SerializeEllswiftBytes returns the ElligatorSwift-encoded public key as a byte array.
func (kp *Keypair) SerializeEllswiftBytes() []byte {
	return kp.publicEllswift[:]
}

// PublicKeyBytes returns the public key as a byte array.
func (kp *Keypair) PublicKeyBytes() []byte {
	return kp.publicX
}

// PublicKey returns the public key as a [Pubkey].
func (kp *Keypair) PublicKey() Pubkey {
	return Pubkey(kp.PublicKeyBytes())
}
func (kp *Keypair) Encode() ([]byte, error) {
	return NewBinaryBuilder().Grow(96).
		AddBytes(kp.Private.Serialize()).
		AddBytes(kp.publicEllswift[:]).
		Bytes()
}
func (kp *Keypair) Decode(b []byte) {
	br := NewBinaryReader(b)
	privkey := br.ReadBytes(32)
	ellswift := br.ReadBytes(64)
	kp.Private, kp.Public = btcec.PrivKeyFromBytes(privkey)
	kp.publicX = kp.Public.X().FillBytes(make([]byte, 32))
	kp.publicEllswift = EllswiftPubkey(ellswift)
}

// HandshakeState provides methods to initiate and receive handshakes.
type HandshakeState struct {
	cs           *CipherState
	h            [32]byte // handshake hash. Accumulated hash of all handshake data that has been sent and received so far during the handshake process
	ck           [32]byte // chaining key. Accumulated hash of all previous ECDH outputs. At the end of the handshake `ck` is used to derive encryption key `k`.
	cert         *SIGNATURE_NOISE_MESSAGE
	serverStatic EllswiftPubkey // used by the initiator for AuthServerCertificate
}

// VerifyServerCertificate is a wrapper around [VerifyServerCertificate].
func (hs *HandshakeState) VerifyServerCertificate(authorityPubkey Pubkey) (bool, error) {
	/// TODO: get X coord from static
	u := &btcec.FieldVal{}
	t := &btcec.FieldVal{}
	u.SetByteSlice(hs.serverStatic[:32])
	t.SetByteSlice(hs.serverStatic[32:])
	serverStaticX, err := ellswift.XSwiftEC(u, t)
	if err != nil {
		return false, err
	}
	// return VerifyServerCertificate(hs.cert, authorityPubkey, hs.serverStatic)
	return VerifyServerCertificate(hs.cert, authorityPubkey, *serverStaticX.Normalize().Bytes())
}

func VerifyServerCertificate(cert *SIGNATURE_NOISE_MESSAGE, authorityPubkey, staticPubkey Pubkey) (bool, error) {
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
	buf, err := cert.EncodeNoSig()
	if err != nil {
		return false, err
	}
	sig, err := schnorr.ParseSignature(cert.Signature)
	if err != nil {
		return false, err
	}
	pub, err := schnorr.ParsePubKey(authorityPubkey[:])
	if err != nil {
		return false, err
	}

	buf = append(buf, staticPubkey[:]...)
	hash := sha256.Sum256(buf)
	return sig.Verify(hash[:], pub), nil
}

// PerformHandshakeInitiator initiates a handshake with a remote party.
func (hs *HandshakeState) PerformHandshakeInitiator(rw io.ReadWriter) (send, recv *CipherState, err error) {
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
	/// "1. initializes empty output buffer"
	out := bytes.Buffer{}
	out.Grow(64)
	/// "2. generates ephemeral keypair e, appends e.public_key.serializeEllSwift() to the buffer (64 bytes plaintext EllSwift encoded public key)"
	ephemeral := NewKeypair()
	// println(fmt.Sprintf("[Initiatior] ellswift: %x", ephemeral.SerializeEllswift()))
	out.Write(ephemeral.SerializeEllswiftBytes())

	/// "3. calls MixHash(e.public_key)"
	hs.mixHash(ephemeral.SerializeEllswiftBytes())
	// println(fmt.Sprintf("[Initiatior] After MixHash(e): h=%x", hs.h))

	/// "4. calls EncryptAndHash() with empty payload and appends the ciphertext to the buffer"
	hs.encryptAndHash([]byte{})
	// println(fmt.Sprintf("[Initiatior] After EncryptAndHash(empty): h=%x", hs.h))

	rw.Write(out.Bytes())
	out.Reset()

	/// 4.5.2.2
	/// "1. receives NX-handshake part 2 message"
	pt2 := make([]byte, 234)
	rw.Read(pt2)
	/// "2. interprets first 64 bytes as EllSwift encoded re.public_key"
	remoteEphemeral := pt2[:64]
	encryptedStatic := pt2[64:144] /// 80 for static
	encryptedCert := pt2[144:]     /// rest is cert

	/// "3. calls MixHash(re.public_key)"
	hs.mixHash(remoteEphemeral)
	// println(fmt.Sprintf("[Initiatior] got se: %x", remoteEphemeral))
	// println(fmt.Sprintf("[Initiatior] got es: %x", encryptedStatic))
	// println(fmt.Sprintf("[Initiatior] After MixHash(se): h=%x", hs.h))

	/// "4. calls MixKey(ECDH(e.private_key, re.public_key))"
	sharedeeDH := hs.ecdh(ephemeral, EllswiftPubkey(remoteEphemeral), true)
	// println(fmt.Sprintf("[Initiatior] ee DH shared secret: %x", sharedeeDH))
	hs.mixKey(sharedeeDH)

	/// "5. decrypts next 80 bytes with DecryptAndHash() and
	/// 	   stores the results as rs.public_key which is server's static public key
	///     (note that 64 bytes is the public key and 16 bytes is MAC)"

	// println(fmt.Sprintf("[Initiatior] h=%x", hs.h))
	plainStatic, err := hs.decryptAndHash(encryptedStatic)
	if err != nil {
		return nil, nil, err
	}
	hs.serverStatic = EllswiftPubkey(plainStatic)
	// println(fmt.Sprintf("[Initiatior] h=%x", hs.h))

	// println(fmt.Sprintf("[Initiatior] decrypted se: %x", plainStatic))

	/// "6. calls MixKey(ECDH(e.private_key, rs.public_key)"
	sharedesDH := hs.ecdh(ephemeral, EllswiftPubkey(plainStatic), true)
	// println(fmt.Sprintf("[Initiatior] es DH shared secret: %x", sharedesDH))
	hs.mixKey(sharedesDH)
	// println(fmt.Sprintf("[Initiatior] After MixKey(es): ck=%x", hs.ck))
	// println(fmt.Sprintf("[Initiatior] h (AD for decrypt cert): h=%x", hs.h))
	// println(SerializeAuthorityKey(plainStatic))

	/// "7. decrypts next 90 bytes with DecryptAndHash() and deserialize plaintext into
	///     SIGNATURE_NOISE_MESSAGE (74 bytes data + 16 bytes MAC)"
	plainCert, err := hs.decryptAndHash(encryptedCert)
	if err != nil {
		return nil, nil, err
	}
	cert := &SIGNATURE_NOISE_MESSAGE{}
	if err := cert.Decode(plainCert); err != nil {
		// println(len(encryptedCert))
		return nil, nil, err
	}
	/// save cert for optional verification later
	hs.cert = cert
	// println(fmt.Sprintf("[Initiatior] got cert: %+v", cert))

	/// "8. return pair of CipherState objects, the first for encrypting transport messages
	///     from initiator to responder, and the second for messages in the other direction"
	temp_k1, temp_k2 := HKDF(hs.ck[:], []byte{})
	// println(fmt.Sprintf("[Initiator] k1=%x, k2=%x", temp_k1, temp_k2))

	send.InitializeKey([32]byte(temp_k1))
	recv.InitializeKey([32]byte(temp_k2))
	/// initiator->responder, responder->initiator
	return send, recv, nil
}

// PerformHandshakeResponder responds to a handshake initiated by a remote party.
// NOTE: remember to sign signedCert!
// [NewAuthoritySignature] is this packages helper
func (hs *HandshakeState) PerformHandshakeResponder(rw io.ReadWriter, signedCert *SIGNATURE_NOISE_MESSAGE, staticKeys *Keypair) (recv, send *CipherState, err error) {
	recv = &CipherState{}
	send = &CipherState{}

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
	/// "1. receives ephemeral public key message (64 bytes plaintext EllSwift encoded public key)
	///  2. parses received public key as re.public_key"
	remoteEphemeral := make([]byte, 64)
	rw.Read(remoteEphemeral)

	/// "3. calls MixHash(re.public_key)"
	hs.mixHash(remoteEphemeral)
	// println(fmt.Sprintf("[Responder] got ie: %x", remoteEphemeral))
	// println(fmt.Sprintf("[Responder] After MixHash(ie): h=%x", hs.h))

	/// "4. calls DecryptAndHash() on the remaining bytes, which is the empty payload
	///     (note that k is empty at this point, so this effectively reduces down to MixHash() on empty data)"
	hs.decryptAndHash([]byte{})
	// println(fmt.Sprintf("[Responder] After DecryptAndHash(empty): h=%x", hs.h))

	/// 4.5.2 Handshake Act 2: NX-handshake part 2
	/// 4.5.2.1
	out := bytes.Buffer{}
	out.Grow(234) /// length of pt 2

	/// "2. generates ephemeral keypair e, appends e.public_key to the buffer (64 bytes plaintext EllSwift encoded public key)"
	ephemeral := NewKeypair()
	out.Write(ephemeral.SerializeEllswiftBytes())
	// println(fmt.Sprintf("[Responder] se: %x", ephemeral.SerializeEllswift()))

	/// "3. calls MixHash(e.public_key)"
	hs.mixHash(ephemeral.SerializeEllswiftBytes())
	// println(fmt.Sprintf("[Responder] After MixHash(se): h=%x", hs.h))

	/// "4. calls MixKey(ECDH(e.private_key, re.public_key))"
	sharedeeDH := hs.ecdh(ephemeral, EllswiftPubkey(remoteEphemeral), false)
	hs.mixKey(sharedeeDH)
	// println(fmt.Sprintf("[Responder] ee DH shared secret: %x", sharedeeDH))
	// println(fmt.Sprintf("[Responder] After MixKey(ee): ck=%x", hs.ck))

	// println(fmt.Sprintf("[Responder] h (AD for encrypt static): h=%x", hs.h))
	// println(fmt.Sprintf("[Responder] Static pub (plaintext): %x", staticKeys.SerializeEllswift()))

	/// "5. appends EncryptAndHash(s.public_key) (64 bytes encrypted EllSwift encoded public key, 16 bytes MAC)"
	out.Write(hs.encryptAndHash(staticKeys.SerializeEllswiftBytes()))
	// println(fmt.Sprintf("[Responder] Encrypted static (%d bytes): %x", len(x), x))

	/// "6. calls MixKey(ECDH(s.private_key, re.public_key))"
	sharedesDH := hs.ecdh(staticKeys, EllswiftPubkey(remoteEphemeral), false)
	hs.mixKey(sharedesDH)
	// println(fmt.Sprintf("[Responder] es DH shared secret (responder): %x", sharedesDH))
	// println(fmt.Sprintf("[Responder] After MixKey(es): ck=%x", hs.ck))

	/// "7. appends EncryptAndHash(SIGNATURE_NOISE_MESSAGE) to the buffer"
	certBytes, err := signedCert.Encode()
	if err != nil {
		return nil, nil, err
	}
	out.Write(hs.encryptAndHash(certBytes))
	// println(fmt.Sprintf("[Responder] h (AD for encrypt cert): h=%x", hs.h))
	// println(fmt.Sprintf("[Responder] Cert payload (%d bytes): %x", len(certBytes), certBytes))

	/// "8. submits the buffer for sending to the initiator"
	rw.Write(out.Bytes())
	out.Reset()

	/// "9. return pair of CipherState objects, the first for encrypting transport messages
	///     from initiator to responder, and the second for messages in the other direction"
	temp_k1, temp_k2 := HKDF(hs.ck[:], []byte{})
	// println(fmt.Sprintf("[Responder] k1=%x, k2=%x", temp_k1, temp_k2))
	recv.InitializeKey([32]byte(temp_k1))
	send.InitializeKey([32]byte(temp_k2))
	/// initiator->responder, responder->initiator
	return recv, send, nil
}

func (hs *HandshakeState) encryptAndHash(plaintext []byte) []byte {
	var ciphertext []byte
	if len(hs.cs.k) != 0 {
		/// NOTE: at this early stage nonce wont be anywhere close to the limit
		ciphertext, _ = hs.cs.EncryptWithAd(hs.h[:], plaintext)
	} else {
		ciphertext = plaintext
	}
	hs.mixHash(ciphertext)
	return ciphertext
}
func (hs *HandshakeState) decryptAndHash(ciphertext []byte) ([]byte, error) {
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
	hs.mixHash(ciphertext)
	return plaintext, err
}
func (hs *HandshakeState) mixHash(data []byte) {
	hs.h = sha256.Sum256(append(hs.h[:], data...))
}
func (hs *HandshakeState) mixKey(inputKeyMaterial []byte) {
	ck, temp := HKDF(hs.ck[:], inputKeyMaterial)
	hs.ck = [32]byte(ck)
	hs.cs.InitializeKey([32]byte(temp))
}
func (hs *HandshakeState) ecdh(k *Keypair, remoteKey EllswiftPubkey, initiator bool) []byte {
	hash, err := ellswift.V2Ecdh(k.Private, remoteKey, k.SerializeEllswift(), initiator)
	if err != nil {
		panic(err)
	}
	return hash[:]
}

// CipherState encapsulates encryption and decryption operations with underlying AEAD mode
// cipher functions using 32-byte encryption key `k` and 8-byte nonce `n`.
type CipherState struct {
	k   []byte // encryption key
	n   uint64
	gcm cipher.AEAD
}

// InitializeKey initializes the encryption key `k` and resets the nonce counter to 0.
func (cs *CipherState) InitializeKey(k [32]byte) error {
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

// Encrypt encrypts `plaintext`.
// It only returns an error when nonce space is exhausted (at 2^64).
// Be sure to call [CipherState.InitializeKey] before, or this will pass through the plaintext.
func (cs *CipherState) Encrypt(plaintext []byte) ([]byte, error) {
	return cs.EncryptWithAd([]byte{}, plaintext)
}

// Decrypt decrypts `ciphertext`.
// It returns an error when decrypt fails or when nonce space is exhausted (at 2^64).
func (cs *CipherState) Decrypt(ciphertext []byte) ([]byte, error) {
	return cs.DecryptWithAd([]byte{}, ciphertext)
}

// EncryptWithAd encrypts `plaintext` with `ad` as additional data.
// It only returns an error when nonce space is exhausted (at 2^64).
// Be sure to call [CipherState.InitializeKey] before, or this will pass through the plaintext.
//
// TODO: make this thread-safe
// TODO: how do i do security validation lol
func (cs *CipherState) EncryptWithAd(ad, plaintext []byte) ([]byte, error) {
	if len(cs.k) == 0 {
		return plaintext, nil
	}
	/// noise doesnt reuse nonces and also treats 2^64 as invalid
	if cs.n == maxNoiseNonce {
		return nil, errors.New("nonce space exhausted")
	}
	return cs.gcm.Seal(make([]byte, 0, PlainTextLenToCipherTextLen(len(plaintext))), cs.getNonce(), plaintext, ad), nil
}

// DecryptWithAd decrypts `ciphertext` with `ad` as additional data.
// It returns an error when decrypt fails or when nonce space is exhausted (at 2^64).
func (cs *CipherState) DecryptWithAd(ad, ciphertext []byte) ([]byte, error) {
	if len(cs.k) == 0 {
		return ciphertext, nil
	}
	if cs.n == maxNoiseNonce {
		return nil, errors.New("nonce space exhausted")
	}
	/// FIXME: why cant we reuse ciphertext here?
	out, err := cs.gcm.Open(make([]byte, 0, len(ciphertext)), cs.getNonce(), ciphertext, ad)
	if err != nil {
		cs.n--
		return nil, err
	}
	return out, nil
}

// EncryptFrame encrypts a [Frame] to a byte array.
func (cs *CipherState) EncryptFrame(frame Frame) ([]byte, error) {
	encoded, err := frame.Encode()
	if err != nil {
		return nil, err
	}
	header, err := cs.EncryptWithAd([]byte{}, encoded[:FrameHeaderSize])
	if err != nil {
		return nil, fmt.Errorf("error while encrypting header: %s", err)
	}
	out, err := cs.EncryptWithAd([]byte{}, encoded[FrameHeaderSize:])
	if err != nil {
		return nil, fmt.Errorf("error while encrypting payload: %s", err)
	}

	return append(header, out...), nil
}

// EncryptFrameToWriter encrypts a [Frame] to an [io.Writer].
func (cs *CipherState) EncryptFrameToWriter(frame Frame, w io.Writer) (int, error) {
	encoded, err := frame.Encode()
	if err != nil {
		return 0, err
	}
	header, err := cs.Encrypt(encoded[:FrameHeaderSize])
	if err != nil {
		return 0, fmt.Errorf("error while encrypting header: %s", err)
	}
	payload, err := cs.Encrypt(encoded[FrameHeaderSize:])
	if err != nil {
		return 0, fmt.Errorf("error while encrypting payload: %s", err)
	}

	return w.Write(append(header, payload...))
}

// DecryptFrame decrypts a [Frame] from a byte array.
func (cs *CipherState) DecryptFrame(f []byte) (Frame, error) {
	r := NewBinaryReader(f)
	frame := Frame{}
	/// decrypt the header
	header := make([]byte, NoiseHeaderSize)
	read, err := io.ReadFull(r, header)

	if err != nil {
		return Frame{}, err
	}
	if read < NoiseHeaderSize {
		return Frame{}, errors.New("header ciphertext too short")
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
		return Frame{}, err
	}
	if read < payloadLen {
		return Frame{}, errors.New("payload ciphertext too short")
	}
	decrypted, err = cs.DecryptWithAd([]byte{}, payload)
	if err != nil {
		return Frame{}, fmt.Errorf("error while decrypting payload: %s", err)
	}
	frame.Payload = decrypted
	return frame, nil
}

// DecryptFrameFromReader decrypts a [Frame] from an [io.Reader].
func (cs *CipherState) DecryptFrameFromReader(r io.Reader) (Frame, error) {
	frame := Frame{}
	/// decrypt the header
	header := make([]byte, NoiseHeaderSize)
	read, err := io.ReadFull(r, header)

	if err != nil {
		return Frame{}, err
	}
	if read < NoiseHeaderSize {
		return Frame{}, errors.New("header ciphertext too short")
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
		return Frame{}, err
	}
	if read < payloadLen {
		return Frame{}, errors.New("payload ciphertext too short")
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
func NewAuthoritySignature(authorityPrivkey *btcec.PrivateKey, staticPubkey Pubkey, validFrom, notValidAfter uint32) (*SIGNATURE_NOISE_MESSAGE, error) {
	m := &SIGNATURE_NOISE_MESSAGE{
		Version:       CertificateFormatVersion,
		ValidFrom:     validFrom,
		NotValidAfter: notValidAfter,
	}
	buf, err := m.EncodeNoSig()
	if err != nil {
		return nil, err
	}
	buf = append(buf, staticPubkey[:]...)
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

// TODO: doesnt btcd already have this?
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
func NewKeypair() *Keypair {
	/// only error comes from crypto/rand Read, which never errors
	priv, ellswiftPub, _ := ellswift.EllswiftCreate()
	pub := priv.PubKey()
	return &Keypair{
		Private:        priv,
		Public:         pub,
		publicEllswift: ellswiftPub,
		publicX:        pub.X().FillBytes(make([]byte, 32)),
	}
}
