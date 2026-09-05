package stratumv2_test

/// test data stolen from public-pool and sri

import (
	"bytes"
	crand "crypto/rand"
	"encoding/hex"
	"net"
	"sync"
	"testing"
	"time"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestBase58Check(t *testing.T) {
	raw_ca_public_key := []byte{
		118, 99, 112, 0, 151, 156,
		28, 17, 175, 12, 48, 11, 205,
		140, 127, 228, 134, 16, 252, 233,
		185, 193, 30, 61, 174, 227, 90, 224,
		176, 138, 116, 85,
	}
	prefixed_base58check := "9bXiEd8boQVhq7WddEcERUL5tyyJVFYdU8th3HfbNXK3Yw6GRXh"

	serialized := stratumv2.SerializeAuthorityKey(raw_ca_public_key)

	t.Log(serialized)
	t.Log(prefixed_base58check)
	if serialized != prefixed_base58check {
		t.Errorf("expected %s, got %s", prefixed_base58check, serialized)
	}
	deserialized, err := stratumv2.DeserializeAuthorityKey(prefixed_base58check)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if string(deserialized) != string(raw_ca_public_key) {
		t.Errorf("expected %s, got %s", raw_ca_public_key, deserialized)
	}
}

func TestCerts(t *testing.T) {
	authority, _ := stratumv2.GenerateKeypair()
	staticPub := make([]byte, 32)
	crand.Read(authority.Public[:])
	crand.Read(staticPub)
	now := uint32(time.Now().Unix())
	cert, err := stratumv2.NewAuthoritySignature(authority.Private, staticPub, 0, now+3600)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	ok, err := stratumv2.VerifyServerCertificate(cert, authority.PublicX, staticPub)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !ok {
		t.Errorf("failed to verify server certificate")
	}

	/// verify failure
	badKey, _ := stratumv2.GenerateKeypair()
	ok, err = stratumv2.VerifyServerCertificate(cert, badKey.PublicX, staticPub)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if ok {
		t.Errorf("cert verified when it should have failed")
	}
}

func TestHMAC(t *testing.T) {
	key, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	data := []byte("Hi There")
	expected := "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
	out := hex.EncodeToString(stratumv2.HmacHash(key, data))
	if out != expected {
		t.Errorf("expected %s, got %s", expected, out)
	}
	key = []byte("Jefe")
	data = []byte("what do ya want for nothing?")
	expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	out = hex.EncodeToString(stratumv2.HmacHash(key, data))
	if out != expected {
		t.Errorf("expected %s, got %s", expected, out)
	}
}

func TestHKDF(t *testing.T) {
	ck := make([]byte, 32)
	for i := range ck {
		ck[i] = 0x01
	}
	ikm := make([]byte, 32)
	for i := range ikm {
		ikm[i] = 0x02
	}
	out1, out2 := stratumv2.HKDF(ck, ikm)
	if len(out1) != 32 || len(out2) != 32 {
		t.Errorf("expected 32-byte output, got %d and %d", len(out1), len(out2))
	}
	if bytes.Equal(out1, out2) {
		t.Errorf("expected unequal outputs, got %x", out1)
	}

	/// deterministic test
	out3, out4 := stratumv2.HKDF(ck, ikm)
	if !bytes.Equal(out1, out3) {
		t.Errorf("expected equal outputs, got %x and %x", out1, out3)
	}
	if !bytes.Equal(out2, out4) {
		t.Errorf("expected equal outputs, got %x and %x", out2, out4)
	}

	/// empty ikm test
	ikm = make([]byte, 0)
	out5, out6 := stratumv2.HKDF(ck, ikm)
	if len(out5) != 32 || len(out6) != 32 {
		t.Errorf("expected 32-byte output, got %d and %d", len(out5), len(out6))
	}
}

func TestCipherState(t *testing.T) {
	enc := &stratumv2.CipherState{}
	dec := &stratumv2.CipherState{}
	key := make([]byte, 32)
	crand.Read(key)
	enc.InitializeKey(key)
	dec.InitializeKey(key)

	plaintext := []byte("/sneefy snoofy/")
	t.Logf("plaintext: %x", plaintext)
	ciphertext := enc.EncryptWithAd([]byte{}, plaintext)
	if len(ciphertext) != len(plaintext)+stratumv2.MacLen {
		t.Fatalf("expected ciphertext length %d, got %d", len(plaintext)+stratumv2.MacLen, len(ciphertext))
	}
	t.Logf("encrypted: %x", ciphertext)
	if bytes.Equal(ciphertext[:len(plaintext)], plaintext) {
		t.Fatalf("expected ciphertext to be different from plaintext")
	}
	decrypted, err := dec.DecryptWithAd([]byte{}, ciphertext)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("expected decrypted text to be equal to plaintext")
	}
	t.Logf("decrypted: %x", decrypted)

	/// fail with wrong key

	dec.InitializeKey(make([]byte, 32))
	ciphertext = enc.EncryptWithAd([]byte{}, plaintext)
	decrypted, err = dec.DecryptWithAd([]byte{}, ciphertext)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if bytes.Equal(decrypted, plaintext) {
		t.Fatalf("expected decrypted text to not be equal to plaintext")
	}

	/// fail with wrong ad
	dec.InitializeKey(key)
	ciphertext = enc.EncryptWithAd([]byte{}, plaintext)
	decrypted, err = dec.DecryptWithAd([]byte("miZmatX"), ciphertext)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if bytes.Equal(decrypted, plaintext) {
		t.Fatalf("expected decrypted text to not be equal to plaintext")
	}

	/// nonce check
	ciphertexta := enc.EncryptWithAd([]byte{}, plaintext)
	ciphertextb := enc.EncryptWithAd([]byte{}, plaintext)
	if bytes.Equal(ciphertexta, ciphertextb) {
		t.Fatalf("expected ciphertexts to be different")
	}

	/// plaintext passthrough
	enc = &stratumv2.CipherState{}
	passthrough := enc.EncryptWithAd([]byte{}, plaintext)
	passthrough2, _ := enc.DecryptWithAd([]byte{}, plaintext)
	if !bytes.Equal(passthrough, plaintext) {
		t.Errorf("expected encrypted text to be equal to plaintext")
	}
	if !bytes.Equal(passthrough, passthrough2) {
		t.Errorf("expected encrypted text to be equal to plaintext")
	}

	/// rejects are basically testing stdlib lmao
	/// ignoring those tests, we can safely assume stdlib is working

	for range 10 {
		ciphertext = enc.EncryptWithAd([]byte{}, plaintext)
		decrypted, err := enc.DecryptWithAd([]byte{}, ciphertext)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("expected decrypted text to be equal to plaintext")
		}
	}

}

func TestHandshake(t *testing.T) {
	// authority, _ := stratumv2.GenerateKeypair()
	// static, _ := stratumv2.GenerateKeypair()
	static := &stratumv2.Keypair{
		Private: secp256k1.PrivKeyFromBytes(hexDec("77029ece8752b7e3177a3e15dc0c95a38f7f272bd3a6ff6f5677772b14f65483")),
		PublicX: [32]byte(hexDec("7fad14e7183636460d720a57862bd021c6c3d2c572d5195803dcb8aef627d2a5")),
		Public:  [64]byte(hexDec("e3748efb2b947c5af12322de08e9ab0323c46b3302307eb73f44f1411283528331032c5aace7b1586d124d95cd2df8ee6f1472c5bf1a4f2c9caaf034a1a7ec79")),
	}
	authority := &stratumv2.Keypair{
		Private: secp256k1.PrivKeyFromBytes(hexDec("da1183fb4a13b0779201797557df16199f5f7341f83ee30952d1af9334b668bb")),
		PublicX: [32]byte(hexDec("e49f0b5342de94379898fbe983efd17122b8180fa4916be878e7a1bab33c8b21")),
	}
	rpipe, lpipe := net.Pipe()

	srvPaw := &stratumv2.HandshakeState{}
	cliPaw := &stratumv2.HandshakeState{}
	wg := &sync.WaitGroup{}

	var srvc2s, srvs2c, clientc2s, clients2c *stratumv2.CipherState
	wg.Go(func() {
		var err error
		clientc2s, clients2c, err = cliPaw.PerformHandshakeInitiator(rpipe, authority.PublicX)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})
	wg.Go(func() {
		var err error
		cert, err := stratumv2.NewAuthoritySignature(authority.Private, static.Public[:], 20, uint32(time.Now().Unix())+3600)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		srvc2s, srvs2c, err = srvPaw.PerformHandshakeResponder(lpipe, cert, static)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})
	wg.Wait()

	// data := []byte("/pogolo/")
	// enc := srvs2c.EncryptWithAd([]byte{}, data)
	// t.Log(len(enc))
	// lpipe.Write(enc)

	// r := make([]byte, stratumv2.PlainTextLenToCipherTextLen(len(data)))
	// rpipe.Read(r)
	// t.Log("rlen ", len(r))
	// dec, err := clients2c.DecryptWithAd([]byte{}, r)
	// if err != nil {
	// 	t.Errorf("expected no error, got %v", err)
	// }
	// t.Log(string(dec))
	_ = srvc2s
	_ = srvs2c
	_ = clientc2s
	_ = clients2c
}
