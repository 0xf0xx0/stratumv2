package stratumv2_test

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync"
	"testing"
	"time"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
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
	rand.Read(authority.Public[:])
	rand.Read(staticPub)
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
}

func TestHandshake(t *testing.T) {
	authority, _ := stratumv2.GenerateKeypair()
	static, _ := stratumv2.GenerateKeypair()
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
