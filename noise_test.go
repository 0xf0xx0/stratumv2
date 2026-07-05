package stratumv2_test

import (
	"testing"

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
