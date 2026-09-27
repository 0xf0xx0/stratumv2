package stratumv2_test

import (
	"bytes"
	"testing"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
)

func TestEllswiftDeterminism(t *testing.T) {
	key1, pubkey1, auxRand, caseNum, err := stratumv2.EllswiftCreate()
	if err != nil {
		t.Fatal(err)
	}

	key2, pubkey2, err := stratumv2.EllswiftCreateFromBytes(key1.Key.Bytes(), auxRand, caseNum)
	if err != nil {
		t.Fatal(err)
	}
	key3, pubkey3, err := stratumv2.EllswiftCreateFromBytes(key2.Key.Bytes(), auxRand, caseNum)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pubkey1[:], pubkey2[:]) {
		t.Logf("\n\t%x\n\t%x", pubkey1, pubkey2)
		t.Fatal("pubkey1 != pubkey2")
	}
	if !bytes.Equal(pubkey1[:], pubkey3[:]) {
		t.Logf("\n\t%x\n\t%x", pubkey1, pubkey3)
		t.Fatal("pubkey1 != pubkey3")
	}
	if !bytes.Equal(key1.Serialize(), key2.Serialize()) {
		t.Fatal("key1 != key2")
	}
	if !bytes.Equal(key1.Serialize(), key3.Serialize()) {
		t.Fatal("key1 != key3")
	}
}
