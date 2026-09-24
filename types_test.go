package stratumv2_test

import (
	"testing"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
)

func TestU256(t *testing.T) {
	target := &stratumv2.U256{}
	comp := &stratumv2.U256{}

	target.SetBytes(hexDec("00ff000000000000000000000000000000000000000000000000000000000000"))

	/// meets
	comp.SetBytes(hexDec("00ff000000000000000000000000000000000000000000000000000000000000"))
	if !target.IsMetBy(comp) {
		t.Error("should have met target")
	}

	/// exceeds
	comp.SetBytes(hexDec("ff00000000000000000000000000000000000000000000000000000000000000"))
	if !target.IsMetBy(comp) {
		t.Error("should have met target")
	}

	/// fails
	comp.SetBytes(hexDec("000000000000000000000000000000000000000000000000000000000000ff00"))
	if target.IsMetBy(comp) {
		t.Error("should have failed to meet target")
	}
}

// bench set and compare
func BenchmarkU256SetString(b *testing.B) {
	b1 := hexDec("00ff000000000000000000000000000000000000000000000000000000000000")

	u1 := &stratumv2.U256{}
	u1.SetBytes(b1)
	for b.Loop() {
		u2 := &stratumv2.U256{}
		/// slowest path
		u2.SetString("000000000000000000000000000000000000000000000000000000000000ff00")
		ok := u1.IsMetBy(u2)
		if ok {
			b.Fatal("wtf")
		}
	}
}
func BenchmarkU256SetBytes(b *testing.B) {
	b1 := hexDec("00ff000000000000000000000000000000000000000000000000000000000000")
	b2 := hexDec("000000000000000000000000000000000000000000000000000000000000ff00")

	u1 := &stratumv2.U256{}
	u1.SetBytes(b1)
	for b.Loop() {
		u2 := &stratumv2.U256{}
		/// slowest path
		u2.SetBytes(b2)
		ok := u1.IsMetBy(u2)
		if ok {
			b.Fatal("wtf")
		}
	}
}
