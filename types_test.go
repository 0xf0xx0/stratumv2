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
	comp.SetBytes(hexDec("2000000000000000000000000000000000000000000000000000000000000000"))
	if !target.IsMetBy(comp) {
		t.Error("should have met target")
	}

	/// fails
	comp.SetBytes(hexDec("0000ff0000000000000000000000000000000000000000000000000000000000"))
	if target.IsMetBy(comp) {
		t.Error("should have failed to meet target")
	}
}
