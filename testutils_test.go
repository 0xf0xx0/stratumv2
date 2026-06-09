package stratumv2_test

import "encoding/hex"

func hexDec(s string) []byte {
	x, _ := hex.DecodeString(s)
	return x
}
