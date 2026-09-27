// taken from btcd and tweaked for greater usability
// TODO: pr back upstream
package stratumv2

import (
	"crypto/rand"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ellswift"
)

// EllswiftCreateFromBytes deterministically generates a random private key and
// returns that along with the ElligatorSwift encoding of its corresponding public key.
//
// taken from btcd.
func EllswiftCreateFromBytes(privKeyBytes, auxRand [32]byte, caseNum uint8) (*btcec.PrivateKey, [64]byte, error) {
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes[:])

	// Fetch the x-coordinate of the public key.
	x := getXCoord(privKey)

	// Get the ElligatorSwift encoding of the public key.
	u, t, err := XElligatorSwiftAux(x, auxRand, caseNum)
	if err != nil {
		return nil, [64]byte{}, err
	}

	uBytes := u.Bytes()
	tBytes := t.Bytes()

	// ellswift_pub = bytes(u) || bytes(t), its encoding as 64 bytes
	var ellswiftPub [64]byte
	copy(ellswiftPub[0:32], (*uBytes)[:])
	copy(ellswiftPub[32:64], (*tBytes)[:])

	// Return (priv, ellswift_pub)
	return privKey, ellswiftPub, nil
}

// XElligatorSwiftAux takes the x-coordinate of a point on secp256k1 and
// an auxiliary random value, and deterministically generates the
// ElligatorSwift encoding of that point composed of two field elements (u, t).
//
// taken from btcd.
// NOTE: x MUST be normalized. The return values u, t are normalized.
func XElligatorSwiftAux(x *btcec.FieldVal, auxRand [32]byte, caseNum uint8) (*btcec.FieldVal, *btcec.FieldVal,
	error) {

	// We'll choose a random `u` value and a random case so that we can
	// generate a `t` value.
	u := new(btcec.FieldVal)
	overflow := u.SetBytes(&auxRand)
	if overflow == 1 {
		u.Normalize()
	}

	// Ensure case is in the interval [0, 7]
	// Find t, if none is found, error.
	t := ellswift.XSwiftECInv(u, x, int(caseNum&7))
	if t == nil {
		return nil, nil, errors.New("t not found")
	}
	return u, t, nil
}

// EllswiftCreate generates a random private key and returns that along with
// the ElligatorSwift encoding of its corresponding public key, the auxiliary random value,
// and the case number used to generate the `t` value.
//
// taken from btcd.
func EllswiftCreate(randPrivKeyBytes [32]byte) (*btcec.PrivateKey, [64]byte, [32]byte, uint8, error) {
	// var randPrivKeyBytes [32]byte
	var auxRand [32]byte
	var caseNum uint8

	// Generate a random private key
	// _, err := rand.Read(randPrivKeyBytes[:])
	// if err != nil {
	// 	return nil, [64]byte{}, [32]byte{}, 0, err
	// }

	privKey, _ := btcec.PrivKeyFromBytes(randPrivKeyBytes[:])

	// Fetch the x-coordinate of the public key.
	x := getXCoord(privKey)

	// Get the ElligatorSwift encoding of the public key.
	u, t, auxRand, caseNum, err := XElligatorSwift(x)
	if err != nil {
		return nil, [64]byte{}, [32]byte{}, 0, err
	}

	uBytes := u.Bytes()
	tBytes := t.Bytes()

	// ellswift_pub = bytes(u) || bytes(t), its encoding as 64 bytes
	var ellswiftPub [64]byte
	copy(ellswiftPub[0:32], (*uBytes)[:])
	copy(ellswiftPub[32:64], (*tBytes)[:])

	// Return (priv, ellswift_pub)
	return privKey, ellswiftPub, auxRand, caseNum, nil
}

// XElligatorSwift takes the x-coordinate of a point on secp256k1 and generates
// ElligatorSwift encoding of that point composed of two field elements (u, t).
//
// taken from btcd.
// NOTE: x MUST be normalized. The return values u, t are normalized.
func XElligatorSwift(x *btcec.FieldVal) (*btcec.FieldVal, *btcec.FieldVal, [32]byte, uint8,
	error) {

	// We'll choose a random `u` value and a random case so that we can
	// generate a `t` value.
	for {
		// Choose random u value.
		var randUBytes [32]byte
		_, err := rand.Read(randUBytes[:])
		if err != nil {
			return nil, nil, [32]byte{}, 0, err
		}

		u := new(btcec.FieldVal)
		overflow := u.SetBytes(&randUBytes)
		if overflow == 1 {
			u.Normalize()
		}

		// Choose a random case in the interval [0, 7]
		var randCaseByte [1]byte
		_, err = rand.Read(randCaseByte[:])
		if err != nil {
			return nil, nil, [32]byte{}, 0, err
		}

		caseNum := randCaseByte[0] & 7

		// Find t, if none is found, continue with the loop.
		t := ellswift.XSwiftECInv(u, x, int(caseNum))
		if t != nil {
			return u, t, randUBytes, caseNum, nil
		}
	}
}

// getXCoord fetches the corresponding public key's x-coordinate given a
// private key.
//
// taken from btcd.
func getXCoord(privKey *btcec.PrivateKey) *btcec.FieldVal {
	var result btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&privKey.Key, &result)
	result.ToAffine()
	return &result.X
}
