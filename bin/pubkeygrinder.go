// shitty key grinder
//
// write one in c or rust with asm if you want performance
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"runtime/pprof"
	"strconv"
	"sync"
	"time"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
	"github.com/minio/sha256-simd"
)

func main() {
	f, _ := os.Create("./cpu.prof")
	pprof.StartCPUProfile(f)
	// str := "pogoLo"
	str := "fox"
	strLen := len(str)
	maxResults := 5
	resultChan := make(chan result, maxResults)
	wg := sync.WaitGroup{}
	ctx, cancel := context.WithCancel(context.Background())
	for i := range 4 {
		pprof.WithLabels(ctx, pprof.Labels("grinder", strconv.Itoa(i)))
		println("starting goroutine", i)
		wg.Go(func() {
			grinder(strLen, str, resultChan, &cancel, ctx, &wg)
		})
	}

	resColl := make([]result, 0, maxResults)
	for {
		res := <-resultChan
		println(fmt.Sprintf("found!\npubkey:\t%s\nprivkey:\t%x\nauxrand:\t%x\ncase:\t%d",
			res.pubKey, res.privKey, res.auxRand, res.caseNum))

		resColl = append(resColl, res)
		if len(resColl) == cap(resColl) {
			cancel()
			break
		}
	}
	fmt.Println("found keys:")
	totalHashrate := float64(0)
	for _, res := range resColl {
		fmt.Printf("pubkey:\t%s\nprivkey:\t%x\nauxrand:\t%x\ncase:\t%d\n",
			res.pubKey, res.privKey, res.auxRand, res.caseNum)
		totalHashrate += float64(res.nonce) / res.timeTaken.Seconds()
	}
	fmt.Printf("total hashrate: %f h/s", totalHashrate)
	pprof.StopCPUProfile()
	wg.Wait()
}

type result struct {
	pubKey    string
	privKey   []byte
	auxRand   [32]byte
	caseNum   uint8
	nonce     uint64
	timeTaken time.Duration
}

func grinder(strLen int, str string, resultChan chan result, cancel *context.CancelFunc, ctx context.Context, wg *sync.WaitGroup) {
	sha := sha256.New()
	nonce := uint64(0)
	nonceBytes := make([]byte, 8)
	privKey := make([]byte, 32)
	keyRng := make([]byte, 32)
	rand.Read(keyRng)
	startTime := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if nonce == math.MaxUint64 {
			println("resetting nonce")
			nonce = 0
			rand.Read(keyRng)
		}
		binary.LittleEndian.PutUint64(nonceBytes, nonce)
		sha.Write(keyRng)
		sha.Write(nonceBytes)
		privKey = sha.Sum(privKey[:0])
		key, _, auxrand, casenum, err := stratumv2.EllswiftCreate([32]byte(privKey))
		if err != nil {
			panic(err)
		}
		enc := stratumv2.SerializeAuthorityKey(stratumv2.Pubkey(key.PubKey().X().FillBytes(make([]byte, 32))))
		// println(enc)
		// if strings.ToLower(enc[2:2+strLen]) == str {
		if enc[2:2+strLen] == str {
			resultChan <- result{
				pubKey:    enc,
				privKey:   key.Serialize(),
				auxRand:   auxrand,
				caseNum:   casenum,
				nonce:     nonce,
				timeTaken: time.Since(startTime),
			}
		}
		nonce++
		sha.Reset()
	}
}
