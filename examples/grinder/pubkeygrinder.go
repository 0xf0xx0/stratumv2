// shitty key grinder
//
// write one in c or rust with asm if you want performance
package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
)

func main() {
	// f, _ := os.Create("./cpu.prof")
	// pprof.StartCPUProfile(f)
	// str := "pogoLo" /// is this even possible lul
	str := "SV2"
	strLen := len(str)
	maxResults := 1
	resultChan := make(chan result, maxResults)
	wg := sync.WaitGroup{}
	ctx, cancel := context.WithCancel(context.Background())
	for i := range 4 {
		// pprof.WithLabels(ctx, pprof.Labels("grinder", strconv.Itoa(i)))
		println("starting goroutine", i)
		wg.Go(func() {
			grinder(strLen, str, resultChan, &cancel, ctx, &wg)
		})
	}

	resColl := make([]result, 0, maxResults)
	for {
		res := <-resultChan
		println(fmt.Sprintf("found pubkey:\t%s", res.pubKey))

		resColl = append(resColl, res)
		if len(resColl) == cap(resColl) {
			cancel()
			break
		}
	}
	fmt.Println("found keys:")
	totalHashrate := float64(0)
	for _, res := range resColl {
		kp, _ := stratumv2.NewKeypairFrom([32]byte(res.privKey), res.auxRand, res.caseNum)
		encoded, _ := kp.Encode()
		fmt.Printf("pubkey:\t%s\nprivkey:\t%#x\nauxrand:\t%#x\ncase:\t%d\nencoded Keypair:\t%x\n",
			res.pubKey, res.privKey, res.auxRand, res.caseNum, encoded)
		totalHashrate += float64(res.nonce) / res.timeTaken.Seconds()
	}
	fmt.Printf("total hashrate: %f h/s", totalHashrate)
	// pprof.StopCPUProfile()
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
	nonce := uint64(0)
	pubkeyBuf := make([]byte, 32)
	startTime := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		key, _, auxrand, casenum, err := stratumv2.EllswiftCreate()
		if err != nil {
			panic(err)
		}
		enc := stratumv2.SerializeAuthorityKey(stratumv2.Pubkey(key.PubKey().X().FillBytes(pubkeyBuf)))
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
	}
}
