# A Golang library for the Bitcoin Stratum V2 Protocol

[![Go Reference](https://pkg.go.dev/badge/git.0xf0xx0.eth.limo/0xf0xx0/stratumv2.svg)](https://pkg.go.dev/git.0xf0xx0.eth.limo/0xf0xx0/stratumv2@master)

https://stratumprotocol.org/

currently unstable, api will change + no security guarantees (but any issues will be fixed)

# implemented
- core messages
- mining protocol

# TODO
- properly implement TLVs
- implement all protocols
    - jobs
    - template
- docs
- tests
    need test messages

## usage
TODO: docs  
see [TestHandshake](./noise_test.go) and [TestSetupConnectionEncDec](./core_test.go)
