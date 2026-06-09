# A Golang library for the Bitcoin Stratum V2 Protocol

[![Go Reference](https://pkg.go.dev/badge/git.0xf0xx0.eth.limo/0xf0xx0/stratumv2.svg)](https://pkg.go.dev/git.0xf0xx0.eth.limo/0xf0xx0/stratumv2@master)

https://stratumprotocol.org/

# implemented
- core messages
- mining protocol

## usage

```go
bytes := hexDec("00801b1f00002d000000060000001f1e2f01a18a144c53f5256a00e00a200600000000000a")
frame := stratumv2.Frame{}
msg := stratumv2.SubmitSharesExtended{}
if err := frame.Decode(bytes); err != nil {
	println(err.Error())
	return
}
if f.MessageType != stratumv2.MethodSubmitSharesExtended {
	panic("not SubmitSharesExtended message")
}
if err := msg.Decode(frame.Payload); err != nil {
	println(err.Error())
	return
}
fmt.Sprintf("%+v", m) /// {SubmitSharesStandard:{ChannelID:45 Sequence:6 JobID:19865119 Nonce:1276414625 Time:1780872531 Version:537583616} Extranonce:[0 0 0 0 0 10]}

/// most everything implements the [Codable] interface
enc, err := msg.Encode()
if err != nil {
	println(err.Error())
	return
}
```

# TODO
- implement all protocols
    - jobs
    - template
- implement noise
