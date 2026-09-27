package shared

import (
	"log"
	"net"
	"os"
	"time"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
)

var Logger = loog
var loog = log.New(os.Stdout, "\x1b[0m", log.Lmicroseconds|log.LUTC)

// wrapper to enc/dec and log frames
// MAYBE: actually export?
type Sv2Conn struct {
	NetConn    net.Conn
	Send, Recv *stratumv2.CipherState
}

func (conn *Sv2Conn) WriteFrame(frame *stratumv2.Frame) (int, error) {
	plainBytes, _ := frame.Encode()
	loog.Printf("\x1b[92mTX: (%s) %x\n", frame.MessageType, plainBytes)
	return conn.Send.EncryptFrameToWriter(frame, conn.NetConn)
}
func (conn *Sv2Conn) ReadFrame() (*stratumv2.Frame, error) {
	frame, err := conn.Recv.DecryptFrameFromReader(conn.NetConn)
	if err == nil {
		plainBytes, _ := frame.Encode()
		loog.Printf("\x1b[94mRX: (%s) %x\n", frame.MessageType, plainBytes)
	}
	return frame, err
}

/// net.Conn impl

func (conn *Sv2Conn) Write(b []byte) (int, error) {
	return conn.NetConn.Write(b)
}
func (conn *Sv2Conn) Read(b []byte) (int, error) {
	return conn.NetConn.Read(b)
}
func (conn *Sv2Conn) Close() error {
	return conn.NetConn.Close()
}
func (conn *Sv2Conn) LocalAddr() net.Addr {
	return conn.NetConn.LocalAddr()
}
func (conn *Sv2Conn) RemoteAddr() net.Addr {
	return conn.NetConn.RemoteAddr()
}
func (conn *Sv2Conn) SetDeadline(t time.Time) error {
	return conn.NetConn.SetDeadline(t)
}
func (conn *Sv2Conn) SetReadDeadline(t time.Time) error {
	return conn.NetConn.SetReadDeadline(t)
}
func (conn *Sv2Conn) SetWriteDeadline(t time.Time) error {
	return conn.NetConn.SetWriteDeadline(t)
}
