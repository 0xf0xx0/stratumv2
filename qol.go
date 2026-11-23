// qol things for dx
package stratumv2

import (
	"errors"
	"net"
	"time"
)

type ClientConn struct {
	conn       net.Conn
	send, recv *CipherState
}

// EncryptToWriter encrypts a byte array to an [io.Writer].
// func (cs *CipherState) EncryptToWriter(b []byte, w io.Writer) (int, error) {

// 	if err != nil {
// 		return 0, fmt.Errorf("error while encrypting payload: %s", err)
// 	}

//		return w.Write(payload)
//	}
func (conn *ClientConn) PerformHandshake() error {
	clientPaw := &HandshakeState{}
	send, recv, err := clientPaw.PerformHandshakeInitiator(conn.conn)
	if err != nil {
		return err
	}
	conn.send = send
	conn.recv = recv
	return nil
}
func (conn *ClientConn) WriteFrame(frame *Frame) (int, error) {
	return conn.send.EncryptFrameToWriter(frame, conn.conn)
}
func (conn *ClientConn) ReadFrame() (*Frame, error) {
	frame, err := conn.recv.DecryptFrameFromReader(conn.conn)
	return frame, err
}

// net.Conn impl
// Write implements [net.Conn] with noise encryption.
func (conn *ClientConn) Write(b []byte) (int, error) {
	if conn.send == nil {
		return 0, errors.New(".PerformHandshake was not called yet")
	}
	enc, err := conn.send.Encrypt(b)
	if err != nil {
		return 0, err
	}
	return conn.conn.Write(enc)
}

// Read implements [net.Conn] with noise decryption.
func (conn *ClientConn) Read(b []byte) (int, error) {
	if conn.recv == nil {
		return 0, errors.New(".PerformHandshake was not called yet")
	}
	n, err := conn.conn.Read(b)
	if err != nil {
		return n, err
	}
	dec, err := conn.recv.Decrypt(b)
	copy(b, dec)
	return n, err
}
func (conn *ClientConn) Close() error {
	return conn.conn.Close()
}
func (conn *ClientConn) LocalAddr() net.Addr {
	return conn.conn.LocalAddr()
}
func (conn *ClientConn) RemoteAddr() net.Addr {
	return conn.conn.RemoteAddr()
}
func (conn *ClientConn) SetDeadline(t time.Time) error {
	return conn.conn.SetDeadline(t)
}
func (conn *ClientConn) SetReadDeadline(t time.Time) error {
	return conn.conn.SetReadDeadline(t)
}
func (conn *ClientConn) SetWriteDeadline(t time.Time) error {
	return conn.conn.SetWriteDeadline(t)
}

// NewSv2Conn returns a new, uninitialized [ClientConn].
// [ClientConn.PerformHandshake] must be called before writing and reading is possible.
func NewSv2Conn(rawConn net.Conn) *ClientConn {
	return &ClientConn{
		conn: rawConn,
	}
}
