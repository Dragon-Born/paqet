package udp

import (
	"net"
	"paqet/internal/socket"
	"time"
)

// ConnAdapter wraps a PacketConn + fixed remote address into a net.Conn for smux.
// It also applies optional per-packet encryption.
type ConnAdapter struct {
	pConn  *socket.PacketConn
	remote net.Addr
	cipher *Cipher
}

// NewConnAdapter creates a ConnAdapter that sends/receives from a specific remote address.
func NewConnAdapter(pConn *socket.PacketConn, remote net.Addr, cipher *Cipher) *ConnAdapter {
	return &ConnAdapter{pConn: pConn, remote: remote, cipher: cipher}
}

func (a *ConnAdapter) Read(b []byte) (int, error) {
	for {
		n, _, err := a.pConn.ReadFrom(b)
		if err != nil {
			return 0, err
		}
		if a.cipher == nil {
			return n, nil
		}
		plain, err := a.cipher.Decrypt(b[:n])
		if err != nil {
			continue // drop corrupted packets
		}
		// plain is a sub-slice within b (after nonce), move to front
		if len(plain) > 0 && &plain[0] != &b[0] {
			copy(b, plain)
		}
		return len(plain), nil
	}
}

func (a *ConnAdapter) Write(b []byte) (int, error) {
	data := b
	if a.cipher != nil {
		var err error
		data, err = a.cipher.Encrypt(b)
		if err != nil {
			return 0, err
		}
	}
	return a.pConn.WriteTo(data, a.remote)
}

func (a *ConnAdapter) Close() error                       { return a.pConn.Close() }
func (a *ConnAdapter) LocalAddr() net.Addr                { return a.pConn.LocalAddr() }
func (a *ConnAdapter) RemoteAddr() net.Addr               { return a.remote }
func (a *ConnAdapter) SetDeadline(t time.Time) error      { return a.pConn.SetDeadline(t) }
func (a *ConnAdapter) SetReadDeadline(t time.Time) error  { return a.pConn.SetReadDeadline(t) }
func (a *ConnAdapter) SetWriteDeadline(t time.Time) error { return a.pConn.SetWriteDeadline(t) }
