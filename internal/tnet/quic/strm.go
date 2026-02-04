package quic

import (
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// Strm wraps a quic.Stream and implements tnet.Strm (which extends net.Conn).
type Strm struct {
	stream     *quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (s *Strm) Read(b []byte) (int, error)  { return s.stream.Read(b) }
func (s *Strm) Write(b []byte) (int, error) { return s.stream.Write(b) }
func (s *Strm) Close() error                { return s.stream.Close() }

func (s *Strm) LocalAddr() net.Addr  { return s.localAddr }
func (s *Strm) RemoteAddr() net.Addr { return s.remoteAddr }

func (s *Strm) SetDeadline(t time.Time) error      { return s.stream.SetDeadline(t) }
func (s *Strm) SetReadDeadline(t time.Time) error  { return s.stream.SetReadDeadline(t) }
func (s *Strm) SetWriteDeadline(t time.Time) error { return s.stream.SetWriteDeadline(t) }

func (s *Strm) SID() int {
	return int(s.stream.StreamID())
}
