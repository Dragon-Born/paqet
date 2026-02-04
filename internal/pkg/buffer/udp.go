package buffer

import (
	"encoding/binary"
	"io"
	"net"
)

// CopyU copies data from src to dst using a pooled buffer.
// Note: This is a byte-stream copy and does NOT preserve UDP datagram boundaries.
// For UDP forwarding, use WriteUDPFrame/ReadUDPFrame instead.
func CopyU(dst io.Writer, src io.Reader) error {
	bufp := UPool.Get().(*[]byte)
	defer UPool.Put(bufp)
	buf := *bufp

	_, err := io.CopyBuffer(dst, src, buf)
	return err
}

// WriteUDPFrame writes a UDP packet with a 2-byte length prefix.
// This preserves datagram boundaries over byte streams (QUIC, smux).
// Wire format: [2-byte big-endian length][payload]
//
// Uses net.Buffers for scatter-gather I/O (writev) when available,
// avoiding data copy while minimizing syscalls.
func WriteUDPFrame(w io.Writer, data []byte) error {
	if len(data) > 65535 {
		return io.ErrShortBuffer
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(data)))

	// net.Buffers uses writev when the writer supports it (single syscall),
	// otherwise falls back to sequential writes.
	bufs := net.Buffers{header[:], data}
	_, err := bufs.WriteTo(w)
	return err
}

// ReadUDPFrame reads a length-prefixed UDP packet from a stream.
// Returns the packet data (slice of buf) and any error.
// buf must be large enough for the max expected packet size.
func ReadUDPFrame(r io.Reader, buf []byte) (int, error) {
	// Read 2-byte length header
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, err
	}
	length := binary.BigEndian.Uint16(header[:])
	if int(length) > len(buf) {
		return 0, io.ErrShortBuffer
	}
	// Read exactly length bytes of payload
	return io.ReadFull(r, buf[:length])
}
