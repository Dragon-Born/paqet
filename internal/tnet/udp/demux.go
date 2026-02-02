package udp

import (
	"net"
	"paqet/internal/pkg/hash"
	"sync"
	"time"
)

const clientChanSize = 256

// clientConn holds a per-client channel of received packets.
type clientConn struct {
	ch     chan packet
	addr   net.Addr
	cipher *Cipher
}

type packet struct {
	data []byte
	n    int // valid bytes in data
	pool *sync.Pool
}

// putBack returns the packet buffer to the pool.
func (p *packet) putBack() {
	if p.pool != nil {
		p.pool.Put(&p.data)
	}
}

var packetBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 1500)
		return &b
	},
}

var largeBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65536)
		return &b
	},
}

func getPacketBuf(n int) (*sync.Pool, []byte) {
	if n <= 1500 {
		bp := packetBufPool.Get().(*[]byte)
		return &packetBufPool, (*bp)[:n]
	}
	bp := largeBufPool.Get().(*[]byte)
	return &largeBufPool, (*bp)[:n]
}

// Demux reads from a single PacketConn and routes packets to per-client channels by source address.
type Demux struct {
	pConn   net.PacketConn
	cipher  *Cipher
	clients sync.Map // uint64 -> *clientConn
	newConn chan *clientConn
	done    chan struct{}
}

// NewDemux creates a new packet demultiplexer.
func NewDemux(pConn net.PacketConn, cipher *Cipher) *Demux {
	d := &Demux{
		pConn:   pConn,
		cipher:  cipher,
		newConn: make(chan *clientConn, 64),
		done:    make(chan struct{}),
	}
	go d.readLoop()
	return d
}

func (d *Demux) readLoop() {
	defer close(d.done)
	buf := make([]byte, 65536)
	for {
		n, addr, err := d.pConn.ReadFrom(buf)
		if err != nil {
			return
		}

		pool, data := getPacketBuf(n)
		copy(data, buf[:n])

		// Decrypt if cipher is set
		if d.cipher != nil {
			plain, err := d.cipher.Decrypt(data)
			if err != nil {
				pool.Put(&data)
				continue // drop corrupted
			}
			// If decrypt returned a different slice, return the original
			if &plain[0] != &data[0] {
				pool.Put(&data)
				pool = nil // decrypted data is not pooled
			}
			data = plain
		}

		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			if pool != nil {
				pool.Put(&data)
			}
			continue
		}

		key := hash.IPAddr(udpAddr.IP, uint16(udpAddr.Port))

		pkt := packet{data: data, n: len(data), pool: pool}
		if cc, ok := d.clients.Load(key); ok {
			select {
			case cc.(*clientConn).ch <- pkt:
			default: // drop if channel full
				pkt.putBack()
			}
		} else {
			// New client
			cc := &clientConn{
				ch:     make(chan packet, clientChanSize),
				addr:   addr,
				cipher: d.cipher,
			}
			cc.ch <- pkt
			d.clients.Store(key, cc)
			select {
			case d.newConn <- cc:
			default:
			}
		}
	}
}

// Accept waits for a new client connection.
func (d *Demux) Accept() (*clientConn, error) {
	cc, ok := <-d.newConn
	if !ok {
		return nil, net.ErrClosed
	}
	return cc, nil
}

// Close shuts down the demuxer.
func (d *Demux) Close() {
	d.pConn.Close()
	close(d.newConn)
}

// clientConnReader wraps a clientConn into an io.Reader-compatible net.Conn for smux.
type clientConnReader struct {
	cc     *clientConn
	pConn  net.PacketConn
	cipher *Cipher
	buf    []byte  // leftover from previous read
	curPkt *packet // current packet for putBack
}

func newClientConnReader(cc *clientConn, pConn net.PacketConn, cipher *Cipher) *clientConnReader {
	return &clientConnReader{cc: cc, pConn: pConn, cipher: cipher}
}

func (r *clientConnReader) Read(b []byte) (int, error) {
	if len(r.buf) > 0 {
		n := copy(b, r.buf)
		r.buf = r.buf[n:]
		if len(r.buf) == 0 && r.curPkt != nil {
			r.curPkt.putBack()
			r.curPkt = nil
		}
		return n, nil
	}
	pkt, ok := <-r.cc.ch
	if !ok {
		return 0, net.ErrClosed
	}
	n := copy(b, pkt.data[:pkt.n])
	if n < pkt.n {
		r.buf = pkt.data[n:pkt.n]
		r.curPkt = &pkt
	} else {
		pkt.putBack()
	}
	return n, nil
}

func (r *clientConnReader) Write(b []byte) (int, error) {
	data := b
	if r.cipher != nil {
		var err error
		data, err = r.cipher.Encrypt(b)
		if err != nil {
			return 0, err
		}
	}
	return r.pConn.WriteTo(data, r.cc.addr)
}

func (r *clientConnReader) Close() error                        { return nil }
func (r *clientConnReader) LocalAddr() net.Addr                 { return r.pConn.LocalAddr() }
func (r *clientConnReader) RemoteAddr() net.Addr                { return r.cc.addr }
func (r *clientConnReader) SetDeadline(_ time.Time) error       { return nil }
func (r *clientConnReader) SetReadDeadline(_ time.Time) error   { return nil }
func (r *clientConnReader) SetWriteDeadline(_ time.Time) error  { return nil }
