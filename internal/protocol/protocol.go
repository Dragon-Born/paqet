package protocol

import (
	"encoding/binary"
	"errors"
	"io"
	"paqet/internal/conf"
	"paqet/internal/tnet"
)

type PType = byte

const (
	PPING PType = 0x01
	PPONG PType = 0x02
	PTCPF PType = 0x03
	PTCP  PType = 0x04
	PUDP  PType = 0x05
)

var (
	ErrUnknownProtoType = errors.New("unknown protocol type")
	ErrNilAddr          = errors.New("addr is nil")
)

type Proto struct {
	Type PType
	Addr *tnet.Addr
	TCPF []conf.TCPF
}

func (p *Proto) Read(r io.Reader) error {
	var typeBuf [1]byte
	if _, err := io.ReadFull(r, typeBuf[:]); err != nil {
		return err
	}
	p.Type = typeBuf[0]

	switch p.Type {
	case PPING, PPONG:
		return nil
	case PTCP, PUDP:
		return p.readAddr(r)
	case PTCPF:
		return p.readTCPF(r)
	default:
		return ErrUnknownProtoType
	}
}

func (p *Proto) Write(w io.Writer) error {
	if _, err := w.Write([]byte{p.Type}); err != nil {
		return err
	}

	switch p.Type {
	case PPING, PPONG:
		return nil
	case PTCP, PUDP:
		return p.writeAddr(w)
	case PTCPF:
		return p.writeTCPF(w)
	default:
		return ErrUnknownProtoType
	}
}

// readTCPF reads TCPF entries using binary encoding.
// Wire format: uint16 count, then for each entry: 2 bytes of packed flags.
func (p *Proto) readTCPF(r io.Reader) error {
	var count uint16
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return err
	}
	p.TCPF = make([]conf.TCPF, count)
	for i := range p.TCPF {
		var packed [2]byte
		if _, err := io.ReadFull(r, packed[:]); err != nil {
			return err
		}
		p.TCPF[i] = unpackTCPF(packed)
	}
	return nil
}

// writeTCPF writes TCPF entries using binary encoding.
func (p *Proto) writeTCPF(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, uint16(len(p.TCPF))); err != nil {
		return err
	}
	for _, f := range p.TCPF {
		packed := packTCPF(f)
		if _, err := w.Write(packed[:]); err != nil {
			return err
		}
	}
	return nil
}

// packTCPF encodes a TCPF into 2 bytes (9 flags, 7 bits reserved).
func packTCPF(f conf.TCPF) [2]byte {
	var b [2]byte
	if f.FIN {
		b[0] |= 1 << 0
	}
	if f.SYN {
		b[0] |= 1 << 1
	}
	if f.RST {
		b[0] |= 1 << 2
	}
	if f.PSH {
		b[0] |= 1 << 3
	}
	if f.ACK {
		b[0] |= 1 << 4
	}
	if f.URG {
		b[0] |= 1 << 5
	}
	if f.ECE {
		b[0] |= 1 << 6
	}
	if f.CWR {
		b[0] |= 1 << 7
	}
	if f.NS {
		b[1] |= 1 << 0
	}
	return b
}

// unpackTCPF decodes a TCPF from 2 bytes.
func unpackTCPF(b [2]byte) conf.TCPF {
	return conf.TCPF{
		FIN: b[0]&(1<<0) != 0,
		SYN: b[0]&(1<<1) != 0,
		RST: b[0]&(1<<2) != 0,
		PSH: b[0]&(1<<3) != 0,
		ACK: b[0]&(1<<4) != 0,
		URG: b[0]&(1<<5) != 0,
		ECE: b[0]&(1<<6) != 0,
		CWR: b[0]&(1<<7) != 0,
		NS:  b[1]&(1<<0) != 0,
	}
}

func (p *Proto) readAddr(r io.Reader) error {
	var addrLen uint16
	if err := binary.Read(r, binary.BigEndian, &addrLen); err != nil {
		return err
	}
	buf := make([]byte, addrLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	addr, err := tnet.NewAddr(string(buf))
	if err != nil {
		return err
	}
	p.Addr = addr
	return nil
}

func (p *Proto) writeAddr(w io.Writer) error {
	if p.Addr == nil {
		return ErrNilAddr
	}
	addrStr := p.Addr.String()
	if err := binary.Write(w, binary.BigEndian, uint16(len(addrStr))); err != nil {
		return err
	}
	_, err := w.Write([]byte(addrStr))
	return err
}
