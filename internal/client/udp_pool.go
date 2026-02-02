package client

import (
	"paqet/internal/flog"
	"paqet/internal/tnet"
	"sync"
)

type udpPool struct {
	strms sync.Map // uint64 -> tnet.Strm
}

func (p *udpPool) delete(key uint64) error {
	if v, loaded := p.strms.LoadAndDelete(key); loaded {
		strm := v.(tnet.Strm)
		flog.Debugf("closing UDP session stream %d", strm.SID())
		strm.Close()
	} else {
		flog.Debugf("UDP session key %d not found for close", key)
	}
	return nil
}
