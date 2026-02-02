package udp

import (
	"github.com/xtaci/smux"
)

// Strm wraps a smux.Stream and implements tnet.Strm.
type Strm struct {
	*smux.Stream
}

func (s *Strm) SID() int {
	return int(s.ID())
}
