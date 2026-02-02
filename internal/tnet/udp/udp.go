package udp

import (
	"paqet/internal/conf"
	"time"

	"github.com/xtaci/smux"
)

func smuxConf(cfg *conf.UDP) *smux.Config {
	sconf := smux.DefaultConfig()
	sconf.Version = 2
	sconf.KeepAliveInterval = 1 * time.Second
	sconf.KeepAliveTimeout = 5 * time.Second
	sconf.MaxFrameSize = 65535
	sconf.MaxReceiveBuffer = cfg.Smuxbuf
	sconf.MaxStreamBuffer = cfg.Streambuf
	return sconf
}
