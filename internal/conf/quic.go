package conf

import (
	"fmt"
	"time"
)

type QUIC struct {
	Key         string        `yaml:"key"`
	ALPN        string        `yaml:"alpn"`
	MaxStreams  int           `yaml:"max_streams"`
	IdleTimeout time.Duration `yaml:"idle_timeout"`
	CertFile    string        `yaml:"cert_file"`
	KeyFile     string        `yaml:"key_file"`
}

func (q *QUIC) setDefaults(_ string) {
	if q.ALPN == "" {
		q.ALPN = "h3"
	}
	if q.MaxStreams == 0 {
		q.MaxStreams = 256
	}
	if q.IdleTimeout == 0 {
		q.IdleTimeout = 30 * time.Second
	}
}

func (q *QUIC) validate() []error {
	var errors []error
	if len(q.Key) == 0 && q.CertFile == "" {
		errors = append(errors, fmt.Errorf("QUIC: key or cert_file/key_file is required"))
	}
	if q.MaxStreams < 1 || q.MaxStreams > 65535 {
		errors = append(errors, fmt.Errorf("QUIC: max_streams must be between 1-65535"))
	}
	if q.IdleTimeout < time.Second || q.IdleTimeout > 5*time.Minute {
		errors = append(errors, fmt.Errorf("QUIC: idle_timeout must be between 1s-5m"))
	}
	if (q.CertFile == "") != (q.KeyFile == "") {
		errors = append(errors, fmt.Errorf("QUIC: both cert_file and key_file must be set, or neither"))
	}
	return errors
}
