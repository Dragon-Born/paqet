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

	// Flow control windows for high-throughput optimization
	InitialStreamWindow uint64 `yaml:"initial_stream_window"`
	MaxStreamWindow     uint64 `yaml:"max_stream_window"`
	InitialConnWindow   uint64 `yaml:"initial_conn_window"`
	MaxConnWindow       uint64 `yaml:"max_conn_window"`
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
	// Flow control windows for high-throughput
	if q.InitialStreamWindow == 0 {
		q.InitialStreamWindow = 4 * 1024 * 1024 // 4 MB
	}
	if q.MaxStreamWindow == 0 {
		q.MaxStreamWindow = 8 * 1024 * 1024 // 8 MB
	}
	if q.InitialConnWindow == 0 {
		q.InitialConnWindow = 8 * 1024 * 1024 // 8 MB
	}
	if q.MaxConnWindow == 0 {
		q.MaxConnWindow = 16 * 1024 * 1024 // 16 MB
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
