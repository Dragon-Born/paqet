package conf

import (
	"testing"
	"time"
)

func TestTransportSetDefaultsKCP(t *testing.T) {
	tr := Transport{Protocol: "kcp"}
	tr.setDefaults("client")

	if tr.Conn != 1 {
		t.Errorf("expected conn=1, got %d", tr.Conn)
	}
	if tr.KCP == nil {
		t.Fatal("KCP config should be initialized")
	}
	if tr.KCP.Mode != "fast3" {
		t.Errorf("expected KCP mode=fast3, got %s", tr.KCP.Mode)
	}
}

func TestTransportSetDefaultsQUIC(t *testing.T) {
	tr := Transport{Protocol: "quic"}
	tr.setDefaults("server")

	if tr.QUIC == nil {
		t.Fatal("QUIC config should be initialized")
	}
	if tr.QUIC.ALPN != "h3" {
		t.Errorf("expected ALPN=h3, got %s", tr.QUIC.ALPN)
	}
	if tr.QUIC.MaxStreams != 256 {
		t.Errorf("expected max_streams=256, got %d", tr.QUIC.MaxStreams)
	}
	if tr.QUIC.IdleTimeout != 30*time.Second {
		t.Errorf("expected idle_timeout=30s, got %v", tr.QUIC.IdleTimeout)
	}
}

func TestTransportSetDefaultsUDP(t *testing.T) {
	tr := Transport{Protocol: "udp"}
	tr.setDefaults("client")

	if tr.UDP == nil {
		t.Fatal("UDP config should be initialized")
	}
	if tr.UDP.Block_ != "aes" {
		t.Errorf("expected block=aes, got %s", tr.UDP.Block_)
	}
	if tr.UDP.Smuxbuf != 4*1024*1024 {
		t.Errorf("expected smuxbuf=4MB, got %d", tr.UDP.Smuxbuf)
	}
}

func TestTransportValidateInvalidProtocol(t *testing.T) {
	tr := Transport{Protocol: "websocket", Conn: 1}
	errs := tr.validate()
	if len(errs) == 0 {
		t.Fatal("expected validation error for invalid protocol")
	}
}

func TestTransportValidateConnRange(t *testing.T) {
	tr := Transport{Protocol: "kcp", Conn: 0, KCP: &KCP{}}
	tr.KCP.setDefaults("client")
	errs := tr.validate()
	hasConnErr := false
	for _, e := range errs {
		if e.Error() == "transport conn must be between 1-256 connections" {
			hasConnErr = true
		}
	}
	if !hasConnErr {
		t.Error("expected conn range validation error")
	}

	tr.Conn = 257
	errs = tr.validate()
	hasConnErr = false
	for _, e := range errs {
		if e.Error() == "transport conn must be between 1-256 connections" {
			hasConnErr = true
		}
	}
	if !hasConnErr {
		t.Error("expected conn range validation error for 257")
	}
}

func TestTransportValidateKCPNilConfig(t *testing.T) {
	tr := Transport{Protocol: "kcp", Conn: 1, KCP: nil}
	errs := tr.validate()
	found := false
	for _, e := range errs {
		if e.Error() == "KCP configuration is required when protocol is 'kcp'" {
			found = true
		}
	}
	if !found {
		t.Error("expected error for nil KCP config")
	}
}

func TestTransportValidateQUICNilConfig(t *testing.T) {
	tr := Transport{Protocol: "quic", Conn: 1, QUIC: nil}
	errs := tr.validate()
	found := false
	for _, e := range errs {
		if e.Error() == "QUIC configuration is required when protocol is 'quic'" {
			found = true
		}
	}
	if !found {
		t.Error("expected error for nil QUIC config")
	}
}

func TestTransportValidateUDPNilConfig(t *testing.T) {
	tr := Transport{Protocol: "udp", Conn: 1, UDP: nil}
	errs := tr.validate()
	found := false
	for _, e := range errs {
		if e.Error() == "UDP configuration is required when protocol is 'udp'" {
			found = true
		}
	}
	if !found {
		t.Error("expected error for nil UDP config")
	}
}

func TestTransportValidateQUICValid(t *testing.T) {
	tr := Transport{
		Protocol: "quic",
		Conn:     1,
		QUIC: &QUIC{
			Key:         "test-key",
			ALPN:        "h3",
			MaxStreams:  256,
			IdleTimeout: 30 * time.Second,
		},
	}
	errs := tr.validate()
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

func TestTransportValidateUDPValid(t *testing.T) {
	tr := Transport{
		Protocol: "udp",
		Conn:     1,
		UDP: &UDP{
			Key:       "test-key",
			Block_:    "aes",
			Smuxbuf:   4 * 1024 * 1024,
			Streambuf: 2 * 1024 * 1024,
		},
	}
	errs := tr.validate()
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}
