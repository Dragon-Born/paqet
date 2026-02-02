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

func TestTransportValidateAutoAccepted(t *testing.T) {
	tr := Transport{Protocol: "auto", Conn: 1}
	errs := tr.validate()
	// Should not have "invalid protocol" error.
	for _, e := range errs {
		if e.Error() == "transport protocol must be one of: [kcp quic udp auto]" {
			t.Error("auto should be accepted as a valid protocol")
		}
	}
}

func TestTransportValidateAutoNeedsTwo(t *testing.T) {
	// Only one protocol configured — should fail.
	tr := Transport{
		Protocol: "auto",
		Conn:     1,
		KCP:      &KCP{Mode: "fast", Key: "key", Block_: "aes", MTU: 1350, Rcvwnd: 512, Sndwnd: 512, Smuxbuf: 4096, Streambuf: 4096},
	}
	errs := tr.validate()
	found := false
	for _, e := range errs {
		if e.Error() == "auto mode requires at least 2 protocol configurations (kcp, quic, udp)" {
			found = true
		}
	}
	if !found {
		t.Error("expected error requiring at least 2 protocols for auto mode")
	}
}

func TestTransportValidateAutoWithTwo(t *testing.T) {
	tr := Transport{
		Protocol: "auto",
		Conn:     1,
		KCP:      &KCP{Mode: "fast", Key: "key", Block_: "aes", MTU: 1350, Rcvwnd: 512, Sndwnd: 512, Smuxbuf: 4096, Streambuf: 4096},
		QUIC:     &QUIC{Key: "key", ALPN: "h3", MaxStreams: 256, IdleTimeout: 30 * time.Second},
	}
	errs := tr.validate()
	for _, e := range errs {
		if e.Error() == "auto mode requires at least 2 protocol configurations (kcp, quic, udp)" {
			t.Error("should not get min-2 error when 2 protocols configured")
		}
	}
}

func TestTransportValidateAutoWithThree(t *testing.T) {
	tr := Transport{
		Protocol: "auto",
		Conn:     1,
		KCP:      &KCP{Mode: "fast", Key: "key", Block_: "aes", MTU: 1350, Rcvwnd: 512, Sndwnd: 512, Smuxbuf: 4096, Streambuf: 4096},
		QUIC:     &QUIC{Key: "key", ALPN: "h3", MaxStreams: 256, IdleTimeout: 30 * time.Second},
		UDP:      &UDP{Key: "key", Block_: "aes", Smuxbuf: 4096, Streambuf: 4096},
	}
	errs := tr.validate()
	for _, e := range errs {
		if e.Error() == "auto mode requires at least 2 protocol configurations (kcp, quic, udp)" {
			t.Error("should not get min-2 error when 3 protocols configured")
		}
	}
}

func TestTransportSetDefaultsAuto(t *testing.T) {
	tr := Transport{
		Protocol: "auto",
		KCP:      &KCP{},
		QUIC:     &QUIC{},
	}
	tr.setDefaults("client")

	if tr.Conn != 1 {
		t.Errorf("expected conn=1, got %d", tr.Conn)
	}
	if tr.KCP.Mode != "fast3" {
		t.Errorf("expected KCP mode=fast3, got %s", tr.KCP.Mode)
	}
	if tr.QUIC.ALPN != "h3" {
		t.Errorf("expected QUIC ALPN=h3, got %s", tr.QUIC.ALPN)
	}
}

func TestTransportSetDefaultsAutoNilProtocols(t *testing.T) {
	// Auto mode should not create nil protocol configs — only set defaults
	// on ones that exist.
	tr := Transport{Protocol: "auto"}
	tr.setDefaults("server")

	if tr.KCP != nil {
		t.Error("KCP should remain nil when not configured in auto mode")
	}
	if tr.QUIC != nil {
		t.Error("QUIC should remain nil when not configured in auto mode")
	}
	if tr.UDP != nil {
		t.Error("UDP should remain nil when not configured in auto mode")
	}
}

func TestTransportValidateAutoValidatesSubProtocols(t *testing.T) {
	// Auto mode with invalid sub-protocol config should report sub errors.
	tr := Transport{
		Protocol: "auto",
		Conn:     1,
		KCP:      &KCP{Mode: "invalid_mode", Key: "key", Block_: "aes", MTU: 1350, Rcvwnd: 512, Sndwnd: 512, Smuxbuf: 4096, Streambuf: 4096},
		QUIC:     &QUIC{Key: "key", ALPN: "h3", MaxStreams: 256, IdleTimeout: 30 * time.Second},
	}
	errs := tr.validate()
	found := false
	for _, e := range errs {
		if e.Error() == "KCP mode must be one of: [normal fast fast2 fast3 fast4 manual]" {
			found = true
		}
	}
	if !found {
		t.Error("expected KCP mode validation error in auto mode")
	}
}
