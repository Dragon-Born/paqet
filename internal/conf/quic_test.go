package conf

import (
	"testing"
	"time"
)

func TestQUICSetDefaults(t *testing.T) {
	q := QUIC{}
	q.setDefaults("client")

	if q.ALPN != "h3" {
		t.Errorf("expected ALPN=h3, got %s", q.ALPN)
	}
	if q.MaxStreams != 256 {
		t.Errorf("expected MaxStreams=256, got %d", q.MaxStreams)
	}
	if q.IdleTimeout != 30*time.Second {
		t.Errorf("expected IdleTimeout=30s, got %v", q.IdleTimeout)
	}
}

func TestQUICSetDefaultsPreservesExisting(t *testing.T) {
	q := QUIC{ALPN: "h2", MaxStreams: 100, IdleTimeout: 10 * time.Second}
	q.setDefaults("server")

	if q.ALPN != "h2" {
		t.Errorf("expected ALPN=h2, got %s", q.ALPN)
	}
	if q.MaxStreams != 100 {
		t.Errorf("expected MaxStreams=100, got %d", q.MaxStreams)
	}
	if q.IdleTimeout != 10*time.Second {
		t.Errorf("expected IdleTimeout=10s, got %v", q.IdleTimeout)
	}
}

func TestQUICValidateNoKeyNoCert(t *testing.T) {
	q := QUIC{ALPN: "h3", MaxStreams: 256, IdleTimeout: 30 * time.Second}
	errs := q.validate()
	if len(errs) == 0 {
		t.Fatal("expected error when no key and no cert_file")
	}
}

func TestQUICValidateKeyOnly(t *testing.T) {
	q := QUIC{Key: "secret", ALPN: "h3", MaxStreams: 256, IdleTimeout: 30 * time.Second}
	errs := q.validate()
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

func TestQUICValidateMaxStreamsBounds(t *testing.T) {
	q := QUIC{Key: "k", ALPN: "h3", MaxStreams: 0, IdleTimeout: 30 * time.Second}
	errs := q.validate()
	found := false
	for _, e := range errs {
		if e != nil {
			found = true
		}
	}
	if !found {
		t.Error("expected error for MaxStreams=0")
	}

	q.MaxStreams = 70000
	errs = q.validate()
	found = false
	for _, e := range errs {
		if e != nil {
			found = true
		}
	}
	if !found {
		t.Error("expected error for MaxStreams=70000")
	}
}

func TestQUICValidateIdleTimeoutBounds(t *testing.T) {
	q := QUIC{Key: "k", ALPN: "h3", MaxStreams: 256, IdleTimeout: 100 * time.Millisecond}
	errs := q.validate()
	if len(errs) == 0 {
		t.Error("expected error for idle_timeout < 1s")
	}

	q.IdleTimeout = 10 * time.Minute
	errs = q.validate()
	if len(errs) == 0 {
		t.Error("expected error for idle_timeout > 5m")
	}
}

func TestQUICValidateCertKeyMismatch(t *testing.T) {
	q := QUIC{Key: "k", ALPN: "h3", MaxStreams: 256, IdleTimeout: 30 * time.Second, CertFile: "cert.pem"}
	errs := q.validate()
	found := false
	for _, e := range errs {
		if e.Error() == "QUIC: both cert_file and key_file must be set, or neither" {
			found = true
		}
	}
	if !found {
		t.Error("expected error for cert without key")
	}
}
