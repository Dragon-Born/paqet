package quic

import (
	"bytes"
	"crypto/ecdsa"
	"paqet/internal/conf"
	"testing"
	"time"
)

func TestDeterministicCertSamePrivateKey(t *testing.T) {
	// The deterministic cert derives the same private key from the same shared key.
	// The certificate bytes may differ between calls (Go's x509.CreateCertificate
	// is not guaranteed to be deterministic), but the private key MUST be the same
	// so both client and server can establish TLS.
	cert1, err := deterministicCert("shared-secret")
	if err != nil {
		t.Fatalf("deterministicCert failed: %v", err)
	}
	cert2, err := deterministicCert("shared-secret")
	if err != nil {
		t.Fatalf("deterministicCert failed: %v", err)
	}

	key1, ok1 := cert1.PrivateKey.(*ecdsa.PrivateKey)
	key2, ok2 := cert2.PrivateKey.(*ecdsa.PrivateKey)
	if !ok1 || !ok2 {
		t.Fatal("expected ECDSA private keys")
	}

	if key1.D.Cmp(key2.D) != 0 {
		t.Fatal("same key should produce same private key scalar D")
	}
	if key1.PublicKey.X.Cmp(key2.PublicKey.X) != 0 || key1.PublicKey.Y.Cmp(key2.PublicKey.Y) != 0 {
		t.Fatal("same key should produce same public key")
	}
}

func TestDeterministicCertDifferentKey(t *testing.T) {
	cert1, err := deterministicCert("key-a")
	if err != nil {
		t.Fatalf("deterministicCert failed: %v", err)
	}
	cert2, err := deterministicCert("key-b")
	if err != nil {
		t.Fatalf("deterministicCert failed: %v", err)
	}

	key1 := cert1.PrivateKey.(*ecdsa.PrivateKey)
	key2 := cert2.PrivateKey.(*ecdsa.PrivateKey)

	if key1.D.Cmp(key2.D) == 0 {
		t.Fatal("different keys should produce different private keys")
	}
}

func TestDeterministicCertValid(t *testing.T) {
	cert, err := deterministicCert("test-key")
	if err != nil {
		t.Fatalf("deterministicCert failed: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected at least one certificate")
	}
	if cert.PrivateKey == nil {
		t.Fatal("expected private key to be set")
	}
}

func TestBuildTLSConfigClient(t *testing.T) {
	cfg := &conf.QUIC{Key: "test", ALPN: "h3"}
	tlsConf, err := buildTLSConfig(cfg, false)
	if err != nil {
		t.Fatalf("buildTLSConfig failed: %v", err)
	}
	if len(tlsConf.Certificates) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(tlsConf.Certificates))
	}
	if len(tlsConf.NextProtos) != 1 || tlsConf.NextProtos[0] != "h3" {
		t.Errorf("expected NextProtos=[h3], got %v", tlsConf.NextProtos)
	}
	if !tlsConf.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true for shared-key mode")
	}
}

func TestBuildTLSConfigServer(t *testing.T) {
	cfg := &conf.QUIC{Key: "test", ALPN: "h3"}
	tlsConf, err := buildTLSConfig(cfg, true)
	if err != nil {
		t.Fatalf("buildTLSConfig failed: %v", err)
	}
	if tlsConf.ClientAuth != 0 { // tls.NoClientCert == 0
		t.Errorf("expected NoClientCert, got %d", tlsConf.ClientAuth)
	}
}

func TestBuildQUICConfig(t *testing.T) {
	cfg := &conf.QUIC{MaxStreams: 128, IdleTimeout: 60 * time.Second}
	qConf := buildQUICConfig(cfg)

	if qConf.MaxIncomingStreams != 128 {
		t.Errorf("expected MaxIncomingStreams=128, got %d", qConf.MaxIncomingStreams)
	}
	if qConf.MaxIdleTimeout != 60*time.Second {
		t.Errorf("expected MaxIdleTimeout=60s, got %v", qConf.MaxIdleTimeout)
	}
	if qConf.KeepAlivePeriod != 20*time.Second {
		t.Errorf("expected KeepAlivePeriod=20s, got %v", qConf.KeepAlivePeriod)
	}
	if !qConf.Allow0RTT {
		t.Error("expected Allow0RTT=true")
	}
}

func TestDeterministicRandProducesDeterministicOutput(t *testing.T) {
	r1 := &deterministicRand{data: []byte("seed1234567890123456789012345678")}
	r2 := &deterministicRand{data: []byte("seed1234567890123456789012345678")}

	buf1 := make([]byte, 100)
	buf2 := make([]byte, 100)
	r1.Read(buf1)
	r2.Read(buf2)

	if !bytes.Equal(buf1, buf2) {
		t.Fatal("same seed should produce same output")
	}
}

func TestDeterministicRandLargeRead(t *testing.T) {
	r := &deterministicRand{data: []byte("short-seed-12345678901234567890")}
	buf := make([]byte, 1024)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 1024 {
		t.Fatalf("expected 1024 bytes, got %d", n)
	}
}
