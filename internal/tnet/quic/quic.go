package quic

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"paqet/internal/conf"
	"time"

	"github.com/quic-go/quic-go"
)

// buildTLSConfig creates a TLS configuration for QUIC.
// If cert_file and key_file are provided, they are used directly.
// Otherwise, a deterministic self-signed certificate is derived from the shared key.
func buildTLSConfig(cfg *conf.QUIC, isServer bool) (*tls.Config, error) {
	var cert tls.Certificate
	var err error

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err = tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, err
		}
	} else {
		cert, err = deterministicCert(cfg.Key)
		if err != nil {
			return nil, err
		}
	}

	tlsConf := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		NextProtos:         []string{cfg.ALPN},
		InsecureSkipVerify: true,
	}

	if isServer {
		tlsConf.ClientAuth = tls.NoClientCert
	}

	return tlsConf, nil
}

// deterministicCert generates a deterministic ECDSA certificate from a shared key.
// Both client and server derive the same cert from the same key.
func deterministicCert(key string) (tls.Certificate, error) {
	// Derive deterministic private key scalar from shared key
	seed := sha256.Sum256([]byte("paqet-quic-cert:" + key))

	curve := elliptic.P256()
	d := new(big.Int).SetBytes(seed[:])
	// Ensure d is in valid range [1, N-1]
	d.Mod(d, new(big.Int).Sub(curve.Params().N, big.NewInt(1)))
	d.Add(d, big.NewInt(1))

	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve},
		D:        d,
	}
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())

	// Use deterministic reader for certificate creation (signing nonce)
	deterministicReader := &deterministicRand{data: append([]byte{}, seed[:]...)}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2034, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(deterministicReader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// deterministicRand is an io.Reader that produces deterministic output from a seed
// by repeatedly hashing.
type deterministicRand struct {
	data []byte
	pos  int
}

func (d *deterministicRand) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if d.pos >= len(d.data) {
			h := sha256.Sum256(d.data)
			d.data = h[:]
			d.pos = 0
		}
		copied := copy(p[n:], d.data[d.pos:])
		d.pos += copied
		n += copied
	}
	return n, nil
}

var _ io.Reader = (*deterministicRand)(nil)

// buildQUICConfig creates a QUIC configuration.
func buildQUICConfig(cfg *conf.QUIC) *quic.Config {
	return &quic.Config{
		MaxIncomingStreams: int64(cfg.MaxStreams),
		MaxIdleTimeout:    cfg.IdleTimeout,
		KeepAlivePeriod:   cfg.IdleTimeout / 3,
		Allow0RTT:         true,
	}
}
