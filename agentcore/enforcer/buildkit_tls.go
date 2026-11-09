package enforcer

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"
)

// buildKitCertExpiryWarn is the remaining validity below which a loaded
// client certificate is logged at Warn instead of Info.
const buildKitCertExpiryWarn = 7 * 24 * time.Hour

// BuildKitTLSConfig configures TLS for the buildkitd Control connection
// (buildkitd --tlscacert/--tlscert/--tlskey on the server side).
type BuildKitTLSConfig struct {
	// CAFile is a PEM bundle used to verify buildkitd's certificate.
	// When empty the system roots are used. When set, ONLY this bundle
	// is trusted (no fallback to system roots).
	CAFile string
	// CertFile and KeyFile are the PEM client certificate and key
	// presented for mutual TLS. Both or neither.
	CertFile string
	KeyFile  string
	// ServerName overrides the name used for SNI and certificate
	// verification. Needed when dialing an IP or a name that is not in
	// the server certificate's SANs.
	ServerName string
}

// Enabled reports whether any TLS option is set.
func (c BuildKitTLSConfig) Enabled() bool {
	return c.CAFile != "" || c.CertFile != "" || c.KeyFile != "" || c.ServerName != ""
}

// BuildKitTLS builds gRPC transport credentials for the Control
// connection and keeps them fresh across certificate rotation.
//
// Reload strategy:
//   - Client certificate/key: re-read on a TLS handshake whenever either
//     file's mtime or size changed (checked per handshake, cheap stat).
//     A failed reload keeps the previous certificate and logs a warning.
//   - CA bundle: re-read each time the watcher (re)connects, i.e. after
//     every disconnect/backoff. A long-lived healthy connection keeps
//     the CA it handshook with.
//
// Existing connections are never torn down by rotation; new handshakes
// (after a reconnect) use the new material.
//
// Do not use TLS with a unix:// address: buildkitd wraps only its TCP
// listeners in TLS, unix sockets are always plaintext. The CE daemon
// rejects that combination at startup.
type BuildKitTLS struct {
	cfg    BuildKitTLSConfig
	logger *slog.Logger

	mu       sync.Mutex
	cert     *tls.Certificate
	certMod  time.Time
	certSize int64
	keyMod   time.Time
	keySize  int64
}

// LoadBuildKitTLS validates cfg (files readable and parseable) and
// returns a ready BuildKitTLS. It fails fast with a descriptive error.
// Key material is never logged; only paths and certificate
// subject/expiry are.
func LoadBuildKitTLS(cfg BuildKitTLSConfig, logger *slog.Logger) (*BuildKitTLS, error) {
	if logger == nil {
		logger = slog.Default()
	}

	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, errors.New("buildkit tls: client cert and key must be set together")
	}

	t := &BuildKitTLS{cfg: cfg, logger: logger}

	if cfg.CAFile != "" {
		_, err := loadCAPool(cfg.CAFile)
		if err != nil {
			return nil, err
		}

		logger.Info("buildkit tls: CA loaded", "ca_file", cfg.CAFile)
	}

	if cfg.CertFile != "" {
		err := t.reloadCert()
		if err != nil {
			return nil, err
		}
	}

	return t, nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("buildkit tls: read CA file: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("buildkit tls: CA file %s contains no valid PEM certificates", path)
	}

	return pool, nil
}

// reloadCert reads the client cert+key pair and stores it. Caller must
// not hold t.mu.
func (t *BuildKitTLS) reloadCert() error {
	cs, cerr := os.Stat(t.cfg.CertFile)
	ks, kerr := os.Stat(t.cfg.KeyFile)

	if cerr != nil {
		return fmt.Errorf("buildkit tls: stat client cert: %w", cerr)
	}

	if kerr != nil {
		return fmt.Errorf("buildkit tls: stat client key: %w", kerr)
	}

	pair, err := tls.LoadX509KeyPair(t.cfg.CertFile, t.cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("buildkit tls: load client key pair: %w", err)
	}

	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("buildkit tls: parse client cert: %w", err)
	}

	pair.Leaf = leaf

	remaining := time.Until(leaf.NotAfter)
	if remaining <= 0 {
		return fmt.Errorf("buildkit tls: client certificate %s expired at %s",
			t.cfg.CertFile, leaf.NotAfter.UTC().Format(time.RFC3339))
	}

	t.mu.Lock()
	t.cert = &pair
	t.certMod, t.certSize = cs.ModTime(), cs.Size()
	t.keyMod, t.keySize = ks.ModTime(), ks.Size()
	t.mu.Unlock()

	attrs := []any{
		"cert_file", t.cfg.CertFile,
		"subject", leaf.Subject.String(),
		"not_after", leaf.NotAfter.UTC().Format(time.RFC3339),
	}

	if remaining < buildKitCertExpiryWarn {
		t.logger.Warn("buildkit tls: client certificate expires soon or is expired", attrs...)
	} else {
		t.logger.Info("buildkit tls: client certificate loaded", attrs...)
	}

	return nil
}

// getClientCertificate is the tls.Config callback: it serves the cached
// pair, reloading when the files changed on disk.
func (t *BuildKitTLS) getClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cs, cerr := os.Stat(t.cfg.CertFile)
	ks, kerr := os.Stat(t.cfg.KeyFile)

	t.mu.Lock()
	cur := t.cert
	changed := cerr == nil && kerr == nil &&
		(!cs.ModTime().Equal(t.certMod) || cs.Size() != t.certSize ||
			!ks.ModTime().Equal(t.keyMod) || ks.Size() != t.keySize)
	t.mu.Unlock()

	if changed {
		err := t.reloadCert()
		if err != nil {
			// Cert and key are often rotated one after the other; keep
			// serving the old pair and retry on the next handshake.
			t.logger.Warn("buildkit tls: client certificate reload failed; keeping previous", "error", err)
		} else {
			t.mu.Lock()
			cur = t.cert
			t.mu.Unlock()
		}
	}

	if cur == nil {
		return nil, errors.New("buildkit tls: no client certificate loaded")
	}

	return cur, nil
}

// TransportCredentials builds credentials for one connection. It
// re-reads the CA bundle, so call it per (re)connect.
func (t *BuildKitTLS) TransportCredentials() (credentials.TransportCredentials, error) {
	tc := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: t.cfg.ServerName,
	}

	if t.cfg.CAFile != "" {
		pool, err := loadCAPool(t.cfg.CAFile)
		if err != nil {
			return nil, err
		}

		tc.RootCAs = pool
	}

	if t.cfg.CertFile != "" {
		tc.GetClientCertificate = t.getClientCertificate
	}

	return credentials.NewTLS(tc), nil
}

// WithTLS makes the watcher dial buildkitd over TLS using t (from
// LoadBuildKitTLS). nil keeps plaintext. Ignored when WithDialOptions
// is set.
func WithTLS(t *BuildKitTLS) WatcherOption {
	return func(w *AttributionWatcher) { w.tls = t }
}
