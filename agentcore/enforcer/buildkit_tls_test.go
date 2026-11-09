package enforcer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, _ := x509.ParseCertificate(der)

	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue returns PEM cert and key for cn, valid for server and client use.
func (ca *testCA) issue(t *testing.T, cn string, serial int64, dns []string, ips []net.IP) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}

	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()

	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// startTLSServer runs a health gRPC server on localhost. When clientCA
// is nil client certs are not requested.
func startTLSServer(t *testing.T, ca *testCA, clientCA *testCA) string {
	t.Helper()

	cp, kp := ca.issue(t, "buildkitd", 10, []string{"buildkitd.test"}, []net.IP{net.ParseIP("127.0.0.1")})

	pair, err := tls.X509KeyPair(cp, kp)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	if clientCA != nil {
		pool := x509.NewCertPool()
		pool.AddCert(clientCA.cert)
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	healthpb.RegisterHealthServer(srv, health.NewServer())

	go func() { _ = srv.Serve(lis) }()

	t.Cleanup(srv.Stop)

	return lis.Addr().String()
}

type tlsFixture struct {
	dir                       string
	ca                        *testCA
	caFile, certFile, keyFile string
}

func newTLSFixture(t *testing.T) *tlsFixture {
	t.Helper()

	f := &tlsFixture{dir: t.TempDir(), ca: newTestCA(t, "test-ca")}
	f.caFile = filepath.Join(f.dir, "ca.pem")
	f.certFile = filepath.Join(f.dir, "tls.crt")
	f.keyFile = filepath.Join(f.dir, "tls.key")

	writeFile(t, f.caFile, f.ca.pem)
	c, k := f.ca.issue(t, "agent-1", 20, nil, nil)
	writeFile(t, f.certFile, c)
	writeFile(t, f.keyFile, k)

	return f
}

// check dials addr through a watcher with the given TLS config and
// performs one health RPC.
func checkHealth(t *testing.T, addr string, cfg BuildKitTLSConfig) error {
	t.Helper()

	bk, err := LoadBuildKitTLS(cfg, nil)
	if err != nil {
		t.Fatalf("LoadBuildKitTLS: %v", err)
	}

	w := NewAttributionWatcher("tcp://"+addr, NewSessionRegistry(time.Minute), nil, WithTLS(bk))

	conn, err := w.connect(context.Background())
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})

	return err
}

func TestBuildKitTLS_MutualSuccess(t *testing.T) {
	f := newTLSFixture(t)
	addr := startTLSServer(t, f.ca, f.ca)

	err := checkHealth(t, addr, BuildKitTLSConfig{
		CAFile: f.caFile, CertFile: f.certFile, KeyFile: f.keyFile, ServerName: "buildkitd.test",
	})
	if err != nil {
		t.Fatalf("mTLS health check: %v", err)
	}
}

func TestBuildKitTLS_WrongCAFails(t *testing.T) {
	f := newTLSFixture(t)
	addr := startTLSServer(t, f.ca, f.ca)

	other := newTestCA(t, "other-ca")
	otherFile := filepath.Join(f.dir, "other.pem")
	writeFile(t, otherFile, other.pem)

	err := checkHealth(t, addr, BuildKitTLSConfig{
		CAFile: otherFile, CertFile: f.certFile, KeyFile: f.keyFile, ServerName: "buildkitd.test",
	})
	if err == nil {
		t.Fatal("expected verification failure with wrong CA")
	}
}

func TestBuildKitTLS_MissingClientCertRejected(t *testing.T) {
	f := newTLSFixture(t)
	addr := startTLSServer(t, f.ca, f.ca)

	err := checkHealth(t, addr, BuildKitTLSConfig{CAFile: f.caFile, ServerName: "buildkitd.test"})
	if err == nil {
		t.Fatal("server requiring client certs accepted a client without one")
	}
}

func TestBuildKitTLS_ClientCertFromUntrustedCARejected(t *testing.T) {
	f := newTLSFixture(t)
	other := newTestCA(t, "rogue")
	addr := startTLSServer(t, f.ca, other) // server trusts only "rogue" for clients

	err := checkHealth(t, addr, BuildKitTLSConfig{
		CAFile: f.caFile, CertFile: f.certFile, KeyFile: f.keyFile, ServerName: "buildkitd.test",
	})
	if err == nil {
		t.Fatal("client cert from an untrusted CA was accepted")
	}
}

func TestBuildKitTLS_ServerNameOverride(t *testing.T) {
	f := newTLSFixture(t)
	addr := startTLSServer(t, f.ca, nil)

	// 127.0.0.1 is in the SANs, a made-up name is not.
	if err := checkHealth(t, addr, BuildKitTLSConfig{CAFile: f.caFile}); err != nil {
		t.Fatalf("IP SAN verification: %v", err)
	}

	if err := checkHealth(t, addr, BuildKitTLSConfig{CAFile: f.caFile, ServerName: "buildkitd.test"}); err != nil {
		t.Fatalf("override to SAN name: %v", err)
	}

	if err := checkHealth(t, addr, BuildKitTLSConfig{CAFile: f.caFile, ServerName: "not-in-cert.test"}); err == nil {
		t.Fatal("expected name mismatch failure")
	}
}

func TestBuildKitTLS_PlaintextClientCannotTalkToTLSServer(t *testing.T) {
	f := newTLSFixture(t)
	addr := startTLSServer(t, f.ca, nil)

	w := NewAttributionWatcher("tcp://"+addr, NewSessionRegistry(time.Minute), nil)

	conn, err := w.connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}); err == nil {
		t.Fatal("plaintext client unexpectedly succeeded against a TLS listener")
	}
}

func TestBuildKitTLS_CertRotation(t *testing.T) {
	f := newTLSFixture(t)

	cp, kp := f.ca.issue(t, "buildkitd", 10, []string{"buildkitd.test"}, nil)
	pair, _ := tls.X509KeyPair(cp, kp)

	pool := x509.NewCertPool()
	pool.AddCert(f.ca.cert)

	seen := make(chan string, 8)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			c, _ := x509.ParseCertificate(raw[0])
			seen <- c.Subject.CommonName

			return nil
		},
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	healthpb.RegisterHealthServer(srv, health.NewServer())

	go func() { _ = srv.Serve(lis) }()

	t.Cleanup(srv.Stop)

	tc := BuildKitTLSConfig{CAFile: f.caFile, CertFile: f.certFile, KeyFile: f.keyFile, ServerName: "buildkitd.test"}

	bk, err := LoadBuildKitTLS(tc, nil)
	if err != nil {
		t.Fatal(err)
	}

	handshake := func() string {
		creds, err := bk.TransportCredentials()
		if err != nil {
			t.Fatal(err)
		}

		conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(creds))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		if _, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
			t.Fatalf("health: %v", err)
		}

		return <-seen
	}

	if got := handshake(); got != "agent-1" {
		t.Fatalf("first handshake cert = %q", got)
	}

	// Rotate: rewrite both files with a new identity, bump mtime.
	c2, k2 := f.ca.issue(t, "agent-2", 21, nil, nil)
	writeFile(t, f.keyFile, k2)
	writeFile(t, f.certFile, c2)

	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(f.certFile, future, future)
	_ = os.Chtimes(f.keyFile, future, future)

	if got := handshake(); got != "agent-2" {
		t.Fatalf("handshake after rotation cert = %q, want agent-2", got)
	}
}

func TestLoadBuildKitTLS_Validation(t *testing.T) {
	f := newTLSFixture(t)

	bad := filepath.Join(f.dir, "bad.pem")
	writeFile(t, bad, []byte("not pem"))

	cases := map[string]struct {
		cfg  BuildKitTLSConfig
		want string
	}{
		"cert without key": {BuildKitTLSConfig{CertFile: f.certFile}, "together"},
		"key without cert": {BuildKitTLSConfig{KeyFile: f.keyFile}, "together"},
		"missing CA":       {BuildKitTLSConfig{CAFile: filepath.Join(f.dir, "nope")}, "read CA"},
		"garbage CA":       {BuildKitTLSConfig{CAFile: bad}, "no valid PEM"},
		"garbage cert":     {BuildKitTLSConfig{CertFile: bad, KeyFile: f.keyFile}, "client key pair"},
		"missing key file": {BuildKitTLSConfig{CertFile: f.certFile, KeyFile: filepath.Join(f.dir, "nope")}, "stat client key"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadBuildKitTLS(tc.cfg, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestBuildKitTLS_MismatchedPairKeepsOldThenNew(t *testing.T) {
	f := newTLSFixture(t)

	bk, err := LoadBuildKitTLS(BuildKitTLSConfig{CAFile: f.caFile, CertFile: f.certFile, KeyFile: f.keyFile}, nil)
	if err != nil {
		t.Fatal(err)
	}

	cn := func() string {
		c, err := bk.getClientCertificate(nil)
		if err != nil {
			t.Fatal(err)
		}

		return c.Leaf.Subject.CommonName
	}

	// New cert lands first, old key still on disk: mismatch.
	c2, k2 := f.ca.issue(t, "agent-2", 21, nil, nil)
	writeFile(t, f.certFile, c2)

	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(f.certFile, future, future)

	if got := cn(); got != "agent-1" {
		t.Fatalf("mid-write cert = %q, want old agent-1", got)
	}

	writeFile(t, f.keyFile, k2)

	future = future.Add(time.Minute)
	_ = os.Chtimes(f.keyFile, future, future)

	if got := cn(); got != "agent-2" {
		t.Fatalf("after both files landed cert = %q, want agent-2", got)
	}
}

func TestBuildKitTLS_CAReloadedOnConnect(t *testing.T) {
	f := newTLSFixture(t)
	addr := startTLSServer(t, f.ca, nil)

	other := newTestCA(t, "other-ca")
	caFile := filepath.Join(f.dir, "live-ca.pem")
	writeFile(t, caFile, other.pem)

	bk, err := LoadBuildKitTLS(BuildKitTLSConfig{CAFile: caFile, ServerName: "buildkitd.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	w := NewAttributionWatcher("tcp://"+addr, NewSessionRegistry(time.Minute), nil, WithTLS(bk))

	try := func() error {
		conn, err := w.connect(context.Background())
		if err != nil {
			return err
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})

		return err
	}

	if try() == nil {
		t.Fatal("old (wrong) CA accepted")
	}

	writeFile(t, caFile, f.ca.pem)

	if err := try(); err != nil {
		t.Fatalf("new CA not honoured on next connect: %v", err)
	}
}

func TestLoadBuildKitTLS_ExpiredCertFatal(t *testing.T) {
	f := newTLSFixture(t)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "old"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca.cert, &key.PublicKey, f.ca.key)
	if err != nil {
		t.Fatal(err)
	}

	kder, _ := x509.MarshalECPrivateKey(key)
	writeFile(t, f.certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeFile(t, f.keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))

	_, err = LoadBuildKitTLS(BuildKitTLSConfig{CertFile: f.certFile, KeyFile: f.keyFile}, nil)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("err = %v, want expired", err)
	}
}

func TestBuildKitTLS_RotationToExpiredCertKeepsOld(t *testing.T) {
	f := newTLSFixture(t)

	bk, err := LoadBuildKitTLS(BuildKitTLSConfig{CertFile: f.certFile, KeyFile: f.keyFile}, nil)
	if err != nil {
		t.Fatal(err)
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(98),
		Subject:      pkix.Name{CommonName: "expired"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca.cert, &key.PublicKey, f.ca.key)
	if err != nil {
		t.Fatal(err)
	}

	kder, _ := x509.MarshalECPrivateKey(key)
	writeFile(t, f.certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeFile(t, f.keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))

	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(f.certFile, future, future)
	_ = os.Chtimes(f.keyFile, future, future)

	c, err := bk.getClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}

	if got := c.Leaf.Subject.CommonName; got != "agent-1" {
		t.Fatalf("cert after rotation to expired = %q, want old agent-1", got)
	}
}

// TestBuildKitTLS_ConnTrackerRecordsRawTCPAddr checks that the connection
// tracker works together with TLS: it holds the raw TCP local address
// while the connection is up and releases it when the TLS conn closes.
func TestBuildKitTLS_ConnTrackerRecordsRawTCPAddr(t *testing.T) {
	f := newTLSFixture(t)
	addr := startTLSServer(t, f.ca, f.ca)

	bk, err := LoadBuildKitTLS(BuildKitTLSConfig{
		CAFile: f.caFile, CertFile: f.certFile, KeyFile: f.keyFile, ServerName: "buildkitd.test",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	tr := NewBuildKitConnTracker()
	w := NewAttributionWatcher("tcp://"+addr, NewSessionRegistry(time.Minute), nil, WithTLS(bk), WithConnTracker(tr))

	conn, err := w.connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("health over TLS with tracker: %v", err)
	}

	local, ok := tr.Local()
	if !ok {
		t.Fatal("tracker not populated")
	}

	if _, isTCP := local.(*net.TCPAddr); !isTCP {
		t.Fatalf("tracker local = %T, want the raw *net.TCPAddr", local)
	}

	_ = conn.Close()

	waitFor(t, time.Second, func() bool { _, ok := tr.Local(); return !ok })
}
