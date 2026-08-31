package certsync

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeCertificatePair(
	t *testing.T,
	root string,
	name string,
	ip net.IP,
	notAfter time.Time,
) Pair {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(notAfter.UnixNano()),
		Subject:      pkix.Name{CommonName: ip.String()},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter.UTC(),
		IPAddresses:  []net.IP{ip},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader, template, template, publicKey, privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER},
	)
	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER},
	)
	certificatePath := filepath.Join(root, name+".crt")
	privateKeyPath := filepath.Join(root, name+".key")
	if err := os.WriteFile(certificatePath, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return Pair{
		CertificatePath: certificatePath,
		PrivateKeyPath:  privateKeyPath,
		CertificatePEM:  certificatePEM,
		PrivateKeyPEM:   privateKeyPEM,
		IP:              ip,
		NotAfter:        notAfter.UTC(),
	}
}

func TestDiscoverSelectsNewestMatchingIPCertificate(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	target := net.ParseIP("203.0.113.10")
	writeCertificatePair(t, root, "older", target, now.Add(2*time.Hour))
	newest := writeCertificatePair(t, root, "newer", target, now.Add(6*time.Hour))
	writeCertificatePair(
		t, root, "wrong", net.ParseIP("198.51.100.8"), now.Add(8*time.Hour),
	)

	result, err := Discover(root, target, now, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if result.CertificatePath != newest.CertificatePath {
		t.Fatalf("selected %q, want newest matching pair", result.CertificatePath)
	}
}

func TestDiscoverRejectsCertificateBelowMinimumValidity(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	target := net.ParseIP("203.0.113.10")
	writeCertificatePair(t, root, "short", target, now.Add(20*time.Minute))

	_, err := Discover(root, target, now, 30*time.Minute)
	if !errors.Is(err, ErrNoMatchingCertificate) {
		t.Fatalf("error = %v, want ErrNoMatchingCertificate", err)
	}
}

func TestDiscoverDoesNotFollowCertificateSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	now := time.Now().UTC()
	target := net.ParseIP("203.0.113.10")
	pair := writeCertificatePair(t, outside, "outside", target, now.Add(time.Hour))
	if err := os.Symlink(pair.CertificatePath, filepath.Join(root, "linked.crt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(pair.PrivateKeyPath, filepath.Join(root, "linked.key")); err != nil {
		t.Fatal(err)
	}

	_, err := Discover(root, target, now, 30*time.Minute)
	if !errors.Is(err, ErrNoMatchingCertificate) {
		t.Fatalf("error = %v, want ErrNoMatchingCertificate", err)
	}
}
