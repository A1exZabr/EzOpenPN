package certsync

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maximumPEMSize = 4 << 20

var (
	ErrNoMatchingCertificate = errors.New("no matching certificate is ready")
	ErrCertificateSource     = errors.New("certificate source is unavailable")
	ErrInvalidCertificate    = errors.New("certificate pair is invalid")
)

type Pair struct {
	CertificatePath string
	PrivateKeyPath  string
	CertificatePEM  []byte
	PrivateKeyPEM   []byte
	IP              net.IP
	NotAfter        time.Time
	Fingerprint     string
}

func Discover(
	source string,
	wantedIP net.IP,
	now time.Time,
	minimumValidity time.Duration,
) (Pair, error) {
	wantedIPv4 := wantedIP.To4()
	if source == "" || wantedIPv4 == nil || minimumValidity <= 0 {
		return Pair{}, ErrCertificateSource
	}
	rootInfo, err := os.Lstat(source)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return Pair{}, ErrCertificateSource
	}

	best := Pair{}
	walkErr := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkError error) error {
		if walkError != nil {
			return ErrCertificateSource
		}
		if path == source || entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		extension := strings.ToLower(filepath.Ext(path))
		if extension != ".crt" && extension != ".pem" {
			return nil
		}
		certificatePEM, readErr := readRegularFile(path, maximumPEMSize)
		if readErr != nil {
			return nil
		}
		leaf, parseErr := pemCertificate(certificatePEM)
		if parseErr != nil || !certificateMatches(leaf, wantedIPv4, now, minimumValidity) {
			return nil
		}
		keyPath, privateKeyPEM, keyErr := findPrivateKey(path, certificatePEM)
		if keyErr != nil {
			return nil
		}
		if _, pairErr := tls.X509KeyPair(certificatePEM, privateKeyPEM); pairErr != nil {
			return nil
		}
		if !best.NotAfter.IsZero() && !leaf.NotAfter.After(best.NotAfter) {
			return nil
		}
		fingerprint := sha256.Sum256(leaf.Raw)
		best = Pair{
			CertificatePath: path,
			PrivateKeyPath:  keyPath,
			CertificatePEM:  bytes.Clone(certificatePEM),
			PrivateKeyPEM:   bytes.Clone(privateKeyPEM),
			IP:              append(net.IP(nil), wantedIPv4...),
			NotAfter:        leaf.NotAfter.UTC(),
			Fingerprint:     hex.EncodeToString(fingerprint[:]),
		}
		return nil
	})
	if walkErr != nil {
		return Pair{}, ErrCertificateSource
	}
	if best.NotAfter.IsZero() {
		return Pair{}, ErrNoMatchingCertificate
	}
	return best, nil
}

func certificateMatches(
	certificate *x509.Certificate,
	wantedIPv4 net.IP,
	now time.Time,
	minimumValidity time.Duration,
) bool {
	if certificate == nil || now.Before(certificate.NotBefore) {
		return false
	}
	if certificate.NotAfter.Before(now.Add(minimumValidity)) {
		return false
	}
	for _, candidate := range certificate.IPAddresses {
		if candidate.To4() != nil && candidate.Equal(wantedIPv4) {
			return true
		}
	}
	return false
}

func findPrivateKey(certificatePath string, certificatePEM []byte) (string, []byte, error) {
	extension := filepath.Ext(certificatePath)
	stem := strings.TrimSuffix(certificatePath, extension)
	candidates := []string{stem + ".key", stem + "-key.pem"}
	if strings.ToLower(extension) != ".pem" {
		candidates = append(candidates, stem+".pem")
	}
	candidates = append(candidates, certificatePath)
	for _, candidate := range candidates {
		privateKeyPEM, err := readRegularFile(candidate, maximumPEMSize)
		if err != nil {
			continue
		}
		if _, err = tls.X509KeyPair(certificatePEM, privateKeyPEM); err == nil {
			return candidate, privateKeyPEM, nil
		}
	}
	return "", nil, ErrInvalidCertificate
}

func readRegularFile(path string, maximumBytes int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidCertificate
	}
	if before.Size() <= 0 || before.Size() > maximumBytes {
		return nil, ErrInvalidCertificate
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalidCertificate
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() {
		return nil, ErrInvalidCertificate
	}
	content, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil || int64(len(content)) > maximumBytes {
		return nil, ErrInvalidCertificate
	}
	return content, nil
}

func pemCertificate(content []byte) (*x509.Certificate, error) {
	rest := content
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrInvalidCertificate
		}
		return certificate, nil
	}
	return nil, ErrInvalidCertificate
}
