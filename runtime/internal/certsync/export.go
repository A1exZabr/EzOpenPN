package certsync

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

const maximumHealthSize = 4096

var ErrUnhealthyCertificate = errors.New("exported certificate is not healthy")

type Health struct {
	IP          string    `json:"ip"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"`
}

func Export(pair Pair, output string) error {
	leaf, err := validatePair(pair)
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	health := Health{
		IP:          pair.IP.To4().String(),
		NotAfter:    leaf.NotAfter.UTC(),
		Fingerprint: hex.EncodeToString(fingerprint[:]),
	}
	healthJSON, err := json.Marshal(health)
	if err != nil {
		return ErrInvalidCertificate
	}
	healthJSON = append(healthJSON, '\n')

	if err := ensureOutputDirectory(output); err != nil {
		return err
	}
	expected := []exportFile{
		{name: "fullchain.pem", content: pair.CertificatePEM},
		{name: "privkey.pem", content: pair.PrivateKeyPEM},
		{name: "health.json", content: healthJSON},
	}
	if exportMatches(output, expected) {
		return nil
	}

	staged := make([]stagedFile, 0, len(expected))
	defer func() {
		for _, item := range staged {
			_ = os.Remove(item.temporaryPath)
		}
	}()
	for _, item := range expected {
		stagedItem, stageErr := stageFile(output, item)
		if stageErr != nil {
			return stageErr
		}
		staged = append(staged, stagedItem)
	}
	for _, item := range staged[:2] {
		if err := os.Rename(item.temporaryPath, item.destinationPath); err != nil {
			return ErrInvalidCertificate
		}
	}
	if err := syncDirectory(output); err != nil {
		return err
	}
	if err := os.Rename(staged[2].temporaryPath, staged[2].destinationPath); err != nil {
		return ErrInvalidCertificate
	}
	return syncDirectory(output)
}

func CheckHealth(
	healthPath string,
	now time.Time,
	minimumValidity time.Duration,
) error {
	if minimumValidity <= 0 {
		return ErrUnhealthyCertificate
	}
	healthBytes, err := readRegularFile(healthPath, maximumHealthSize)
	if err != nil {
		return ErrUnhealthyCertificate
	}
	decoder := json.NewDecoder(bytes.NewReader(healthBytes))
	decoder.DisallowUnknownFields()
	var health Health
	if err := decoder.Decode(&health); err != nil {
		return ErrUnhealthyCertificate
	}
	if err := requireJSONEnd(decoder); err != nil {
		return ErrUnhealthyCertificate
	}
	ip := net.ParseIP(health.IP)
	if ip == nil || ip.To4() == nil || health.Fingerprint == "" {
		return ErrUnhealthyCertificate
	}
	directory := filepath.Dir(healthPath)
	certificatePEM, err := readRegularFile(
		filepath.Join(directory, "fullchain.pem"), maximumPEMSize,
	)
	if err != nil {
		return ErrUnhealthyCertificate
	}
	privateKeyPEM, err := readRegularFile(
		filepath.Join(directory, "privkey.pem"), maximumPEMSize,
	)
	if err != nil {
		return ErrUnhealthyCertificate
	}
	if _, err = tls.X509KeyPair(certificatePEM, privateKeyPEM); err != nil {
		return ErrUnhealthyCertificate
	}
	leaf, err := pemCertificate(certificatePEM)
	if err != nil || !certificateMatches(leaf, ip.To4(), now, minimumValidity) {
		return ErrUnhealthyCertificate
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	if health.Fingerprint != hex.EncodeToString(fingerprint[:]) ||
		!health.NotAfter.Equal(leaf.NotAfter.UTC()) {
		return ErrUnhealthyCertificate
	}
	return nil
}

func validatePair(pair Pair) (*x509.Certificate, error) {
	if pair.IP.To4() == nil || len(pair.CertificatePEM) == 0 || len(pair.PrivateKeyPEM) == 0 {
		return nil, ErrInvalidCertificate
	}
	if _, err := tls.X509KeyPair(pair.CertificatePEM, pair.PrivateKeyPEM); err != nil {
		return nil, ErrInvalidCertificate
	}
	leaf, err := pemCertificate(pair.CertificatePEM)
	if err != nil {
		return nil, ErrInvalidCertificate
	}
	matched := false
	for _, candidate := range leaf.IPAddresses {
		if candidate.To4() != nil && candidate.Equal(pair.IP.To4()) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, ErrInvalidCertificate
	}
	return leaf, nil
}

type exportFile struct {
	name    string
	content []byte
}

type stagedFile struct {
	temporaryPath   string
	destinationPath string
}

func ensureOutputDirectory(path string) error {
	if path == "" {
		return ErrInvalidCertificate
	}
	if err := os.MkdirAll(path, 0o750); err != nil {
		return ErrInvalidCertificate
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidCertificate
	}
	return nil
}

func exportMatches(output string, expected []exportFile) bool {
	for _, item := range expected {
		path := filepath.Join(output, item.name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 {
			return false
		}
		current, err := readRegularFile(path, maximumPEMSize)
		if err != nil || !bytes.Equal(current, item.content) {
			return false
		}
	}
	return true
}

func stageFile(output string, item exportFile) (stagedFile, error) {
	file, err := os.CreateTemp(output, "."+item.name+".tmp-")
	if err != nil {
		return stagedFile{}, ErrInvalidCertificate
	}
	temporaryPath := file.Name()
	failed := true
	defer func() {
		_ = file.Close()
		if failed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = file.Chmod(0o640); err != nil {
		return stagedFile{}, ErrInvalidCertificate
	}
	if _, err = file.Write(item.content); err != nil {
		return stagedFile{}, ErrInvalidCertificate
	}
	if err = file.Sync(); err != nil {
		return stagedFile{}, ErrInvalidCertificate
	}
	if err = file.Close(); err != nil {
		return stagedFile{}, ErrInvalidCertificate
	}
	failed = false
	return stagedFile{
		temporaryPath:   temporaryPath,
		destinationPath: filepath.Join(output, item.name),
	}, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return ErrInvalidCertificate
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return ErrInvalidCertificate
	}
	return nil
}

func requireJSONEnd(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return ErrUnhealthyCertificate
}
