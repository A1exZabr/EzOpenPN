package certsync

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExportRejectsMismatchedPrivateKey(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	pair := writeCertificatePair(
		t, root, "selected", net.ParseIP("203.0.113.10"), now.Add(time.Hour),
	)
	other := writeCertificatePair(
		t, root, "other", net.ParseIP("203.0.113.10"), now.Add(time.Hour),
	)
	pair.PrivateKeyPEM = other.PrivateKeyPEM

	if err := Export(pair, t.TempDir()); err == nil {
		t.Fatal("expected key mismatch")
	}
}

func TestExportWritesPrivateFilesAndStableHealth(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(t.TempDir(), "exported")
	now := time.Now().UTC().Truncate(time.Second)
	pair := writeCertificatePair(
		t, root, "selected", net.ParseIP("203.0.113.10"), now.Add(2*time.Hour),
	)

	if err := Export(pair, output); err != nil {
		t.Fatal(err)
	}
	paths := []string{
		filepath.Join(output, "fullchain.pem"),
		filepath.Join(output, "privkey.pem"),
		filepath.Join(output, "health.json"),
	}
	firstModTimes := make([]time.Time, len(paths))
	for index, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Fatalf("mode for %s = %o", filepath.Base(path), info.Mode().Perm())
		}
		firstModTimes[index] = info.ModTime()
	}

	healthBytes, err := os.ReadFile(paths[2])
	if err != nil {
		t.Fatal(err)
	}
	var health Health
	if err := json.Unmarshal(healthBytes, &health); err != nil {
		t.Fatal(err)
	}
	block, _ := pemCertificate(pair.CertificatePEM)
	fingerprint := sha256.Sum256(block.Raw)
	if health.IP != "203.0.113.10" ||
		health.Fingerprint != hex.EncodeToString(fingerprint[:]) ||
		!health.NotAfter.Equal(pair.NotAfter) {
		t.Fatalf("unexpected health metadata: %#v", health)
	}

	time.Sleep(20 * time.Millisecond)
	if err := Export(pair, output); err != nil {
		t.Fatal(err)
	}
	for index, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.ModTime().Equal(firstModTimes[index]) {
			t.Fatalf("unchanged export rewrote %s", filepath.Base(path))
		}
	}
}

func TestCheckHealthRejectsExpiringCertificate(t *testing.T) {
	root := t.TempDir()
	output := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	pair := writeCertificatePair(
		t, root, "selected", net.ParseIP("203.0.113.10"), now.Add(20*time.Minute),
	)
	if err := Export(pair, output); err != nil {
		t.Fatal(err)
	}

	err := CheckHealth(
		filepath.Join(output, "health.json"), now, 30*time.Minute,
	)
	if err == nil {
		t.Fatal("expected expiring certificate to be unhealthy")
	}
}

func TestCheckHealthAcceptsMatchingFreshExport(t *testing.T) {
	root := t.TempDir()
	output := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	pair := writeCertificatePair(
		t, root, "selected", net.ParseIP("203.0.113.10"), now.Add(2*time.Hour),
	)
	if err := Export(pair, output); err != nil {
		t.Fatal(err)
	}

	if err := CheckHealth(
		filepath.Join(output, "health.json"), now, 30*time.Minute,
	); err != nil {
		t.Fatalf("fresh export is unhealthy: %v", err)
	}
}
