package supervisor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeController struct {
	restarts int
	healthy  bool
}

func TestUnixListenerRejectsAnExistingRegularFile(t *testing.T) {
	directory := t.TempDir()
	socketPath := filepath.Join(directory, "control.sock")
	if err := os.WriteFile(socketPath, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	listener, cleanup, err := ListenUnix(socketPath)

	if listener != nil || cleanup != nil {
		t.Fatal("unsafe path returned a listener")
	}
	if !errors.Is(err, ErrUnsafeSocket) {
		t.Fatalf("error = %v", err)
	}
	contents, readErr := os.ReadFile(socketPath)
	if readErr != nil || string(contents) != "keep" {
		t.Fatal("existing file was changed")
	}
}

func TestUnixListenerUsesRestrictedPermissionsAndSafeCleanup(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "ezopenpn-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socketPath := filepath.Join(directory, "control.sock")

	listener, cleanup, err := ListenUnix(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o770 {
		t.Fatalf("socket mode = %o", info.Mode().Perm())
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remains after cleanup: %v", err)
	}
}

func (controller *fakeController) Restart(context.Context) error {
	controller.restarts++
	return nil
}

func (controller *fakeController) Healthy() bool {
	return controller.healthy
}

func TestServerRejectsRequestBody(t *testing.T) {
	controller := &fakeController{healthy: true}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/restart", strings.NewReader("unexpected"))

	NewServer(controller).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", recorder.Code)
	}
	if controller.restarts != 0 {
		t.Fatalf("restarts = %d", controller.restarts)
	}
}

func TestServerAcceptsOnlyFixedOperations(t *testing.T) {
	controller := &fakeController{healthy: true}
	server := NewServer(controller)

	health := httptest.NewRecorder()
	server.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/health", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d", health.Code)
	}

	restart := httptest.NewRecorder()
	server.ServeHTTP(restart, httptest.NewRequest(http.MethodPost, "/restart", nil))
	if restart.Code != http.StatusAccepted {
		t.Fatalf("restart status = %d", restart.Code)
	}
	if controller.restarts != 1 {
		t.Fatalf("restarts = %d", controller.restarts)
	}

	unknown := httptest.NewRecorder()
	server.ServeHTTP(unknown, httptest.NewRequest(http.MethodPost, "/other", nil))
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown status = %d", unknown.Code)
	}
}
