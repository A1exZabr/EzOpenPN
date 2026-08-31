package supervisor

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var (
	ErrUnsafeSocket = errors.New("existing supervisor socket is unsafe")
	ErrSocketOwner  = errors.New("existing supervisor socket has another owner")
)

type server struct {
	controller Controller
}

func NewServer(controller Controller) http.Handler {
	return &server{controller: controller}
}

func writeStatus(writer http.ResponseWriter, status int, value string) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, value+"\n")
}

func emptyBody(request *http.Request) bool {
	defer request.Body.Close()
	value := make([]byte, 1)
	read, err := io.ReadFull(io.LimitReader(request.Body, 1), value)
	return read == 0 && (err == nil || errors.Is(err, io.EOF))
}

func (service *server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" {
		writeStatus(writer, http.StatusBadRequest, "bad request")
		return
	}
	switch request.URL.Path {
	case "/health":
		if request.Method != http.MethodGet {
			writeStatus(writer, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !emptyBody(request) {
			writeStatus(writer, http.StatusBadRequest, "bad request")
			return
		}
		if !service.controller.Healthy() {
			writeStatus(writer, http.StatusServiceUnavailable, "unavailable")
			return
		}
		writeStatus(writer, http.StatusOK, "ok")
	case "/restart":
		if request.Method != http.MethodPost {
			writeStatus(writer, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !emptyBody(request) {
			writeStatus(writer, http.StatusBadRequest, "bad request")
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), 4*time.Second)
		defer cancel()
		if err := service.controller.Restart(ctx); err != nil {
			writeStatus(writer, http.StatusServiceUnavailable, "unavailable")
			return
		}
		writeStatus(writer, http.StatusAccepted, "accepted")
	default:
		writeStatus(writer, http.StatusNotFound, "not found")
	}
}

func socketOwnedByCurrentUser(info os.FileInfo) bool {
	status, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(status.Uid) == os.Geteuid()
}

func ListenUnix(socketPath string) (net.Listener, func() error, error) {
	if !filepath.IsAbs(socketPath) {
		return nil, nil, ErrUnsafeSocket
	}
	directory := filepath.Dir(socketPath)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return nil, nil, ErrUnsafeSocket
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 {
		return nil, nil, ErrUnsafeSocket
	}
	if !socketOwnedByCurrentUser(directoryInfo) {
		return nil, nil, ErrSocketOwner
	}
	if err := os.Chmod(directory, 0o750); err != nil {
		return nil, nil, ErrUnsafeSocket
	}
	info, err := os.Lstat(socketPath)
	if err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, nil, ErrUnsafeSocket
		}
		if !socketOwnedByCurrentUser(info) {
			return nil, nil, ErrSocketOwner
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, nil, ErrUnsafeSocket
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, ErrUnsafeSocket
	}

	previousMask := syscall.Umask(0o007)
	listener, err := net.Listen("unix", socketPath)
	syscall.Umask(previousMask)
	if err != nil {
		return nil, nil, ErrUnsafeSocket
	}
	if err := os.Chmod(socketPath, 0o770); err != nil {
		_ = listener.Close()
		return nil, nil, ErrUnsafeSocket
	}
	created, err := os.Lstat(socketPath)
	if err != nil {
		_ = listener.Close()
		return nil, nil, ErrUnsafeSocket
	}
	cleanup := func() error {
		current, currentErr := os.Lstat(socketPath)
		if errors.Is(currentErr, os.ErrNotExist) {
			return nil
		}
		if currentErr != nil || !os.SameFile(created, current) {
			return ErrUnsafeSocket
		}
		return os.Remove(socketPath)
	}
	return listener, cleanup, nil
}
