package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ezopenpn/ezopenpn/runtime/internal/supervisor"
)

const controlSocket = "/run/ezopenpn-xray/control.sock"

func run() int {
	listener, cleanup, err := supervisor.ListenUnix(controlSocket)
	if err != nil {
		log.Print("supervisor socket setup failed")
		return 1
	}
	defer func() {
		_ = listener.Close()
		_ = cleanup()
	}()

	manager := supervisor.NewProcessManager(supervisor.NewXrayStarter())
	controller := supervisor.NewRestarter(manager)
	httpServer := &http.Server{
		Handler:           supervisor.NewServer(controller),
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       10 * time.Second,
		MaxHeaderBytes:    4096,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	processResult := make(chan error, 1)
	serverResult := make(chan error, 1)
	go func() { processResult <- manager.Run(ctx) }()
	go func() { serverResult <- httpServer.Serve(listener) }()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	exitCode := 0
	processFinished := false
	select {
	case received := <-signals:
		shutdownContext, stopShutdown := context.WithTimeout(context.Background(), 5*time.Second)
		if manager.Shutdown(shutdownContext, received) != nil {
			exitCode = 1
		}
		stopShutdown()
	case processErr := <-processResult:
		processFinished = true
		if processErr != nil {
			log.Print("supervised process stopped")
			exitCode = 1
		}
	case serverErr := <-serverResult:
		if serverErr != nil && !errors.Is(serverErr, http.ErrServerClosed) {
			log.Print("supervisor control server stopped")
			exitCode = 1
		}
	}

	cancel()
	if !processFinished {
		select {
		case processErr := <-processResult:
			if processErr != nil {
				exitCode = 1
			}
		case <-time.After(4 * time.Second):
			exitCode = 1
		}
	}
	shutdownContext, stopShutdown := context.WithTimeout(context.Background(), 2*time.Second)
	_ = httpServer.Shutdown(shutdownContext)
	stopShutdown()
	return exitCode
}

func main() {
	os.Exit(run())
}
