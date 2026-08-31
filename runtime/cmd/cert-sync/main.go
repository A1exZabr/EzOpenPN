package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ezopenpn/ezopenpn/runtime/internal/certsync"
)

func run() int {
	flags := flag.NewFlagSet("cert-sync", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	source := flags.String("source", "", "certificate source directory")
	output := flags.String("output", "", "certificate export directory")
	ipValue := flags.String("ip", "", "public IPv4 address")
	interval := flags.Duration("interval", time.Minute, "discovery interval")
	healthPath := flags.String("healthcheck", "", "health metadata path")
	minimumValidity := flags.Duration(
		"min-validity", 30*time.Minute, "required remaining validity",
	)
	if err := flags.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if *minimumValidity <= 0 || flags.NArg() != 0 {
		return 2
	}
	if *healthPath != "" {
		if *source != "" || *output != "" || *ipValue != "" {
			return 2
		}
		if err := certsync.CheckHealth(
			*healthPath, time.Now().UTC(), *minimumValidity,
		); err != nil {
			return 1
		}
		return 0
	}
	publicIP := net.ParseIP(*ipValue)
	if *source == "" || *output == "" || publicIP == nil || publicIP.To4() == nil || *interval <= 0 {
		return 2
	}

	synchronize := func() {
		pair, err := certsync.Discover(
			*source, publicIP.To4(), time.Now().UTC(), *minimumValidity,
		)
		if err != nil {
			log.Print("certificate synchronization is waiting")
			return
		}
		if err = certsync.Export(pair, *output); err != nil {
			log.Print("certificate synchronization failed")
			return
		}
		log.Print("certificate synchronization complete")
	}
	synchronize()
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	for {
		select {
		case <-ticker.C:
			synchronize()
		case <-signals:
			return 0
		}
	}
}

func main() {
	os.Exit(run())
}
