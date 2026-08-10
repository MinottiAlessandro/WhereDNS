package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/MinottiAlessandro/WhereDNS/internal/cli"
	"github.com/MinottiAlessandro/WhereDNS/internal/dnsengine"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cache, err := dnsengine.NewCache(dnsengine.CachePathFromEnvironment())
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning: persistent cache unavailable:", err)
		cache, _ = dnsengine.NewCache("")
	}
	app := cli.New(ctx, dnsengine.New(cache), os.Stdout, os.Stderr)
	if err := app.Run(os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
