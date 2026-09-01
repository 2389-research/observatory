// ABOUTME: vmobs-runner binary: per-VM supervisor launched by the jailer adapter.
// ABOUTME: Parses argv, reads the token from file (§15.3), and calls runner.Run.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/2389-research/observatory-v2/internal/runner"
)

func main() {
	cfg, err := runner.ParseFlags(os.Args[0], os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", os.Args[0], err)
		os.Exit(3) // usage error — matches repo exit-code convention
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if err := runner.Run(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", os.Args[0], err)
		os.Exit(1)
	}
}
