// ABOUTME: Starts one runner process with its acquired observer descriptors attached.
// ABOUTME: The adapter drops its own copies as soon as the child holds them.
//go:build linux

package jailer

import (
	"context"
	"os"
	"os/exec"
	"syscall"
)

// buildRunnerCmd builds an exec.Cmd for the runner with Setsid and the given log file.
// logFile is attached to both stdout and stderr; callers must call logFile.Close() after cmd.Start().
func buildRunnerCmd(argv []string, logFile *os.File) *exec.Cmd {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd
}

// startRunner acquires this VM's observers, builds the argv, and starts the
// process with the descriptors at runner.FirstObserverFD and up. The adapter's
// copies are closed once the child holds its own; callers close logFile after
// this returns.
func (a *Adapter) startRunner(ctx context.Context, m Manifest, instanceID string, logFile *os.File) (*exec.Cmd, error) {
	bundle, reason := a.acquireRunnerObservers(ctx, m)
	defer bundle.Close()
	argv, err := a.runnerArguments(m, instanceID, bundle, reason)
	if err != nil {
		return nil, err
	}
	cmd := buildRunnerCmd(argv, logFile)
	if bundle != nil {
		cmd.ExtraFiles = bundle.Files
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}
