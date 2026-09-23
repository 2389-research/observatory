// ABOUTME: Stub for platforms with no real full-filesystem helper: always skips.
// ABOUTME: Real filesystems are built in smallfs_darwin_test.go and smallfs_linux_test.go.
//go:build !darwin && !linux

package api_test

import "testing"

// smallFilesystem has no implementation on this platform.
func smallFilesystem(t *testing.T) string {
	t.Helper()
	t.Skip("no small-filesystem helper for this platform")
	return ""
}
