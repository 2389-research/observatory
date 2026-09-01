// ABOUTME: Non-linux stub for vmobs-privd; the daemon only runs on Linux.
// ABOUTME: Exits 1 with an explanatory message so cross-compile builds succeed on darwin/etc.
//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "vmobs-privd requires linux")
	os.Exit(1)
}
