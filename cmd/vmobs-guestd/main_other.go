// ABOUTME: Non-linux stub for vmobs-guestd; the binary only runs inside a Linux guest.
// ABOUTME: Exits 2 with an explanatory message so cross-compile builds succeed on darwin/etc.
//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "vmobs-guestd runs inside a Linux guest")
	os.Exit(2)
}
