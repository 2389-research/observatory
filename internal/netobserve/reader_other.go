// ABOUTME: Refuses Linux netlink reading on platforms without Linux AF_NETLINK semantics.
// ABOUTME: Leaves every supplied file caller-owned when reader creation cannot succeed.
//go:build !linux

package netobserve

import (
	"context"
	"fmt"
)

type Reader struct{}

func NewReader(_ context.Context, config ReaderConfig) (*Reader, error) {
	if err := validateReaderConfig(&config); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("live netlink reader requires Linux")
}

func (r *Reader) Observations() <-chan Observation { return nil }
func (r *Reader) Status() ReaderStatus             { return ReaderStatus{} }
func (r *Reader) Close() error                     { return nil }
