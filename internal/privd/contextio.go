// ABOUTME: Staging streams observe the execution budget between file reads.
// ABOUTME: Open descriptors remain pinned while cancellation stops hashing and copying.
package privd

import (
	"context"
	"io"
)

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
