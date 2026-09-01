// ABOUTME: Identity carried by authenticated requests, and the context
// ABOUTME: plumbing trusted ingress uses to hand it to handlers.
package auth

import "context"

// Identity is who a request acts as. Owner is the resource-owner string
// persisted on created rows. Method records how the identity was proven:
// "session" (cookie), "token" (bearer), or "none" (auth disabled by config).
type Identity struct {
	Owner     string
	Method    string
	SessionID string // set when Method == "session"
	TokenID   string // set when Method == "token"
}

type ctxKey struct{}

// WithIdentity is called only by the API middleware (trusted ingress).
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}
