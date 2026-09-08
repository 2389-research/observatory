// ABOUTME: CLI handlers for auth subcommands: whoami, token create/list/revoke.
// ABOUTME: The token secret appears in CLI output exactly once (create stdout).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"

	"github.com/2389-research/observatory/internal/auth"
)

// dispatchAuthCmd handles `vmobs auth <subcmd> ...`.
func (c *client) dispatchAuthCmd(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: vmobs auth whoami|token|tokens ...")
		return exitUsage
	}
	switch args[0] {
	case "whoami":
		return c.authWhoami(args[1:])
	case "token":
		return c.dispatchAuthTokenCmd(args[1:])
	case "tokens":
		return c.authTokenList(args[1:])
	default:
		fmt.Fprintf(c.stderr, "vmobs: unknown auth subcommand %q\n", args[0])
		return exitUsage
	}
}

// dispatchAuthTokenCmd handles `vmobs auth token <subcmd> ...`.
func (c *client) dispatchAuthTokenCmd(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: vmobs auth token create|revoke ...")
		return exitUsage
	}
	switch args[0] {
	case "create":
		return c.authTokenCreate(args[1:])
	case "revoke":
		return c.authTokenRevoke(args[1:])
	default:
		fmt.Fprintf(c.stderr, "vmobs: unknown auth token subcommand %q\n", args[0])
		return exitUsage
	}
}

// authWhoami handles `vmobs auth whoami` — GET /auth/session.
func (c *client) authWhoami(args []string) int {
	fs := flag.NewFlagSet("vmobs auth whoami", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	status, body, err := c.do(http.MethodGet, "/api/v1/auth/session", nil)
	if err != nil {
		return c.transport(err)
	}
	if status != http.StatusOK {
		return c.fail(status, body)
	}
	if c.json {
		fmt.Fprintf(c.stdout, "%s\n", body)
		return exitOK
	}

	var sess struct {
		Owner  string `json:"owner"`
		Method string `json:"method"`
	}
	if err := json.Unmarshal(body, &sess); err != nil {
		fmt.Fprintf(c.stderr, "vmobs: cannot decode session: %v\n", err)
		return exitTransport
	}
	fmt.Fprintf(c.stdout, "owner:  %s\nmethod: %s\n", sess.Owner, sess.Method)
	return exitOK
}

// authTokenCreate handles `vmobs auth token create --name NAME [--ttl-minutes N]`.
// The secret is printed to stdout exactly once; a warning goes to stderr.
func (c *client) authTokenCreate(args []string) int {
	fs := flag.NewFlagSet("vmobs auth token create", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	name := fs.String("name", "", "token name (required)")
	ttl := fs.Int64("ttl-minutes", 0, fmt.Sprintf("token TTL in minutes (0 = no expiry; max %d)", auth.MaxTokenTTLMinutes))
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *name == "" {
		fmt.Fprintln(c.stderr, "vmobs: --name is required")
		return exitUsage
	}

	if _, err := auth.TokenTTL(*ttl); err != nil {
		fmt.Fprintf(c.stderr, "vmobs: --ttl-minutes: %v\n", err)
		return exitUsage
	}
	reqBody := map[string]any{"name": *name}
	if *ttl > 0 {
		reqBody["ttl_minutes"] = *ttl
	}
	encoded, _ := json.Marshal(reqBody)

	status, body, err := c.do(http.MethodPost, "/api/v1/auth/tokens", bytes.NewReader(encoded))
	if err != nil {
		return c.transport(err)
	}
	if status != http.StatusCreated {
		return c.fail(status, body)
	}
	if c.json {
		fmt.Fprintf(c.stdout, "%s\n", body)
		return exitOK
	}

	var resp struct {
		Token struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Owner     string `json:"owner"`
			CreatedAt string `json:"created_at"`
			ExpiresAt string `json:"expires_at"`
		} `json:"token"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintf(c.stderr, "vmobs: cannot decode token create response: %v\n", err)
		return exitTransport
	}

	// Secret appears exactly once, on stdout.
	fmt.Fprintf(c.stdout, "id:      %s\nname:    %s\nowner:   %s\nsecret:  %s\n",
		resp.Token.ID, resp.Token.Name, resp.Token.Owner, resp.Secret)
	if resp.Token.ExpiresAt != "" {
		fmt.Fprintf(c.stdout, "expires: %s\n", resp.Token.ExpiresAt)
	}

	// Warning on stderr — never includes the secret.
	fmt.Fprintln(c.stderr, "warning: the token secret will not be shown again; store it now")

	return exitOK
}

// authTokenList handles `vmobs auth tokens` — GET /auth/tokens.
func (c *client) authTokenList(args []string) int {
	fs := flag.NewFlagSet("vmobs auth tokens", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	status, body, err := c.do(http.MethodGet, "/api/v1/auth/tokens", nil)
	if err != nil {
		return c.transport(err)
	}
	if status != http.StatusOK {
		return c.fail(status, body)
	}
	if c.json {
		fmt.Fprintf(c.stdout, "%s\n", body)
		return exitOK
	}

	var resp struct {
		Tokens []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Owner     string `json:"owner"`
			CreatedAt string `json:"created_at"`
			ExpiresAt string `json:"expires_at"`
			RevokedAt string `json:"revoked_at"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintf(c.stderr, "vmobs: cannot decode token list: %v\n", err)
		return exitTransport
	}
	if len(resp.Tokens) == 0 {
		fmt.Fprintln(c.stdout, "(no tokens)")
		return exitOK
	}
	fmt.Fprintf(c.stdout, "%-12s  %-20s  %-16s  %-20s  %s\n", "ID", "NAME", "OWNER", "CREATED", "STATUS")
	for _, tok := range resp.Tokens {
		status := "active"
		if tok.RevokedAt != "" {
			status = "revoked"
		} else if tok.ExpiresAt != "" {
			status = "expires " + tok.ExpiresAt
		}
		fmt.Fprintf(c.stdout, "%-12s  %-20s  %-16s  %-20s  %s\n",
			tok.ID, tok.Name, tok.Owner, tok.CreatedAt, status)
	}
	return exitOK
}

// authTokenRevoke handles `vmobs auth token revoke ID` — DELETE /auth/tokens/{id}.
func (c *client) authTokenRevoke(args []string) int {
	fs := flag.NewFlagSet("vmobs auth token revoke", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(c.stderr, "usage: vmobs auth token revoke ID")
		return exitUsage
	}
	tokenID := rest[0]

	status, body, err := c.do(http.MethodDelete, "/api/v1/auth/tokens/"+url.PathEscape(tokenID), nil)
	if err != nil {
		return c.transport(err)
	}
	if status != http.StatusOK {
		return c.fail(status, body)
	}
	if c.json {
		fmt.Fprintf(c.stdout, "%s\n", body)
		return exitOK
	}
	fmt.Fprintf(c.stdout, "revoked %s\n", tokenID)
	return exitOK
}
