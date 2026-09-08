// ABOUTME: A lost start reply must resolve before any local ownership can be released.
// ABOUTME: Tests durable manifest adoption and refusal of pending mutation outcomes.
package jailer

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/2389-research/observatory/internal/privd"
	"testing"
)

type outcomeClient struct {
	privdClient
	outcome privd.OperationOutcome
}

func (c outcomeClient) QueryOperation(context.Context, string) (privd.OperationOutcome, error) {
	return c.outcome, nil
}

func TestStartOutcomeRetainsPendingManifest(t *testing.T) {
	dir := t.TempDir()
	m := Manifest{VMID: "vm-outcome", StartOpID: "pending"}
	if err := writeManifest(dir, m); err != nil {
		t.Fatal(err)
	}
	a := &Adapter{cfg: Config{StateDir: dir}, pc: outcomeClient{outcome: privd.OperationOutcome{State: "pending"}}}
	var unknown *privd.UnknownOutcomeError
	if err := a.resolveStartOutcome(context.Background(), &m); !errors.As(err, &unknown) {
		t.Fatalf("pending start cleared: %v", err)
	}
	if _, err := readManifest(dir, m.VMID); err != nil {
		t.Fatal(err)
	}
}

func TestStartOutcomeAdoptsLostReplyIdentity(t *testing.T) {
	dir := t.TempDir()
	m := Manifest{VMID: "vm-outcome", StartOpID: "finished"}
	raw, _ := json.Marshal(privd.StartVMResp{PID: 1234, StartTime: "99"})
	a := &Adapter{cfg: Config{StateDir: dir}, pc: outcomeClient{outcome: privd.OperationOutcome{State: "succeeded", Response: &privd.Response{OK: true, Payload: raw}}}}
	if err := a.resolveStartOutcome(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	got, err := readManifest(dir, m.VMID)
	if err != nil || got.VMMPID != 1234 || got.VMMStart != "99" {
		t.Fatalf("lost reply not durably adopted: %+v %v", got, err)
	}
}
