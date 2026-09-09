// ABOUTME: Defines immutable network observer bindings and descriptor ownership.
// ABOUTME: Validates exact framed metadata independently of platform socket checks.
package privd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/2389-research/observatory/internal/network"
	"github.com/google/uuid"
)

const observerVerb = "acquire_network_observers"

type AcquireNetworkObserversReq struct {
	VMID        string `json:"vm_id"`
	GuestBootID string `json:"guest_boot_id"`
}
type NetworkObserverBinding struct {
	VMID              string `json:"vm_id"`
	GuestBootID       string `json:"guest_boot_id"`
	HostBootID        string `json:"host_boot_id"`
	GatewayGeneration string `json:"gateway_generation"`
	NamespaceDevice   string `json:"namespace_device"`
	NamespaceInode    string `json:"namespace_inode"`
	PolicyID          string `json:"policy_id"`
	PolicyDigest      string `json:"policy_digest"`
	Profile           string `json:"profile"`
	AcquisitionID     string `json:"acquisition_id"`
}
type ObserverSocket struct {
	Kind             string `json:"kind"`
	Boundary         string `json:"boundary"`
	PortID           uint32 `json:"port_id"`
	Group            uint16 `json:"group"`
	SnapshotSequence uint32 `json:"snapshot_sequence"`
}

// NetworkObserverBundle owns each received file. Close before reacquiring NFLOG:
// Linux permits only one reader for a group in each network namespace.
// The authenticated UID boundary does not isolate mutually trusted same-UID runners.
type NetworkObserverBundle struct {
	Binding NetworkObserverBinding `json:"binding"`
	Sockets []ObserverSocket       `json:"sockets"`
	Files   []*os.File             `json:"-"`
}

func (b *NetworkObserverBundle) Close() error {
	if b == nil {
		return nil
	}
	var err error
	for _, f := range b.Files {
		if f != nil {
			err = errors.Join(err, f.Close())
		}
	}
	b.Files = nil
	return err
}

// EncodeObserverBinding renders a bundle's metadata for a process that will
// receive the descriptors by inheritance. Files never appear: they travel as
// descriptors, and the metadata alone is what the receiver re-checks them against.
func EncodeObserverBinding(b *NetworkObserverBundle) ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("missing observer bundle")
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxMsgBytes {
		return nil, fmt.Errorf("observer metadata exceeds %d bytes", MaxMsgBytes)
	}
	return raw, nil
}

// DecodeObserverBinding decodes inherited observer metadata under the same
// strict framing rules the acquisition reply uses, then checks the binding it
// carries. The descriptors are validated separately, where the platform allows it.
func DecodeObserverBinding(raw []byte) (*NetworkObserverBundle, error) {
	var out NetworkObserverBundle
	if err := decodeObserverJSON(raw, &out); err != nil {
		return nil, err
	}
	if err := ValidateObserverBinding(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ValidateObserverBinding checks a bundle's metadata against itself: canonical
// identity, a known policy and profile, and the exact three-socket order privd
// guarantees. A process that did not perform the acquisition uses it to refuse
// metadata no acquisition could have produced.
func ValidateObserverBinding(b *NetworkObserverBundle) error {
	if b == nil {
		return fmt.Errorf("missing observer bundle")
	}
	return validateObserverMetadata(AcquireNetworkObserversReq{VMID: b.Binding.VMID, GuestBootID: b.Binding.GuestBootID}, b)
}

func observerUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}
func observerHex(value string, n int) bool {
	if len(value) != n || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func observerNumber(value string) bool {
	n, err := strconv.ParseUint(value, 10, 64)
	return err == nil && n != 0 && strconv.FormatUint(n, 10) == value
}
func validateObserverRequest(req AcquireNetworkObserversReq) error {
	if !ValidVMID(req.VMID) || !observerUUID(req.GuestBootID) {
		return fmt.Errorf("observer request requires valid VM and canonical guest boot UUID")
	}
	return nil
}
func validateObserverMetadata(req AcquireNetworkObserversReq, b *NetworkObserverBundle) error {
	if err := validateObserverRequest(req); err != nil {
		return err
	}
	if b == nil {
		return fmt.Errorf("missing observer bundle")
	}
	v := b.Binding
	if v.VMID != req.VMID || v.GuestBootID != req.GuestBootID || !observerUUID(v.HostBootID) || !observerUUID(v.AcquisitionID) || !observerHex(v.GatewayGeneration, 32) || !observerHex(v.PolicyDigest, 64) || !observerNumber(v.NamespaceDevice) || !observerNumber(v.NamespaceInode) {
		return fmt.Errorf("invalid observer scope or acquisition identity")
	}
	if !ValidVMID(v.PolicyID) || (v.Profile != string(network.ProfileOffline) && v.Profile != string(network.ProfileTransport)) {
		return fmt.Errorf("invalid observer policy identity")
	}
	if len(b.Sockets) != 3 {
		return fmt.Errorf("observer reply requires three socket slots")
	}
	ct, ns, host := b.Sockets[0], b.Sockets[1], b.Sockets[2]
	if ct.Kind != "conntrack" || ct.Boundary != "namespace_gateway" || ct.PortID == 0 || ct.Group != 0 || ct.SnapshotSequence == 0 || ns.Kind != "nflog" || ns.Boundary != "namespace_gateway" || ns.PortID == 0 || ns.Group != network.NamespaceNFLogGroup || ns.SnapshotSequence != 0 || host.Kind != "nflog" || host.Boundary != "host_veth" || host.PortID == 0 || !network.IsHostNFLogGroup(host.Group) || host.SnapshotSequence != 0 {
		return fmt.Errorf("invalid observer socket order or metadata")
	}
	return nil
}

// decodeObserverJSON rejects unknown and duplicate fields at every object level.
// A strict struct decoder alone accepts repeated fields and silently takes the last.
func decodeObserverJSON(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > MaxMsgBytes {
		return fmt.Errorf("invalid observer JSON size")
	}
	scan := json.NewDecoder(bytes.NewReader(raw))
	first, err := scan.Token()
	if err != nil || first != json.Delim('{') {
		return fmt.Errorf("observer JSON must be an object")
	}
	if err := scanObserverObject(scan, 0); err != nil {
		return err
	}
	if _, err = scan.Token(); err != io.EOF {
		return fmt.Errorf("trailing observer JSON")
	}
	if err := observerFieldNames(raw, reflect.TypeOf(out)); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	return nil
}
func scanObserverObject(d *json.Decoder, depth int) error {
	if depth > 8 {
		return fmt.Errorf("observer JSON nesting exceeded")
	}
	seen := make(map[string]bool)
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return err
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return fmt.Errorf("duplicate or invalid observer field")
		}
		seen[name] = true
		if err := scanObserverValue(d, depth+1); err != nil {
			return err
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return fmt.Errorf("invalid observer object")
	}
	return nil
}
func scanObserverValue(d *json.Decoder, depth int) error {
	if depth > 8 {
		return fmt.Errorf("observer JSON nesting exceeded")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		return scanObserverObject(d, depth)
	case json.Delim('['):
		for d.More() {
			if err := scanObserverValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("invalid observer array")
		}
	}
	return nil
}

// encoding/json also accepts case-folded aliases for struct tags. Compare exact
// tags before decoding, so a second spelling cannot override an authenticated field.
func observerFieldNames(raw []byte, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return err
		}
		allowed := make(map[string]reflect.Type)
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")[0]
			if tag != "-" {
				allowed[tag] = field.Type
			}
		}
		for name, value := range fields {
			fieldType, ok := allowed[name]
			if !ok {
				return fmt.Errorf("unknown observer field %q", name)
			}
			if err := observerFieldNames(value, fieldType); err != nil {
				return err
			}
		}
	case reflect.Slice:
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return err
		}
		for _, value := range values {
			if err := observerFieldNames(value, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
