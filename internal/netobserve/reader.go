// ABOUTME: Defines bounded live netlink reader inputs, observations and health snapshots.
// ABOUTME: Keeps immutable source identity and loss classes separate from durable event storage.
package netobserve

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	DefaultReaderQueueCapacity = 128
	MaxReaderQueueCapacity     = 1024
	MaxReaderSources           = 3
	MaxBaselineTimeout         = 30 * time.Second
)

type SourceKind string

const (
	SourceConntrack SourceKind = "conntrack"
	SourceNFLog     SourceKind = "nflog"
)

// SourceConfig binds an already acquired file to immutable host-owned evidence.
// File ownership transfers to Reader only when NewReader succeeds.
type SourceConfig struct {
	ID               string
	File             *os.File
	Scope            Scope
	Kind             SourceKind
	PortID           uint32
	SnapshotSequence uint32
	NFLogGroup       uint16
	DenialPrefixes   []string
}

type ReaderConfig struct {
	Sources          []SourceConfig
	TrackerLimits    Limits
	QueueCapacity    int
	BaselineTimeout  time.Duration
	MaxDatagramBytes int
}

type Observation struct {
	SourceID   string
	ObservedAt time.Time
	Result     Result
}

type BaselineState string

const (
	BaselinePending       BaselineState = "pending"
	BaselineReady         BaselineState = "ready"
	BaselineFailed        BaselineState = "failed"
	BaselineNotApplicable BaselineState = "not_applicable"
)

type ReadState string

const (
	ReadStarting ReadState = "starting"
	ReadHealthy  ReadState = "healthy"
	ReadFailed   ReadState = "failed"
	ReadStopped  ReadState = "stopped"
)

// SourceStatus separates measured local loss, measured kernel sequence gaps,
// unknown kernel intervals and forgotten correlation state.
type SourceStatus struct {
	ID                      string
	Scope                   Scope
	Kind                    SourceKind
	Baseline                BaselineState
	ReadState               ReadState
	QueueDrops              uint64
	NFLogSequenceDrops      uint64
	NFLogUnknownIntervals   uint64
	KernelUnknownIntervals  uint64
	TrackerEntriesForgotten uint64
	// FlowIdentityUntracked counts flows observed but not correlatable: no
	// conntrack id and a tuple this collector cannot key. Not loss.
	FlowIdentityUntracked uint64
	// UnsupportedFamilyMessages counts kernel messages skipped for an address
	// family outside this collector's declared scope. Not loss.
	UnsupportedFamilyMessages uint64
	LastSuccess               time.Time
	LastErrorAt               time.Time
	LastError                 string
}

type ReaderStatus struct {
	Sources       []SourceStatus
	QueueDepth    int
	QueueCapacity int
}

func validateReaderConfig(config *ReaderConfig) error {
	if config == nil {
		return fmt.Errorf("reader config is required")
	}
	if config.QueueCapacity == 0 {
		config.QueueCapacity = DefaultReaderQueueCapacity
	}
	if config.MaxDatagramBytes == 0 {
		config.MaxDatagramBytes = MaxDatagramBytes
	}
	if len(config.Sources) < 1 || len(config.Sources) > MaxReaderSources {
		return fmt.Errorf("reader requires 1..%d sources", MaxReaderSources)
	}
	if config.QueueCapacity < 1 || config.QueueCapacity > MaxReaderQueueCapacity {
		return fmt.Errorf("reader queue capacity must be 1..%d", MaxReaderQueueCapacity)
	}
	if config.BaselineTimeout <= 0 || config.BaselineTimeout > MaxBaselineTimeout {
		return fmt.Errorf("reader baseline timeout must be positive and at most %s", MaxBaselineTimeout)
	}
	if config.MaxDatagramBytes < 20 || config.MaxDatagramBytes > MaxDatagramBytes {
		return fmt.Errorf("reader datagram bound must be 20..%d bytes", MaxDatagramBytes)
	}

	ids := make(map[string]struct{}, len(config.Sources))
	files := make(map[*os.File]struct{}, len(config.Sources))
	for i := range config.Sources {
		source := &config.Sources[i]
		if len(source.ID) < 1 || len(source.ID) > 128 {
			return fmt.Errorf("reader source %d requires a bounded nonempty ID", i)
		}
		if _, exists := ids[source.ID]; exists {
			return fmt.Errorf("reader source ID %q is duplicated", source.ID)
		}
		ids[source.ID] = struct{}{}
		if source.File == nil {
			return fmt.Errorf("reader source %q requires a file", source.ID)
		}
		if _, exists := files[source.File]; exists {
			return fmt.Errorf("reader source file for %q is duplicated", source.ID)
		}
		files[source.File] = struct{}{}
		if source.PortID == 0 {
			return fmt.Errorf("reader source %q requires a netlink port ID", source.ID)
		}
		if _, err := NewTracker(source.Scope, config.TrackerLimits); err != nil {
			return fmt.Errorf("reader source %q: %w", source.ID, err)
		}
		switch source.Kind {
		case SourceConntrack:
			if source.SnapshotSequence == 0 || source.NFLogGroup != 0 || len(source.DenialPrefixes) != 0 {
				return fmt.Errorf("conntrack source %q has invalid snapshot or NFLOG binding", source.ID)
			}
		case SourceNFLog:
			if source.SnapshotSequence != 0 || source.NFLogGroup == 0 || len(source.DenialPrefixes) < 1 || len(source.DenialPrefixes) > 8 {
				return fmt.Errorf("NFLOG source %q has invalid group, snapshot or prefix binding", source.ID)
			}
			prefixes := make(map[string]struct{}, len(source.DenialPrefixes))
			for _, prefix := range source.DenialPrefixes {
				if len(prefix) < 1 || len(prefix) > 127 || strings.IndexByte(prefix, 0) >= 0 {
					return fmt.Errorf("NFLOG source %q has an invalid denial prefix", source.ID)
				}
				if _, exists := prefixes[prefix]; exists {
					return fmt.Errorf("NFLOG source %q has a duplicate denial prefix", source.ID)
				}
				prefixes[prefix] = struct{}{}
			}
		default:
			return fmt.Errorf("reader source %q has unknown kind %q", source.ID, source.Kind)
		}
	}
	return nil
}
