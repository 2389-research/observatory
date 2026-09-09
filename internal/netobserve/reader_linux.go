// ABOUTME: Reads owned conntrack and NFLOG descriptors with bounded polling and output.
// ABOUTME: Validates kernel provenance and immutable source bindings before publishing evidence.
//go:build linux

package netobserve

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const readerPollMilliseconds = 50

var errNFLogSequenceMissing = errors.New("NFLOG local sequence is missing")

type readerSource struct {
	config           SourceConfig
	fd               int
	tracker          *Tracker
	baselineDeadline time.Time
	mu               sync.Mutex
	status           SourceStatus
}

type Reader struct {
	ctx          context.Context
	cancel       context.CancelFunc
	observations chan Observation
	sources      []*readerSource
	status       ReaderStatus
	done         chan struct{}
	closeOnce    sync.Once
	closeErr     error
}

func NewReader(ctx context.Context, config ReaderConfig) (*Reader, error) {
	if ctx == nil {
		return nil, fmt.Errorf("reader context is required")
	}
	if err := validateReaderConfig(&config); err != nil {
		return nil, err
	}

	fds := make([]int, len(config.Sources))
	seenFDs := make(map[int]struct{}, len(config.Sources))
	for i := range config.Sources {
		fd, err := validateReaderFile(config.Sources[i])
		if err != nil {
			return nil, fmt.Errorf("reader source %q: %w", config.Sources[i].ID, err)
		}
		if _, exists := seenFDs[fd]; exists {
			return nil, fmt.Errorf("reader source %q duplicates an open descriptor", config.Sources[i].ID)
		}
		seenFDs[fd] = struct{}{}
		fds[i] = fd
	}

	readerCtx, cancel := context.WithCancel(ctx)
	r := &Reader{
		ctx:          readerCtx,
		cancel:       cancel,
		observations: make(chan Observation, config.QueueCapacity),
		status:       ReaderStatus{QueueCapacity: config.QueueCapacity},
		done:         make(chan struct{}),
	}
	now := time.Now()
	for i, sourceConfig := range config.Sources {
		tracker, err := NewTracker(sourceConfig.Scope, config.TrackerLimits)
		if err != nil {
			cancel()
			return nil, err
		}
		source := newReaderSource(sourceConfig, tracker, now.Add(config.BaselineTimeout))
		source.fd = fds[i]
		if sourceConfig.Kind == SourceNFLog {
			source.status.ReadState = ReadHealthy
			source.status.LastSuccess = now
		}
		r.sources = append(r.sources, source)
	}
	go r.run(config.MaxDatagramBytes)
	return r, nil
}

func newReaderSource(config SourceConfig, tracker *Tracker, baselineDeadline time.Time) *readerSource {
	baseline := BaselineNotApplicable
	if config.Kind == SourceConntrack {
		baseline = BaselinePending
	}
	return &readerSource{
		config:           config,
		fd:               -1,
		tracker:          tracker,
		baselineDeadline: baselineDeadline,
		status: SourceStatus{
			ID: config.ID, Scope: config.Scope, Kind: config.Kind,
			Baseline: baseline, ReadState: ReadStarting,
		},
	}
}

func validateReaderFile(source SourceConfig) (int, error) {
	raw, err := source.File.SyscallConn()
	if err != nil {
		return -1, fmt.Errorf("access descriptor: %w", err)
	}
	fd := -1
	var validationErr error
	if err := raw.Control(func(rawFD uintptr) {
		fd = int(rawFD)
		domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
		if err != nil || domain != unix.AF_NETLINK {
			validationErr = fmt.Errorf("descriptor is not AF_NETLINK: domain=%d error=%v", domain, err)
			return
		}
		kind, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
		if err != nil || kind != unix.SOCK_RAW {
			validationErr = fmt.Errorf("descriptor is not SOCK_RAW: type=%d error=%v", kind, err)
			return
		}
		protocol, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
		if err != nil || protocol != unix.NETLINK_NETFILTER {
			validationErr = fmt.Errorf("descriptor is not NETLINK_NETFILTER: protocol=%d error=%v", protocol, err)
			return
		}
		flags, err := unix.FcntlInt(rawFD, unix.F_GETFL, 0)
		if err != nil || flags&unix.O_NONBLOCK == 0 {
			validationErr = fmt.Errorf("descriptor is not nonblocking: flags=%d error=%v", flags, err)
			return
		}
		address, err := unix.Getsockname(fd)
		local, ok := address.(*unix.SockaddrNetlink)
		if err != nil || !ok || local.Pid != source.PortID {
			validationErr = fmt.Errorf("descriptor port does not match binding: address=%+v error=%v", address, err)
			return
		}
		if source.Kind == SourceConntrack && local.Groups != 7 {
			validationErr = fmt.Errorf("conntrack descriptor groups=%d want=7", local.Groups)
			return
		}
		if source.Kind == SourceNFLog && local.Groups != 0 {
			validationErr = fmt.Errorf("NFLOG descriptor has multicast groups=%d", local.Groups)
		}
	}); err != nil {
		return -1, fmt.Errorf("inspect descriptor: %w", err)
	}
	if validationErr != nil {
		return -1, validationErr
	}
	return fd, nil
}

func (r *Reader) Observations() <-chan Observation { return r.observations }

func (r *Reader) Status() ReaderStatus {
	status := ReaderStatus{QueueDepth: len(r.observations), QueueCapacity: cap(r.observations)}
	for _, source := range r.sources {
		source.mu.Lock()
		status.Sources = append(status.Sources, source.status)
		source.mu.Unlock()
	}
	return status
}

func (r *Reader) Close() error {
	r.closeOnce.Do(func() {
		r.cancel()
		<-r.done
	})
	return r.closeErr
}

func (r *Reader) run(maxDatagramBytes int) {
	defer close(r.done)
	defer close(r.observations)
	defer func() {
		for _, source := range r.sources {
			if err := source.config.File.Close(); err != nil && r.closeErr == nil {
				r.closeErr = err
			}
			source.stop()
		}
	}()

	poll := make([]unix.PollFd, len(r.sources))
	for i, source := range r.sources {
		poll[i] = unix.PollFd{Fd: int32(source.fd), Events: unix.POLLIN}
	}
	buffers := make([][]byte, len(r.sources))
	for i := range buffers {
		buffers[i] = make([]byte, maxDatagramBytes)
	}
	cursor := 0
	for {
		if err := r.ctx.Err(); err != nil {
			return
		}
		r.expireBaselines(time.Now())
		_, err := unix.Poll(poll, readerPollMilliseconds)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			for _, source := range r.sources {
				r.publish(source, source.readError(err, time.Now()))
			}
			return
		}
		now := time.Now()
		for _, source := range r.sources {
			source.refreshLiveness(now)
		}
		for offset := range r.sources {
			i := (cursor + offset) % len(r.sources)
			if poll[i].Revents == 0 {
				continue
			}
			source := r.sources[i]
			if poll[i].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				r.publish(source, source.readError(fmt.Errorf("netlink poll state %#x", poll[i].Revents), time.Now()))
				poll[i].Fd = -1
				continue
			}
			n, _, flags, sender, err := unix.Recvmsg(source.fd, buffers[i], nil, unix.MSG_DONTWAIT)
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				r.publish(source, source.readError(err, time.Now()))
				continue
			}
			netlinkSender, ok := sender.(*unix.SockaddrNetlink)
			if !ok {
				r.publish(source, source.readError(fmt.Errorf("%w: sender is not netlink", ErrMalformed), time.Now()))
				continue
			}
			now := time.Now()
			observations, err := source.consume(buffers[i][:n], netlinkSender, flags, now)
			if err != nil {
				r.publish(source, source.readError(err, now))
				continue
			}
			for _, observation := range observations {
				r.publish(source, observation)
			}
		}
		cursor = (cursor + 1) % len(r.sources)
	}
}

func (source *readerSource) refreshLiveness(now time.Time) {
	source.mu.Lock()
	if source.status.ReadState == ReadHealthy {
		source.status.LastSuccess = now
	}
	source.mu.Unlock()
}

func (source *readerSource) stop() {
	source.mu.Lock()
	if source.status.ReadState != ReadFailed {
		source.status.ReadState = ReadStopped
	}
	source.mu.Unlock()
}

func (r *Reader) expireBaselines(now time.Time) {
	for _, source := range r.sources {
		source.mu.Lock()
		if source.status.Baseline == BaselinePending && !now.Before(source.baselineDeadline) {
			source.status.Baseline = BaselineFailed
			source.status.KernelUnknownIntervals++
			source.status.LastErrorAt = now
			source.status.LastError = "conntrack baseline deadline exceeded"
		}
		source.mu.Unlock()
	}
}

func (r *Reader) publish(source *readerSource, observation Observation) {
	if observation.SourceID == "" {
		observation.SourceID = source.config.ID
	}
	select {
	case r.observations <- observation:
	default:
		source.mu.Lock()
		source.status.QueueDrops++
		source.mu.Unlock()
	}
}

func (source *readerSource) consume(data []byte, sender *unix.SockaddrNetlink, flags int, now time.Time) ([]Observation, error) {
	if sender == nil || sender.Family != unix.AF_NETLINK || sender.Pid != 0 {
		return nil, fmt.Errorf("%w: datagram sender is not the kernel", ErrMalformed)
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return nil, fmt.Errorf("%w: truncated netlink datagram", ErrMalformed)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty netlink datagram", ErrMalformed)
	}
	parsed, err := messages(data)
	if err != nil {
		return nil, err
	}
	var observations []Observation
	switch source.config.Kind {
	case SourceConntrack:
		for _, m := range parsed {
			snapshot := m.sequence == source.config.SnapshotSequence && m.port == source.config.PortID
			live := m.sequence == 0 && m.port == 0
			if !snapshot && !live {
				return nil, fmt.Errorf("%w: conntrack message does not match dump or live identity", ErrMalformed)
			}
			if snapshot && sender.Groups != 0 {
				return nil, fmt.Errorf("%w: conntrack snapshot arrived as multicast", ErrMalformed)
			}
			if live && sender.Groups != 0 && sender.Groups != 1 && sender.Groups != 2 && sender.Groups != 4 {
				return nil, fmt.Errorf("%w: conntrack message has unexpected multicast group", ErrMalformed)
			}
			if m.kind == unix.NLMSG_DONE {
				if !snapshot {
					return nil, fmt.Errorf("%w: conntrack completion does not match snapshot", ErrMalformed)
				}
				if _, err := ParseConntrack(m.raw, true); err != nil {
					return nil, err
				}
				source.mu.Lock()
				if source.status.Baseline == BaselinePending {
					source.status.Baseline = BaselineReady
				}
				source.mu.Unlock()
				continue
			}
			flows, err := ParseConntrack(m.raw, snapshot)
			if errors.Is(err, ErrUnsupportedFamily) {
				// Outside this collector's declared IPv4 scope: skip the message,
				// count the limitation, and leave the rest of the datagram and the
				// tracker's flow state untouched.
				source.mu.Lock()
				source.status.UnsupportedFamilyMessages++
				source.mu.Unlock()
				continue
			}
			if err != nil {
				return nil, err
			}
			for _, flow := range flows {
				result := source.tracker.ObserveFlow(flow, now)
				source.recordTrackerLosses(result.Losses)
				observations = append(observations, Observation{SourceID: source.config.ID, ObservedAt: now, Result: result})
			}
		}
	case SourceNFLog:
		if sender.Groups != 0 {
			return nil, fmt.Errorf("%w: NFLOG record arrived as multicast", ErrMalformed)
		}
		for _, m := range parsed {
			if m.sequence != 0 || m.port != 0 {
				return nil, fmt.Errorf("%w: NFLOG message has unexpected netlink identity", ErrMalformed)
			}
			denials, err := ParseNFLog(m.raw)
			if err != nil {
				return nil, err
			}
			for _, denial := range denials {
				if denial.Group != source.config.NFLogGroup || !slices.Contains(source.config.DenialPrefixes, denial.Prefix) {
					return nil, fmt.Errorf("%w: NFLOG record does not match installed denial binding", ErrMalformed)
				}
				if denial.Sequence == nil {
					return nil, errNFLogSequenceMissing
				}
				result := source.tracker.ObserveDenial(denial)
				source.recordTrackerLosses(result.Losses)
				observations = append(observations, Observation{SourceID: source.config.ID, ObservedAt: now, Result: result})
			}
		}
	default:
		return nil, fmt.Errorf("unknown reader source kind %q", source.config.Kind)
	}
	source.mu.Lock()
	source.status.ReadState = ReadHealthy
	source.status.LastSuccess = now
	source.mu.Unlock()
	return observations, nil
}

func (source *readerSource) recordTrackerLosses(losses []Loss) {
	source.mu.Lock()
	defer source.mu.Unlock()
	for _, loss := range losses {
		count := uint64(1)
		if loss.Count != nil {
			count = *loss.Count
		}
		switch loss.Reason {
		case "nflog_sequence_gap":
			source.status.NFLogSequenceDrops += count
		case "nflog_sequence_discontinuity":
			source.status.NFLogUnknownIntervals++
		case "flow_state_evicted", "flow_state_expired", "nflog_group_evicted":
			source.status.TrackerEntriesForgotten += count
		case "flow_identity_untracked":
			source.status.FlowIdentityUntracked += count
		}
	}
}

func (source *readerSource) readError(err error, now time.Time) Observation {
	result := source.tracker.ReadError(err)
	source.mu.Lock()
	source.status.ReadState = ReadFailed
	if errors.Is(err, errNFLogSequenceMissing) {
		source.status.NFLogUnknownIntervals++
	} else {
		source.status.KernelUnknownIntervals++
	}
	source.status.LastErrorAt = now
	source.status.LastError = err.Error()
	if errors.Is(err, ErrDumpInterrupted) && source.status.Baseline == BaselinePending {
		source.status.Baseline = BaselineFailed
	}
	source.mu.Unlock()
	return Observation{SourceID: source.config.ID, ObservedAt: now, Result: result}
}
