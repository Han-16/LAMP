package benchmark

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const MemoryInterval = 10 * time.Millisecond

// Memory contains sampled peak RSS, in bytes. This is absolute process
// resident memory, not allocations attributable only to the measured stage.
type Memory struct {
	RSSBytes     uint64
	RSSAvailable bool
	Measured     bool
}

type MemorySampler struct {
	stop chan struct{}
	done chan Memory
}

// StartMemory samples once before returning, periodically during the stage,
// and once when Stop is called. Each sampler starts with fresh maxima.
func StartMemory() *MemorySampler {
	read := func() Memory {
		rss, available := residentBytes()
		return Memory{RSSBytes: rss, RSSAvailable: available, Measured: true}
	}
	return startMemory(MemoryInterval, read)
}

func startMemory(interval time.Duration, read func() Memory) *MemorySampler {
	s := &MemorySampler{stop: make(chan struct{}), done: make(chan Memory)}
	peak := read()
	sample := func() {
		current := read()
		peak.RSSBytes = max(peak.RSSBytes, current.RSSBytes)
		// Do not present a partially failed RSS observation as a valid peak.
		peak.RSSAvailable = peak.RSSAvailable && current.RSSAvailable
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sample()
			case <-s.stop:
				sample()
				s.done <- peak
				return
			}
		}
	}()
	return s
}

// Stop must be called exactly once, including after a failed stage.
func (s *MemorySampler) Stop() Memory {
	close(s.stop)
	return <-s.done
}

// Linux reports statm's resident field in pages. Other systems have no RSS
// reader here: report unavailable rather than a cumulative process high-water
// mark. This also keeps native macOS and CGO-disabled builds supported.
func residentBytes() (uint64, bool) {
	if runtime.GOOS != "linux" {
		return 0, false
	}
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, false
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return pages * uint64(os.Getpagesize()), true
}

// Merge combines disjoint intervals of the same phase without adding memory sizes.
func (m Memory) Merge(other Memory) Memory {
	if !m.Measured {
		return other
	}
	if !other.Measured {
		return m
	}
	return Memory{RSSBytes: max(m.RSSBytes, other.RSSBytes), RSSAvailable: m.RSSAvailable && other.RSSAvailable, Measured: true}
}
