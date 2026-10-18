package benchmark

import (
	"runtime"
	"testing"
	"time"
)

func TestMemorySamplerCapturesInteriorPeakAndResets(t *testing.T) {
	observed := make(chan struct{})
	calls := 0
	s := startMemory(time.Millisecond, func() Memory {
		calls++
		value := uint64(20)
		if calls == 1 {
			value = 10
		}
		if calls == 2 {
			value = 100 // Higher than both endpoint observations.
			close(observed)
		}
		return Memory{HeapBytes: value, RSSBytes: value * 2, RSSAvailable: true}
	})
	select {
	case <-observed:
	case <-time.After(2 * time.Second):
		s.Stop()
		t.Fatal("periodic sample did not run")
	}
	peak := s.Stop()
	if peak.HeapBytes != 100 || peak.RSSBytes != 200 || !peak.RSSAvailable {
		t.Fatalf("missed interior peak: %+v", peak)
	}
	// A new stage must not inherit the previous stage's high-water mark.
	next := startMemory(time.Hour, func() Memory {
		return Memory{HeapBytes: 3, RSSBytes: 6, RSSAvailable: true}
	}).Stop()
	if next.HeapBytes != 3 || next.RSSBytes != 6 {
		t.Fatalf("previous peak leaked into next stage: %+v", next)
	}
}

func TestMemorySamplerInvalidatesFailedRSS(t *testing.T) {
	calls := 0
	s := startMemory(time.Hour, func() Memory {
		calls++
		return Memory{HeapBytes: uint64(calls), RSSBytes: 10, RSSAvailable: calls == 1}
	})
	peak := s.Stop()
	if peak.RSSAvailable || peak.HeapBytes != 2 {
		t.Fatalf("failed RSS must be unavailable while heap remains measured: %+v", peak)
	}
}

func TestRuntimeMemoryReader(t *testing.T) {
	peak := StartMemory().Stop()
	if peak.HeapBytes == 0 {
		t.Fatal("heap metric was not read")
	}
	if runtime.GOOS == "linux" && (!peak.RSSAvailable || peak.RSSBytes == 0) {
		t.Fatal("Linux RSS was not read")
	}
	if runtime.GOOS != "linux" && peak.RSSAvailable {
		t.Fatal("unsupported RSS must not be reported as measured")
	}
}

func TestMergeMemoryIntervals(t *testing.T) {
	first := Memory{HeapBytes: 10, RSSBytes: 100, RSSAvailable: true, Measured: true}
	second := Memory{HeapBytes: 20, RSSBytes: 80, RSSAvailable: true, Measured: true}
	got := first.Merge(second)
	if got.HeapBytes != 20 || got.RSSBytes != 100 || !got.RSSAvailable || !got.Measured {
		t.Fatalf("phase intervals must merge maxima, not sums: %+v", got)
	}
	if empty := (Memory{}).Merge(first); empty != first {
		t.Fatal("empty interval lost measurements")
	}
	if empty := first.Merge(Memory{}); empty != first {
		t.Fatal("unmeasured interval changed peak")
	}
	second.RSSAvailable = false
	if first.Merge(second).RSSAvailable {
		t.Fatal("failed RSS observation must remain unavailable")
	}
}
