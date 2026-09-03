package benchmark

import "testing"

func TestPeakRSSBytes(t *testing.T) {
	if got := PeakRSSBytes(); got == 0 {
		t.Fatal("PeakRSSBytes returned zero")
	}
}
