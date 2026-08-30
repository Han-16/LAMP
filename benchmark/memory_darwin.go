//go:build darwin

package benchmark

import "golang.org/x/sys/unix"

// PeakRSSBytes returns the process high-water resident-set size.
func PeakRSSBytes() uint64 {
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil || usage.Maxrss < 0 {
		return 0
	}
	return uint64(usage.Maxrss) // Darwin reports bytes.
}
