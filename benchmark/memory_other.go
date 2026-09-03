//go:build !linux && !darwin

package benchmark

import "runtime"

// PeakRSSBytes falls back to Go-managed system memory on unsupported systems.
func PeakRSSBytes() uint64 {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.Sys
}
