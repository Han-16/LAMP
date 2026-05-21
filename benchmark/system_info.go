package benchmark

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type systemInfo struct {
	GeneratedAt            string `json:"generatedAt"`
	Hostname               string `json:"hostname,omitempty"`
	OS                     string `json:"os"`
	Arch                   string `json:"arch"`
	GoVersion              string `json:"goVersion"`
	CPUModel               string `json:"cpuModel"`
	LogicalCores           int    `json:"logicalCores"`
	TotalMemoryBytes       uint64 `json:"totalMemoryBytes,omitempty"`
	TotalMemory            string `json:"totalMemory,omitempty"`
	CgroupMemoryLimitBytes uint64 `json:"cgroupMemoryLimitBytes,omitempty"`
	CgroupMemoryLimit      string `json:"cgroupMemoryLimit,omitempty"`
}

func writeSystemInfoForCSV(csvFilename string) {
	outputPath := filepath.Join(filepath.Dir(csvFilename), "system_info.json")
	info := collectSystemInfo()

	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		log.Printf("Warning: failed to encode system info JSON: %v", err)
		return
	}

	if err := os.WriteFile(outputPath, append(data, '\n'), 0644); err != nil {
		log.Printf("Warning: failed to write system info JSON: %v", err)
	}
}

func collectSystemInfo() systemInfo {
	hostname, _ := os.Hostname()
	totalMemory := detectTotalMemoryBytes()
	cgroupMemoryLimit := detectCgroupMemoryLimitBytes()

	return systemInfo{
		GeneratedAt:            time.Now().Format(time.RFC3339),
		Hostname:               hostname,
		OS:                     runtime.GOOS,
		Arch:                   runtime.GOARCH,
		GoVersion:              runtime.Version(),
		CPUModel:               detectCPUModel(),
		LogicalCores:           runtime.NumCPU(),
		TotalMemoryBytes:       totalMemory,
		TotalMemory:            formatBytes(totalMemory),
		CgroupMemoryLimitBytes: cgroupMemoryLimit,
		CgroupMemoryLimit:      formatBytes(cgroupMemoryLimit),
	}
}

func detectCPUModel() string {
	switch runtime.GOOS {
	case "darwin":
		if value := runSysctl("machdep.cpu.brand_string"); value != "" {
			return value
		}
	case "linux":
		if value := readLinuxCPUModel(); value != "" {
			return value
		}
	}
	return runtime.GOARCH
}

func detectTotalMemoryBytes() uint64 {
	switch runtime.GOOS {
	case "darwin":
		value := runSysctl("hw.memsize")
		mem, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err == nil {
			return mem
		}
	case "linux":
		return readLinuxMemTotalBytes()
	}
	return 0
}

func detectCgroupMemoryLimitBytes() uint64 {
	if runtime.GOOS != "linux" {
		return 0
	}

	for _, path := range []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		value := strings.TrimSpace(string(data))
		if value == "" || value == "max" {
			continue
		}
		limit, err := strconv.ParseUint(value, 10, 64)
		if err == nil && isRealisticMemoryLimit(limit) {
			return limit
		}
	}

	return 0
}

func isRealisticMemoryLimit(limit uint64) bool {
	const maxReasonableLimit = uint64(1 << 50) // 1 PiB
	return limit > 0 && limit < maxReasonableLimit
}

func runSysctl(name string) string {
	out, err := exec.Command("sysctl", "-n", name).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func readLinuxCPUModel() string {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	defer file.Close()

	preferredKeys := []string{"model name", "Hardware", "Processor", "cpu model"}
	values := make(map[string]string, len(preferredKeys))

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if value == "" {
			continue
		}
		if _, ok := values[key]; !ok {
			values[key] = value
		}
	}

	for _, key := range preferredKeys {
		if value := values[key]; value != "" {
			return value
		}
	}
	return ""
}

func readLinuxMemTotalBytes() uint64 {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		memKB, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return memKB * 1024
	}
	return 0
}

func formatBytes(bytes uint64) string {
	if bytes == 0 {
		return ""
	}

	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	value := float64(bytes)
	for _, suffix := range []string{"KiB", "MiB", "GiB", "TiB", "PiB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.2f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.2f EiB", value/unit)
}
