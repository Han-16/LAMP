package benchmark

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
)

type lampAverageGroup struct {
	first      LAMPResult
	extra      []string
	runs       int
	timings    []float64
	proofSizes []float64
	memory     [4]float64
	available  [4]bool
}

// Accumulate raw values from this invocation; never average formatted CSV cells.
func (set *LAMPCSV) addAverage(res LAMPResult, extra []string) {
	logk, n := set.dimensions(res)
	key := strings.Join(append([]string{logk, n, res.Rho, strconv.Itoa(res.NumQueries),
		strconv.Itoa(res.Constraints), res.MatrixSource, res.MatrixPath,
		strconv.Itoa(res.MatrixWorkers), res.Linker, res.Merkle}, extra...), "\x00")
	g := set.groups[key]
	if g == nil {
		g = &lampAverageGroup{first: res, extra: slices.Clone(extra),
			timings: make([]float64, len(lampTimingHeader)), proofSizes: make([]float64, len(lampProofSizeHeader)),
			available: [4]bool{true, true, true, true}}
		set.groups[key] = g
		set.groupOrder = append(set.groupOrder, g)
	}
	g.runs++
	for i, value := range res.timings() {
		g.timings[i] += value
	}
	for i, value := range res.proofSizes() {
		g.proofSizes[i] += float64(value)
	}
	for i, m := range res.memoryPeaks() {
		g.memory[i] += float64(m.RSSBytes)
		g.available[i] = g.available[i] && m.Measured && m.RSSAvailable
	}
}

func (set *LAMPCSV) averageRecords() [][]string {
	var rows [][]string
	for _, g := range set.groupOrder {
		r := g.first
		logk, n := set.dimensions(r)
		row := []string{set.runID, logk, r.Rho, strconv.Itoa(r.NumQueries), "legacy", strconv.Itoa(g.runs),
			strconv.Itoa(r.Constraints), r.MatrixSource, r.MatrixPath, strconv.Itoa(r.MatrixWorkers),
			formatSeconds(r.MatrixComputeTime), formatSeconds(r.MatrixLoadTime)}
		count := float64(g.runs)
		for _, sum := range g.timings {
			// LED rounds the raw duration mean to nanoseconds before formatting.
			row = append(row, optionalSeconds(math.Round(sum/count*1e9)/1e9))
		}
		for _, sum := range g.proofSizes {
			row = append(row, strconv.FormatFloat(sum/count, 'f', 2, 64))
		}
		for i, sum := range g.memory {
			cell := ""
			if g.available[i] {
				cell = memorySize(uint64(math.Round(sum / count)))
			}
			row = append(row, cell)
		}
		row = append(row, r.Linker, r.Merkle, n)
		rows = append(rows, append(row, g.extra...))
	}
	return rows
}

// SaveAverages is called only after every requested configuration has succeeded.
// Close deliberately preserves raw results without producing a partial summary.
func (set *LAMPCSV) SaveAverages() (err error) {
	if set.averagesSaved {
		return nil
	}
	if len(set.groupOrder) == 0 {
		return nil
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if set.appendResults {
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	f, err := os.OpenFile(set.averagePath, flags, 0666)
	if err != nil {
		return fmt.Errorf("save average CSV: %w", err)
	}
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}()
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	if stat.Size() == 0 {
		if err := w.Write(set.averageHeader); err != nil {
			return err
		}
	}
	for _, row := range set.averageRecords() {
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	set.averagesSaved = true
	fmt.Printf("Averages saved to CSV: %s\n", set.averagePath)
	return nil
}
