package main

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"example.com/lamp/benchmark"
)

func TestRepeatedExperiments(t *testing.T) {
	t.Setenv("BENCHMARK_APPEND_CSV", "false")
	dir := t.TempDir()
	writer, err := benchmark.InitFreivaldsBatchCSV(filepath.Join(dir, "results.csv"))
	if err != nil {
		t.Fatal(err)
	}
	for _, batch := range []int{1, 2} {
		if err := runRepeatedExperiments(1, batch, false, "generate", dir, 3, writer); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "results_average.csv")); !os.IsNotExist(err) {
		t.Fatal("premature average")
	}
	if err := writer.SaveAverages(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	read := func(name string) [][]string {
		t.Helper()
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		rows, err := csv.NewReader(f).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	for _, suffix := range []string{"", "_info", "_memory"} {
		rows := read("results" + suffix + ".csv")
		if len(rows) != 7 {
			t.Fatalf("%s: want six measurements, got %d", suffix, len(rows)-1)
		}
		for i, row := range rows[1:] {
			if row[1] != strconv.Itoa(i%3+1) {
				t.Fatal("wrong repeat order")
			}
			if suffix == "_info" && row[9] != rows[1+(i/3)*3][9] {
				t.Fatal("input computation was repeated")
			}
		}
	}
	averages := read("results_average.csv")
	if len(averages) != 3 {
		t.Fatalf("want two configuration averages: %v", averages)
	}
	for _, row := range averages[1:] {
		if row[5] != "3" {
			t.Fatal("wrong run count")
		}
	}
}

func TestMissingInputProducesNoAverage(t *testing.T) {
	t.Setenv("BENCHMARK_APPEND_CSV", "false")
	dir := t.TempDir()
	writer, err := benchmark.InitFreivaldsBatchCSV(filepath.Join(dir, "failed.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if err := runRepeatedExperiments(2, 1, false, "file", dir, 1, writer); err == nil {
		t.Fatal("missing input should fail")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "failed_average.csv")); !os.IsNotExist(err) {
		t.Fatal("failed experiment created an average")
	}
}
