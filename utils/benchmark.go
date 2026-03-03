package utils

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strconv"
)

// BenchmarkResult 구조체는 각 실행에 대한 측정 지표를 담습니다.
type BenchmarkResult struct {
	LogK        int
	Rho         string
	Precompute  float64 // s 단위
	Encoding    float64 // s 단위
	Constraints int
}

func InitCSV(filename string) (*os.File, *csv.Writer) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to create CSV file: %v", err)
	}

	writer := csv.NewWriter(file)
	header := []string{"log(K)", "rho", "Precompute (s)", "Encoding (s)", "Constraint"}

	if err := writer.Write(header); err != nil {
		log.Fatalf("Failed to write CSV header: %v", err)
	}
	writer.Flush()

	return file, writer
}

func AppendResultToCSV(writer *csv.Writer, res BenchmarkResult) {
	record := []string{
		strconv.Itoa(res.LogK),
		res.Rho,
		fmt.Sprintf("%.6f", res.Precompute),
		fmt.Sprintf("%.6f", res.Encoding),
		strconv.Itoa(res.Constraints),
	}

	if err := writer.Write(record); err != nil {
		log.Printf("⚠️ Failed to write record to CSV: %v", err)
	}

	writer.Flush()

	if err := writer.Error(); err != nil {
		log.Printf("⚠️ Error flushing csv writer: %v", err)
	} else {
		fmt.Printf("💾 Result saved to CSV: logK=%d, rho=%s\n", res.LogK, res.Rho)
	}
}
