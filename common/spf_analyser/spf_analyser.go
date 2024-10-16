package spf_analyser

import (
	"fmt"
	"strings"
)

// SpfTestResults struct to hold the results of each SPF check
type SpfTestResults struct {
	AllTestsPassed    bool
	RecordFound       bool
	SingleRecord      bool
	QualifierHardFail bool
}

func CheckSPFRecord(records []string) (SpfTestResults, string) {
	// Initialize the struct to hold the results
	results := SpfTestResults{
		AllTestsPassed:    false,
		RecordFound:       false,
		SingleRecord:      len(records) == 1,
		QualifierHardFail: false,
	}

	for _, record := range records {
		if strings.HasPrefix(record, "v=spf1") {
			results.RecordFound = true

			if strings.Contains(record, "-all") {
				results.QualifierHardFail = true
			}
		}
	}

	results.AllTestsPassed = results.RecordFound && results.SingleRecord && results.QualifierHardFail
	return results, fmt.Sprintf("SPF record found: %v, Single SPF record: %v, Hard fail qualifier: %v", results.RecordFound, results.SingleRecord, results.QualifierHardFail)
}
