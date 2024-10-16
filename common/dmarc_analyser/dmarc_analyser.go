package dmarc_analyser

import (
	"fmt"
	"strconv"
	"strings"
)

// dmarcTestResults struct to hold the results of each DMARC check
type dmarcTestResults struct {
	AllTestsPassed        bool
	RecordFound           bool
	SingleRecord          bool
	PolicyReject          bool
	SubdomainPolicyReject bool
	PctValid              bool
}

func CheckDMARCRecord(records []string) (dmarcTestResults, string) {
	// Initialize the struct to hold the results
	results := dmarcTestResults{
		AllTestsPassed:        false,
		RecordFound:           false,
		SingleRecord:          len(records) == 1,
		PolicyReject:          false,
		SubdomainPolicyReject: false,
		PctValid:              true, // Default assumption: pct is valid (100 or not present)
	}

	for _, record := range records {
		if strings.HasPrefix(record, "v=DMARC1") {
			results.RecordFound = true

			// Check for p=reject
			if strings.Contains(record, "p=reject") {
				results.PolicyReject = true
			}

			// Check for sp=reject
			if strings.Contains(record, "sp=reject") {
				results.SubdomainPolicyReject = true
			}

			// Check for pct=100 or no pct parameter
			if strings.Contains(record, "pct=") {
				pctValue := extractPctValue(record)
				if pctValue != 100 {
					results.PctValid = false
				}
			}
		}
	}
	results.AllTestsPassed = results.RecordFound && results.SingleRecord && results.PolicyReject && results.SubdomainPolicyReject && results.PctValid

	return results, fmt.Sprintf(
		"DMARC record found: %v, Single DMARC record: %v, Policy reject: %v, Subdomain policy reject: %v, pct=100 or default: %v",
		results.RecordFound, results.SingleRecord, results.PolicyReject, results.SubdomainPolicyReject, results.PctValid)
}

// Helper function to extract the pct value from a DMARC record
func extractPctValue(record string) int {
	pctIndex := strings.Index(record, "pct=")
	if pctIndex == -1 {
		// If pct isn't present, return 100 as the default value
		return 100
	}

	// Extract the actual pct value
	pctValueStr := record[pctIndex+4:] // Skip the 'pct=' part
	endIndex := strings.IndexAny(pctValueStr, "; ")
	if endIndex != -1 {
		pctValueStr = pctValueStr[:endIndex] // Extract the value until the next separator
	}

	// Convert pct value to an integer
	pctValue, err := strconv.Atoi(pctValueStr)
	if err != nil {
		// If there's an error parsing, assume default pct=100
		return 100
	}

	return pctValue
}
