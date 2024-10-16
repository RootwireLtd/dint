package dns_resolver

import (
	"net"
	"strings"
)

func LookupSPFRecords(domain string) ([]string, error) {
	var records []string
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return nil, err
	}
	for _, txtRecord := range txtRecords {
		if strings.HasPrefix(txtRecord, "v=spf1") {
			records = append(records, txtRecord)
		}
	}
	return records, nil
}
