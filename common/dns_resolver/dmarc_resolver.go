package dns_resolver

import (
	"log/slog"
	"net"
)

func LookupDMARCRecords(domain string) ([]string, error) {
	var records []string
	dmarcDomain := "_dmarc." + domain
	txtRecords, err := net.LookupTXT(dmarcDomain)
	if err != nil {
		slog.Debug("No DKIM record found at: %v\n", dmarcDomain)
	}
	for _, txtRecord := range txtRecords {
		records = append(records, txtRecord)
	}
	return records, nil
}
