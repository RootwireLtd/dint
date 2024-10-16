package dns_resolver

import (
	"log/slog"
	"net"
)

// DKIMRecord holds the DKIM selector and the associated TXT record.
type DKIMRecord struct {
	Selector string
	Record   string
}

func LookupDKIMRecords(domain string) ([]DKIMRecord, error) {
	var dkimRecords []DKIMRecord

	// Common selectors to check for DKIM records
	selectors := []string{
		"default",
		"selector1",
		"selector2",
	}

	for _, selector := range selectors {
		dnsPath := selector + "._domainkey." + domain
		txtRecords, err := net.LookupTXT(dnsPath)
		if err != nil {
			slog.Debug("No DKIM record found at: %v\n", dnsPath)
			continue
		}
		// Append each found record along with its selector
		for _, txtRecord := range txtRecords {
			dkimRecords = append(dkimRecords, DKIMRecord{
				Selector: selector,
				Record:   txtRecord,
			})
		}
	}
	return dkimRecords, nil
}
