package dns_resolver

import "net"

func LookupDNSRecords(recordType, domain string) ([]string, error) {
	var records []string
	switch recordType {
	case "MX":
		mxRecords, err := net.LookupMX(domain)
		if err != nil {
			return nil, err
		}
		for _, mxRecord := range mxRecords {
			records = append(records, mxRecord.Host)
		}
	case "TXT":
		txtRecords, err := net.LookupTXT(domain)
		if err != nil {
			return nil, err
		}
		records = append(records, txtRecords...)
	}
	return records, nil
}
