package main

import (
	"flag"
	"fmt"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/logrusorgru/aurora"
	"github.com/rootwireltd/dint/common/dmarc_analyser"
	"github.com/rootwireltd/dint/common/dns_resolver"
	"github.com/rootwireltd/dint/common/spf_analyser"
	"log"
)

//TIP To run your code, right-click the code and select <b>Run</b>. Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.

func DisplaySummary(domain string, spfTestPass, dmarcTestPass, dkimTestPass bool) {
	spfStatus := aurora.Red("FAIL").String()
	dmarcStatus := aurora.Red("FAIL").String()
	dkimStatus := aurora.Red("FAIL").String()

	if spfTestPass {
		spfStatus = aurora.Green("PASS").String()
	}
	if dmarcTestPass {
		dmarcStatus = aurora.Green("PASS").String()
	}
	if dkimTestPass {
		dkimStatus = aurora.Green("PASS").String()
	}

	var (
		colTitleDomain = "Domain"
		colTitleSPF    = "SPF"
		colTitleDMARC  = "DMARC"
		colTitleDKIM   = "DKIM"
		rowHeader      = table.Row{colTitleDomain, colTitleSPF, colTitleDMARC, colTitleDKIM}
	)

	var domainRow = table.Row{domain, spfStatus, dmarcStatus, dkimStatus}

	tw := table.NewWriter()
	tw.AppendHeader(rowHeader)
	tw.AppendRow(domainRow)

	fmt.Println(tw.Render())
}

func main() {
	// Parse commandline args
	domain := flag.String("d", "", "Domain to query")
	showSummary := flag.Bool("s", false, "Show summary view")
	flag.Parse()

	if *domain == "" {
		log.Fatal("You must specify a domain using -d")
	}

	fmt.Printf("Inspecting Domain: %s\n", *domain)

	// Fetch MX Records
	mxRecords, err := dns_resolver.LookupDNSRecords("MX", *domain)
	if err != nil {
		log.Fatalf("Error fetching MX records: %v", err)
	}

	// Fetch SPF Records
	spfRecords, err := dns_resolver.LookupSPFRecords(*domain)
	if err != nil {
		log.Fatalf("Error fetching SPF records: %v", err)
	}
	spfTestResults, _ := spf_analyser.CheckSPFRecord(spfRecords)

	// Fetch DMARC Records
	dmarcRecords, err := dns_resolver.LookupDMARCRecords(*domain)
	if err != nil {
		log.Fatalf("Error fetching DMARC records: %v", err)
	}
	dmarcTestResults, _ := dmarc_analyser.CheckDMARCRecord(dmarcRecords)

	// Fetch DKIM Records
	dkimRecords, err := dns_resolver.LookupDKIMRecords(*domain)
	if err != nil {
		log.Fatalf("Error fetching DKIM records: %v", err)
	}
	var dkimPresent = len(dkimRecords) > 0

	// Display Results

	DisplaySummary(*domain, spfTestResults.AllTestsPassed, dmarcTestResults.AllTestsPassed, dkimPresent)
	// If summary flag is present, don't show the remaining details
	if *showSummary {

		return
	}

	// MX Records
	fmt.Printf("Domain: %s\n", *domain)
	fmt.Printf("MX Records: \n")
	if len(mxRecords) == 0 {
		fmt.Println("- No MX records found")
	} else {
		for _, mxRecord := range mxRecords {
			fmt.Printf("- %s\n", mxRecord)
		}
	}

	// SPF Records
	fmt.Printf("SPF Records: \n")
	if len(spfRecords) == 0 {
		fmt.Println("- No SPF records found")
	} else {
		for _, spfRecord := range spfRecords {
			fmt.Printf("- %s\n", spfRecord)
		}
	}
	// SPF Analysis
	fmt.Printf("SPF Analysis: \n")
	fmt.Printf("- SPF Record is present: %v\n", spfTestResults.RecordFound)
	fmt.Printf("- SPF Record is a single record: %v\n", spfTestResults.SingleRecord)
	fmt.Printf("- SPF Record Qualifier is Hard Fail: %v\n", spfTestResults.QualifierHardFail)

	// DMARC Records
	fmt.Printf("DMARC Records: \n")
	if len(dmarcRecords) == 0 {
		fmt.Println("- No DMARC records found")
	} else {
		for _, dmarcRecord := range dmarcRecords {
			fmt.Printf("- %s\n", dmarcRecord)
		}
	}

	// DMARC Analysis
	fmt.Printf("DMARC Analysis: \n")
	fmt.Printf("- DMARC Record is present: %v\n", dmarcTestResults.RecordFound)
	fmt.Printf("- DMARC Record is a single record: %v\n", dmarcTestResults.SingleRecord)
	fmt.Printf("- DMARC Record Policy is Reject: %v\n", dmarcTestResults.PolicyReject)
	fmt.Printf("- DMARC Record Subdomain Policy is Reject: %v\n", dmarcTestResults.SubdomainPolicyReject)
	fmt.Printf("- DMARC Record Applies to 100%% of Mail: %v\n", dmarcTestResults.PctValid)

	fmt.Printf("DKIM Records: \n")
	if len(dkimRecords) == 0 {
		fmt.Println("- No DKIM records found")
	} else {
		for _, dkimRecord := range dkimRecords {
			fmt.Printf("- %s\n", dkimRecord)
		}
	}

	// Output DKIM records with selectors
	if len(dkimRecords) > 0 {
		fmt.Println("DKIM Records found:")
		for _, record := range dkimRecords {
			fmt.Printf("Selector: %s, Record: %s\n", record.Selector, record.Record)
		}
	} else {
		fmt.Println("No DKIM records found.")
	}
}
