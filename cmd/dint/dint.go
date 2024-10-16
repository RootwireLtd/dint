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
	"strings"
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
	spfTestResults, spfSummary := spf_analyser.CheckSPFRecord(spfRecords)

	// Fetch DMARC Records
	dmarcDomain := "_dmarc." + *domain
	dmarcRecords, err := dns_resolver.LookupDNSRecords("TXT", dmarcDomain)
	if err != nil {
		log.Fatalf("Error fetching DMARC records: %v", err)
	}
	dmarcTestResults, dmarcSummary := dmarc_analyser.CheckDMARCRecord(dmarcRecords)

	// Fetch DKIM Records
	dkimRecords, err := dns_resolver.LookupDKIMRecords(*domain)
	if err != nil {
		log.Fatalf("Error fetching DKIM records: %v", err)
	}
	var dkimPresent = len(dkimRecords) > 0

	// Display Results

	// If summary flag is present, display the summary table
	if *showSummary {
		DisplaySummary(*domain, spfTestResults.AllTestsPassed, dmarcTestResults.AllTestsPassed, dkimPresent)
		return
	}

	fmt.Printf("MX records: %v\n", mxRecords)

	fmt.Printf("SPF records: %v\n", spfRecords)
	fmt.Println(spfSummary)

	fmt.Println(dmarcSummary)

	// Output DKIM records with selectors
	if len(dkimRecords) > 0 {
		fmt.Println("DKIM Records found:")
		for _, record := range dkimRecords {
			fmt.Printf("Selector: %s, Record: %s\n", record.Selector, record.Record)
		}
	} else {
		fmt.Println("No DKIM records found.")
	}

	// Summarize results
	fmt.Println("\nTest Results:")
	fmt.Printf("1. SPF Record is present: %v\n", spfTestResults)
	fmt.Printf("2. SPF Record is a single record: %v\n", len(spfRecords) == 1)
	fmt.Printf("3. SPF Record has a Hard Fail Qualifier: %v\n", strings.Contains(spfSummary, "Hard fail qualifier: true"))
	fmt.Printf("4. DMARC Record is present: %v\n", dmarcTestResults.RecordFound)
	fmt.Printf("5. DMARC Record is a single record: %v\n", dmarcTestResults.SingleRecord)
	fmt.Printf("6. DMARC Policy and Subdomain Policy is reject: %v\n", dmarcTestResults.PolicyReject && dmarcTestResults.SubdomainPolicyReject)
	fmt.Printf("7. DKIM Record is present: %v\n", dkimPresent)
}

//TIP See GoLand help at <a href="https://www.jetbrains.com/help/go/">jetbrains.com/help/go/</a>.
// Also, you can try interactive lessons for GoLand by selecting 'Help | Learn IDE Features' from the main menu.
