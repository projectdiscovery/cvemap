package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/projectdiscovery/goflags"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

var (
	defaultHeaders = []string{"CVE-ID", "EPSS", "CVSS", "Severity", "CWE", "Application", "Vendor", "Status"}
	maxLimit       = 300
)

func main() {
	var options Options

	flagset := goflags.NewFlagSet()
	flagset.SetDescription(`Navigate the CVE jungle with ease.`)

	flagset.CreateGroup("Options", "options",
		// flagset.StringSliceVarP(&options.cveIds, "cve-id", "id", nil, "cve to list for given id", goflags.StringSliceOptions),
		// flagset.StringSliceVarP(&options.cweIds, "cwe-id", "cwe", nil, "cve to list for given cwe id", goflags.StringSliceOptions),
		// flagset.StringSliceVarP(&options.vendor, "vendor", "v", nil, "cve to list for given vendor", goflags.StringSliceOptions),
		// flagset.StringSliceVarP(&options.product, "product", "p", nil, "cve to list for given product", goflags.StringSliceOptions),
		// flagset.StringSliceVarP(&options.severity, "severity", "s", nil, "cve to list for given severity", goflags.StringSliceOptions),
		// flagset.StringSliceVarP(&options.assignees, "assignee", "a", nil, "cve to list for given assignee", goflags.StringSliceOptions),
		// flagset.StringVarP(&options.cpe, "cpe", "c", "", "cve to list for given cpe"),

		flagset.StringSliceVarP(&options.includeColumns, "field", "f", defaultHeaders, "field to display in cli output (supported: product)", goflags.StringSliceOptions),
		flagset.StringSliceVarP(&options.excludeColumns, "exclude", "e", nil, "field to exclude from cli output", goflags.StringSliceOptions),
		flagset.IntVarP(&options.limit, "limit", "l", 100, "limit the number of results to display"),
	)

	if err := flagset.Parse(); err != nil {
		log.Fatal(err)
	}
	if options.limit > maxLimit {
		options.limit = maxLimit
	}
	// construct headers
	headers := make([]string, 0)
	options.includeColumns = append(defaultHeaders, options.includeColumns...)
	// convert all headers to lowercase
	for i, eh := range options.excludeColumns {
		options.excludeColumns[i] = strings.ToLower(eh)
	}
	for _, header := range options.includeColumns {
		if !sliceutil.Contains(options.excludeColumns, strings.ToLower(header)) {
			headers = append(headers, header)
		}
	}
	headers = sliceutil.Dedupe(headers)

	// Example usage of getCvesByAssignee
	assignee := "zdi-disclosures@trendmicro.com"
	cvesByAssignee, err := getCvesByAssignee(assignee)
	if err != nil {
		fmt.Println("Error getting CVEs by assignee:", err)
		return
	}
	fmt.Println("Found", len(cvesByAssignee.Cves), "CVEs by assignee", assignee)
	headers, rows := generateTableData(cvesByAssignee.Cves, headers)
	if options.limit > len(rows) {
		options.limit = len(rows)
	}
	fmt.Println("Showing", options.limit, "CVEs")
	// Render the table
	renderTable(headers, rows[:options.limit])
}

func renderTable(headers []string, rows [][]interface{}) {
	// Create a table for displaying CVE data with the specified headers
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)

	// Append the specified headers to the table
	headerRow := make([]interface{}, len(headers))
	for i, header := range headers {
		headerRow[i] = header
	}
	t.AppendHeader(headerRow)

	// Loop through the retrieved CVE data and add rows to the table
	for _, row := range rows {
		t.AppendRow(row)
	}

	// Set table options and render it
	t.SetStyle(table.StyleRounded)
	t.Render()
}

func generateTableData(cves []CVEData, headers []string) ([]string, [][]interface{}) {
	dataRows := make([][]interface{}, len(cves))
	for r, cve := range cves {
		dataRows[r] = getRow(headers, cve)
	}
	return headers, dataRows
}

func getRow(headers []string, cve CVEData) []interface{} {
	row := make([]interface{}, len(headers))
	for i, header := range headers {
		switch strings.ToLower(header) {
		case "cve-id":
			row[i] = cve.CveID
		case "epss":
			row[i] = cve.Epss.Score
		case "cvss":
			row[i] = getLatestVersionCVSSScore(*cve.CvssMetrics)
		case "severity":
			row[i] = strings.ToTitle(cve.Severity)
		case "cwe":
			row[i] = ""
			if len(cve.Weaknesses) > 0 {
				row[i] = cve.Weaknesses[0].CWEID
			}
		case "application":
			row[i] = ""
			if application, err := extractApplicationFromCPE(*cve.Cpe.Cpe); err == nil {
				row[i] = application
			}
		case "vendor":
			row[i] = *cve.Cpe.Vendor
		case "product":
			row[i] = *cve.Cpe.Product
		case "status":
			row[i] = strings.ToUpper(cve.VulnStatus)
		default:
			row[i] = ""
		}
	}
	return row
}

func getCveData(cveID string) (*CVEData, error) {
	// Define the URL for the CVE API
	cveURL := fmt.Sprintf("https://cve-dev.nuclei.sh/cves/%s", cveID)

	// Send an HTTP GET request
	response, err := http.Get(cveURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Check the response status code
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	// Create a variable to store the response data
	var cve CVEData

	// Decode the JSON response into the CVEData struct
	err = json.NewDecoder(response.Body).Decode(&cve)
	if err != nil {
		return nil, err
	}

	return &cve, nil
}

func getCvesByAssignee(assignee string) (*CVEBulkData, error) {
	// Define the URL for the CVE API with the assignee query parameter
	cveURL := "https://cve-dev.nuclei.sh/cves"
	queryParams := url.Values{}
	queryParams.Add("assignee", assignee)
	cveURL += "?" + queryParams.Encode()
	// Send an HTTP GET request
	response, err := http.Get(cveURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	// Check the response status code
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}
	// Create a variable to store the response data
	var cvesInBulk CVEBulkData
	// Decode the JSON response into an array of CVEData structs
	err = json.NewDecoder(response.Body).Decode(&cvesInBulk)
	if err != nil {
		return nil, err
	}

	return &cvesInBulk, nil
}
