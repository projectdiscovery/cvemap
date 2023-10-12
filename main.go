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
	cveURL         = "https://cve-dev.nuclei.sh/cves"
	defaultHeaders = []string{"CVE-ID", "EPSS", "CVSS", "Severity", "CWE", "Application", "Vendor", "Status"}
	maxLimit       = 300
)

func main() {
	var options Options

	flagset := goflags.NewFlagSet()
	flagset.SetDescription(`Navigate the CVE jungle with ease.`)

	flagset.CreateGroup("Options", "options",
		flagset.StringSliceVarP(&options.cveIds, "cve-id", "id", nil, "cve to list for given id", goflags.CommaSeparatedStringSliceOptions),
		// flagset.StringSliceVarP(&options.cweIds, "cwe-id", "cwe", nil, "cve to list for given cwe id", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringSliceVarP(&options.vendor, "vendor", "v", nil, "cve to list for given vendor", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringSliceVarP(&options.product, "product", "p", nil, "cve to list for given product", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringSliceVarP(&options.severity, "severity", "s", nil, "cve to list for given severity", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringSliceVarP(&options.cvssScore, "cvss-score", "cs", nil, "cve to list for given cvss score", goflags.CommaSeparatedStringSliceOptions),
		// flagset.StringSliceVarP(&options.cvssMetrics, "cvss-metrics", "cm", nil, "cve to list for given cvss metrics", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringVarP(&options.cpe, "cpe", "c", "", "cve to list for given cpe"),
		flagset.StringSliceVarP(&options.epssScore, "epss-score", "es", nil, "cve to list for given epss score", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringSliceVarP(&options.epssPercentile, "epss-percentile", "ep", nil, "cve to list for given epss percentile", goflags.CommaSeparatedStringSliceOptions),
		//flagset.StringSliceVarP(&options.year, "year", "y", nil, "cve to list for given year", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringSliceVarP(&options.assignees, "assignee", "a", nil, " cve to list for given publisher assignee", goflags.CommaSeparatedStringSliceOptions),
		//flagset.StringSliceVarP(&options.vulnType, "type", "t", nil, "cve to list for given vulnerability type", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringVarP(&options.vulnStatus, "status", "st", "", "cve to list for given vulnerability status in cli output"),
		flagset.StringSliceVarP(&options.reference, "reference", "r", nil, "cve to list for given reference", goflags.CommaSeparatedStringSliceOptions),
		flagset.BoolVarP(&options.kev, "kev", "k", false, "display cve for known exploitable vulnerabilities by cisa"),
		//flagset.BoolVarP(&options.trending, "trending", "tr", false, "display trending cve by hackerone cve discovery"),
		flagset.BoolVarP(&options.hasNucleiTemplate, "nuclei-template", "nt", false, "display cve having nuclei templates"),
		flagset.StringSliceVarP(&options.includeColumns, "field", "f", defaultHeaders, "field to display in cli output (supported: product)", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringSliceVarP(&options.excludeColumns, "exclude", "e", nil, "field to exclude from cli output", goflags.CommaSeparatedStringSliceOptions),
		flagset.IntVarP(&options.limit, "limit", "l", 100, "limit the number of results to display"),
		flagset.BoolVarP(&options.json, "json", "j", false, "return output in json format"),
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

	// Get all CVEs for the given filters
	cvesResp, err := getCves(constructQueryParams(options))
	if err != nil {
		fmt.Println("Error getting CVEs by assignee:", err)
		return
	}

	if options.json {
		outputJson(cvesResp.Cves)
		return
	}

	//fmt.Printf("Found %d, loaded %d CVEs\n", cvesResp.ResultCount, len(cvesResp.Cves))
	headers, rows := generateTableData(cvesResp.Cves, headers)
	if options.limit > len(rows) {
		options.limit = len(rows)
	}
	//fmt.Println("Showing", options.limit, "CVEs")
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
		case "vendor":
			row[i] = ""
			if cve.Cpe != nil {
				row[i] = *cve.Cpe.Vendor
			}
		case "product":
			row[i] = ""
			if cve.Cpe != nil {
				row[i] = *cve.Cpe.Product
			}
		case "status":
			row[i] = strings.ToUpper(cve.VulnStatus)
		default:
			row[i] = ""
		}
	}
	return row
}

func getCves(encodedParams string) (*CVEBulkData, error) {
	url := fmt.Sprintf("%s?%s", cveURL, encodedParams)
	//fmt.Println("URL:", url)
	// Send an HTTP GET request
	response, err := http.Get(url)
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

func outputJson(cve []CVEData) {
	json, err := json.MarshalIndent(cve, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling json:", err)
		return
	}
	fmt.Println(string(json))
}

func constructQueryParams(opts Options) string {
	queryParams := &url.Values{}
	if len(opts.cveIds) > 0 {
		addQueryParams(queryParams, "cve_id", opts.cveIds)
	}
	if len(opts.severity) > 0 {
		addQueryParams(queryParams, "severity", opts.severity)
	}
	if len(opts.assignees) > 0 {
		addQueryParams(queryParams, "assignee", opts.assignees)
	}
	if len(opts.cvssScore) > 0 {
		cvsKey := "cvss_score"
		for _, cvssScore := range opts.cvssScore {
			if cvssScore[0] == '>' {
				cvsKey = "cvss_score_gte"
			}
			if cvssScore[0] == '<' {
				cvsKey = "cvss_score_lte"
			}
			queryParams.Add(cvsKey, cvssScore[1:])
		}
	}
	if opts.kev {
		queryParams.Add("is_exploited", "true")
	}
	// if opts.trending {
	// }
	if opts.hasNucleiTemplate {
		queryParams.Add("is_template", "true")
	}
	if len(opts.vulnStatus) > 0 {
		queryParams.Add("vuln_status", strings.ToLower(opts.vulnStatus))
	}
	if len(opts.reference) > 0 {
		addQueryParams(queryParams, "reference", opts.reference)
	}
	if len(opts.epssScore) > 0 {
		addQueryParams(queryParams, "epss.epss_score", opts.epssScore)
	}
	if len(opts.epssPercentile) > 0 {
		addQueryParams(queryParams, "epss.epss_percentile", opts.epssPercentile)
	}
	if len(opts.cweIds) > 0 {
		addQueryParams(queryParams, "cwe_id", opts.cweIds)
	}
	if len(opts.cpe) > 0 {
		queryParams.Add("cpe.cpe", opts.cpe)
	}
	if len(opts.product) > 0 {
		addQueryParams(queryParams, "cpe.product", opts.product)
	}
	if len(opts.vendor) > 0 {
		addQueryParams(queryParams, "cpe.vendor", opts.vendor)
	}
	return queryParams.Encode()
}

func addQueryParams(queryParams *url.Values, key string, values []string) *url.Values {
	if len(values) > 0 {
		for _, value := range values {
			queryParams.Add(key, value)
		}
	}
	return queryParams
}
