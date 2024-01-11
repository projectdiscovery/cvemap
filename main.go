package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/eiannone/keyboard"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/utils/auth/pdcp"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	updateutils "github.com/projectdiscovery/utils/update"
)

const xPDCPKeyHeader = "X-PDCP-Key"

var (
	baseUrl    = "https://cve.projectdiscovery.io/api/v1"
	httpCleint = &http.Client{}
	pdcpApiKey = ""
)

func init() {
	pch := pdcp.PDCPCredHandler{}
	if creds, err := pch.GetCreds(); err == nil {
		pdcpApiKey = creds.APIKey
	}
}

var (
	defaultHeaders = []string{"ID", "CVSS", "Severity", "EPSS", "Product", "Template"}

	headerMap = map[string]string{
		"id":       "id",
		"cwe":      "cwe",
		"epss":     "epss",
		"cvss":     "cvss",
		"severity": "severity",
		"vendor":   "vendor",
		"product":  "product",
		"vstatus":  "vstatus",
		"assignee": "assignee",
		"age":      "age",
		"kev":      "kev",
		"template": "template",
		"poc":      "poc",
		"rank":     "rank",
		"reports":  "reports",
	}

	allowedHeader = goflags.AllowdTypes{
		"":         goflags.EnumVariable(-1),
		"cwe":      goflags.EnumVariable(0),
		"epss":     goflags.EnumVariable(1),
		"product":  goflags.EnumVariable(2),
		"vendor":   goflags.EnumVariable(3),
		"vstatus":  goflags.EnumVariable(4),
		"assignee": goflags.EnumVariable(5),
		"age":      goflags.EnumVariable(6),
		"kev":      goflags.EnumVariable(7),
		"template": goflags.EnumVariable(8),
		"poc":      goflags.EnumVariable(9),
	}
	allowedHeaderString = allowedHeader.String()

	allowedVstatus = goflags.AllowdTypes{
		"":            goflags.EnumVariable(-1),
		"new":         goflags.EnumVariable(0),
		"confirmed":   goflags.EnumVariable(1),
		"unconfirmed": goflags.EnumVariable(2),
		"modified":    goflags.EnumVariable(3),
		"rejected":    goflags.EnumVariable(4),
		"unknown":     goflags.EnumVariable(5),
	}

	maxLimit = 300
)

func main() {
	var options Options
	var pdcpauth bool

	flagset := goflags.NewFlagSet()
	flagset.SetDescription(`Navigate the CVE jungle with ease.`)

	flagset.CreateGroup("config", "Config",
		flagset.BoolVar(&pdcpauth, "auth", false, "configure projectdiscovery cloud (pdcp) api key"),
	)

	flagset.CreateGroup("OPTIONS", "options",
		flagset.StringSliceVar(&options.cveIds, "id", nil, "cve to list for given id", goflags.CommaSeparatedStringSliceOptions),
		// flagset.StringSliceVarP(&options.cweIds, "cwe-id", "cwe", nil, "cve to list for given cwe id", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringSliceVarP(&options.vendor, "vendor", "v", nil, "cve to list for given vendor", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringSliceVarP(&options.product, "product", "p", nil, "cve to list for given product", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringSliceVar(&options.eproduct, "eproduct", nil, "cves to exclude based on products", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringSliceVarP(&options.severity, "severity", "s", nil, "cve to list for given severity", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringSliceVarP(&options.cvssScore, "cvss-score", "cs", nil, "cve to list for given cvss score", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringVarP(&options.cpe, "cpe", "c", "", "cve to list for given cpe"),
		flagset.StringVarP(&options.epssScore, "epss-score", "es", "", "cve to list for given epss score"),
		flagset.StringSliceVarP(&options.epssPercentile, "epss-percentile", "ep", nil, "cve to list for given epss percentile", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringVar(&options.age, "age", "", "cve to list published by given age in days"),
		flagset.StringSliceVarP(&options.assignees, "assignee", "a", nil, "cve to list for given publisher assignee", goflags.CommaSeparatedStringSliceOptions),
		//flagset.StringSliceVarP(&options.vulnType, "type", "vt", nil, "cve to list for given vulnerability type", goflags.CommaSeparatedStringSliceOptions),
		flagset.EnumVarP(&options.vulnStatus, "vstatus", "vs", goflags.EnumVariable(-1), strings.Replace(fmt.Sprintf("cve to list for given vulnerability status in cli output. supported: %s", allowedVstatus.String()), " ,", "", -1), allowedVstatus),
	)

	flagset.CreateGroup("update", "Update",
		flagset.CallbackVarP(GetUpdateCallback(), "update", "up", "update cvemap to latest version"),
		flagset.BoolVarP(&options.disableUpdateCheck, "disable-update-check", "duc", false, "disable automatic cvemap update check"),
	)

	flagset.CreateGroup("FILTER", "filter",
		flagset.StringVarP(&options.search, "search", "q", "", "search in cve data"),
		flagset.DynamicVarP(&options.kev, "kev", "k", "true", "display cves marked as exploitable vulnerabilities by cisa"),
		flagset.DynamicVarP(&options.hasNucleiTemplate, "template", "t", "true", "display cves that has public nuclei templates"),
		flagset.DynamicVar(&options.hasPoc, "poc", "true", "display cves that has public published poc"),
		flagset.DynamicVarP(&options.hackerone, "hackerone", "h1", "true", "display cves reported on hackerone"),
	)

	flagset.CreateGroup("OUTPUT", "output",
		flagset.EnumSliceVarP(&options.includeColumns, "field", "f", []goflags.EnumVariable{goflags.EnumVariable(-1)}, strings.Replace(fmt.Sprintf("fields to display in cli output. supported: %s", allowedHeaderString), " ,", "", -1), allowedHeader),
		flagset.EnumSliceVarP(&options.excludeColumns, "exclude", "fe", []goflags.EnumVariable{goflags.EnumVariable(-1)}, strings.Replace(fmt.Sprintf("fields to exclude from cli output. supported: %s", allowedHeaderString), " ,", "", -1), allowedHeader),
		flagset.BoolVarP(&options.listId, "list-id", "lid", false, "list only the cve ids in the output"),
		flagset.IntVarP(&options.limit, "limit", "l", 50, "limit the number of results to display"),
		flagset.IntVar(&options.offset, "offset", 0, "offset the results to display"),
		flagset.BoolVarP(&options.json, "json", "j", false, "return output in json format"),
		// experimental
		flagset.BoolVarP(&options.enablePageKeys, "enable-page-keys", "epk", false, "enable page keys to navigate results"),
	)

	flagset.CreateGroup("DEBUG", "debug",
		flagset.BoolVar(&options.version, "version", false, "Version"),
		flagset.BoolVar(&options.silent, "silent", false, "Silent"),
		flagset.BoolVar(&options.verbose, "verbose", false, "Verbose"),
	)

	if err := flagset.Parse(); err != nil {
		gologger.Fatal().Msgf("Error parsing flags: %s\n", err)
	}

	if options.version {
		gologger.Info().Msgf("Current Version: %s\n", version)
		os.Exit(0)
	}

	if options.silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else if options.verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}

	if pdcpauth {
		AuthWithPDCP()
	}

	// Show the user the banner
	showBanner()

	if !options.disableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("cvemap", version)()
		if err != nil {
			if options.verbose {
				gologger.Error().Msgf("cvemap version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current cvemap version %v %v", version, updateutils.GetVersionDescription(version, latestVersion))
		}
	}

	if options.limit > maxLimit {
		options.limit = maxLimit
	}

	if fileutil.HasStdin() {
		// Read from stdin
		bin, err := io.ReadAll(os.Stdin)
		if err != nil {
			gologger.Fatal().Msgf("couldn't read stdin: %s\n", err)
		}
		options.cveIds = append(options.cveIds, strings.Split(strings.TrimSpace(string(bin)), "\n")...)
	}

	// on default, enable kev
	if isDefaultRun(options) {
		options.kev = "true"
	}

	processHeaders(&options)
	if options.enablePageKeys {
		processWithPageKeyEvents(options)
	} else {
		_ = process(options)
	}
}

func process(options Options) *CVEBulkData {
	var cvesResp *CVEBulkData
	var err error
	cvesResp, err = getCves(options)
	if err != nil {
		gologger.Fatal().Msgf("Error getting CVEs: %s\n", err)
		return nil
	}

	if options.json {
		outputJson(cvesResp.Cves)
		return cvesResp
	}

	nPages := cvesResp.TotalResults / options.limit
	if cvesResp.TotalResults%options.limit > 0 {
		nPages++
	}
	currentPage := (options.offset / options.limit) + 1
	if options.verbose || options.enablePageKeys {
		gologger.Print().Msgf("\n Limit: %v Page: %v TotalPages: %v TotalResults: %v\n", options.limit, currentPage, nPages, cvesResp.TotalResults)
	}

	// limit headers to 10, otherwise it will be too wide
	if len(options.tableHeaders) > 10 {
		options.tableHeaders = options.tableHeaders[:10]
	}

	headers, rows := generateTableData(cvesResp.Cves, options.tableHeaders)

	renderTable(headers, rows)

	if options.enablePageKeys {
		pageString := ""
		if currentPage > 1 {
			pageString += " ◀     "
		}
		if currentPage < nPages {
			pageString += "     ▶"
		}
		fmt.Print(pageString)
	}
	return cvesResp
}

func processWithPageKeyEvents(options Options) {
	cveResp := process(options)

	// wait for user input
	err := keyboard.Open()
	if err != nil {
		panic(err)
	}
	defer keyboard.Close()
	waitGroup := sync.WaitGroup{}
	waitGroup.Add(1)

	go func() {
		for {
			_, key, err := keyboard.GetKey()
			if err != nil {
				panic(err)
			}

			if key == keyboard.KeyEsc || key == keyboard.KeyCtrlC {
				waitGroup.Done()
				break
			}

			switch key {
			case keyboard.KeyArrowRight:
				if options.offset+options.limit < cveResp.TotalResults {
					options.offset += options.limit
					clearScreen()
					cveResp = process(options)
				}
			case keyboard.KeyArrowLeft:
				if options.offset-options.limit >= 0 {
					options.offset -= options.limit
					clearScreen()
					cveResp = process(options)
				}
			}
		}
	}()

	waitGroup.Wait()
}

func processHeaders(options *Options) {
	// construct headers
	headers := make([]string, 0)

	if options.hackerone == "true" {
		defaultHeaders = []string{"ID", "CVSS", "Severity", "Rank", "Reports", "Product", "Template"}
	}

	options.includeColumns = getValidHeaders(options.includeColumns)
	options.excludeColumns = getValidHeaders(options.excludeColumns)

	options.includeColumns = append(defaultHeaders, options.includeColumns...)
	// case insensitive contains check
	contains := func(array []string, element string) bool {
		for _, e := range array {
			if strings.EqualFold(e, element) {
				return true
			}
		}
		return false
	}
	// add headers to display
	for _, header := range options.includeColumns {
		if !contains(options.excludeColumns, header) && !contains(headers, header) {
			headers = append(headers, header)
		}
	}
	options.tableHeaders = headers
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
		case "id":
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
		case "vstatus":
			row[i] = strings.ToUpper(cve.VulnStatus)
		case "assignee":
			row[i] = ""
			if len(cve.Assignee) > 0 {
				row[i] = cve.Assignee
			}
		case "age":
			row[i] = ""
			if cve.AgeInDays > 0 {
				row[i] = cve.AgeInDays
			}
		case "kev":
			row[i] = strings.ToUpper(strconv.FormatBool(cve.IsKev))
		case "template":
			if cve.IsTemplate {
				row[i] = "✅"
			} else {
				row[i] = "❌"
			}
		case "poc":
			row[i] = strings.ToUpper(strconv.FormatBool(cve.IsPoc))
		case "rank":
			row[i] = ""
			if cve.Hackerone.Rank > 0 {
				row[i] = cve.Hackerone.Rank
			}
		case "reports":
			row[i] = cve.Hackerone.Count

		default:
			row[i] = ""
		}
	}
	return row
}

func getCves(options Options) (*CVEBulkData, error) {
	if options.listId {
		return getCvesForSpecificFields([]string{"cve_id"}, options.limit, options.offset)
	}
	if options.search != "" {
		return getCvesBySearchString(options.search, options.limit, options.offset)
	}
	return getCvesByFilters(constructQueryParams(options))
}

func getCvesByFilters(encodedParams string) (*CVEBulkData, error) {
	url := fmt.Sprintf("%s/cves?%s", baseUrl, encodedParams)
	// Send an HTTP GET request
	response, err := makeRequest(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	// Check the response status code
	if response.StatusCode != http.StatusOK {
		return nil, errorutil.New("unexpected status code: %d", response.StatusCode)
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

func getCvesBySearchString(query string, limit, offset int) (*CVEBulkData, error) {
	url := fmt.Sprintf("%s/cves/search?q=%s&limit=%v&offset=%v", baseUrl, query, limit, offset)
	// Send an HTTP GET request
	response, err := makeRequest(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	// Check the response status code
	if response.StatusCode != http.StatusOK {
		return nil, errorutil.New("unexpected status code: %d", response.StatusCode)
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

// all the root level fields are supported
func getCvesForSpecificFields(fields []string, limit, offset int) (*CVEBulkData, error) {
	url := fmt.Sprintf("%s/cves?fields=%s&limit=%v&offset=%v", baseUrl, strings.Join(fields, ","), limit, offset)
	// Send an HTTP GET request
	response, err := makeRequest(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	// Check the response status code
	if response.StatusCode != http.StatusOK {
		return nil, errorutil.New("unexpected status code: %d", response.StatusCode)
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

func makeRequest(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		gologger.Fatal().Msgf("Error creating request: %s\n", err)
	}
	req.Header.Set(xPDCPKeyHeader, pdcpApiKey)
	if os.Getenv("DEBUG") == "true" {
		// dump request
		dump, err := httputil.DumpRequest(req, true)
		if err != nil {
			gologger.Fatal().Msgf("Error dumping request: %s\n", err)
		}
		fmt.Println(string(dump))
	}
	return httpCleint.Do(req)
}

func outputJson(cve []CVEData) {
	json, err := json.MarshalIndent(cve, "", "  ")
	if err != nil {
		gologger.Error().Msgf("Error marshalling json: %s\n", err)
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
				cvssScore = cvssScore[1:]
			} else if cvssScore[0] == '<' {
				cvsKey = "cvss_score_lte"
				cvssScore = cvssScore[1:]
			}
			queryParams.Add(cvsKey, cvssScore)
		}
	}

	if len(opts.age) > 0 {
		ageKey := "age_in_days"
		if opts.age[0] == '>' {
			ageKey = "age_in_days_gte"
			opts.age = opts.age[1:]
		} else if opts.age[0] == '<' {
			ageKey = "age_in_days_lte"
			opts.age = opts.age[1:]
		}
		queryParams.Add(ageKey, opts.age)
	}
	if opts.kev == "true" {
		queryParams.Add("is_exploited", "true")
	} else if opts.kev == "false" {
		queryParams.Add("is_exploited", "false")
	}
	if opts.hasNucleiTemplate == "true" {
		queryParams.Add("is_template", "true")
	} else if opts.hasNucleiTemplate == "false" {
		queryParams.Add("is_template", "false")
	}
	if opts.hasPoc == "true" {
		queryParams.Add("is_poc", "true")
	} else if opts.hasPoc == "false" {
		queryParams.Add("is_poc", "false")
	}
	if len(opts.vulnStatus) > 0 {
		queryParams.Add("vuln_status", strings.ToLower(opts.vulnStatus))
	}
	if len(opts.reference) > 0 {
		addQueryParams(queryParams, "reference", opts.reference)
	}
	if len(opts.epssScore) > 0 {
		epssKey := "epss.epss_score"
		if opts.epssScore[0] == '>' {
			epssKey = "epss.epss_score_gte"
			opts.epssScore = opts.epssScore[1:]
		} else if opts.epssScore[0] == '<' {
			epssKey = "epss.epss_score_lte"
			opts.epssScore = opts.epssScore[1:]
		}
		queryParams.Add(epssKey, opts.epssScore)
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
	if len(opts.eproduct) > 0 {
		addQueryParams(queryParams, "cpe.product_ne", opts.eproduct)
	}
	if len(opts.vendor) > 0 {
		addQueryParams(queryParams, "cpe.vendor", opts.vendor)
	}
	if opts.hackerone == "true" {
		queryParams.Add("hackerone.rank_gte", "1")
		queryParams.Add("sort_asc", "hackerone.rank")
	} else {
		queryParams.Add("sort_desc", "cve_id")
	}
	if opts.limit > 0 {
		queryParams.Add("limit", strconv.Itoa(opts.limit))
	}
	if opts.offset >= 0 {
		queryParams.Add("offset", strconv.Itoa(opts.offset))
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

func getValidHeaders(keys []string) []string {
	headers := []string{}
	for _, hk := range keys {
		if v, ok := headerMap[hk]; ok {
			headers = append(headers, v)
		}
	}
	return headers
}
