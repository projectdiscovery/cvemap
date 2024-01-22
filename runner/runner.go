package runner

import (
	"bytes"
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
	sliceutil "github.com/projectdiscovery/utils/slice"
	updateutils "github.com/projectdiscovery/utils/update"
)

const xPDCPKeyHeader = "X-PDCP-Key"

var (
	baseUrl                  = "https://cve.projectdiscovery.io/api/v1"
	httpCleint               = &http.Client{}
	pdcpApiKey               = ""
	DEFAULT_FEILD_CHAR_LIMIT = 20
)

func init() {
	if os.Getenv("CVEMAP_API_URL") != "" {
		baseUrl = os.Getenv("CVEMAP_API_URL")
	}
	pch := pdcp.PDCPCredHandler{}
	if os.Getenv("PDCP_API_KEY") != "" {
		pdcpApiKey = os.Getenv("PDCP_API_KEY")
	} else if creds, err := pch.GetCreds(); err == nil {
		pdcpApiKey = creds.APIKey
	}
	if os.Getenv("DEFAULT_FEILD_CHAR_LIMIT") != "" {
		DEFAULT_FEILD_CHAR_LIMIT, _ = strconv.Atoi(os.Getenv("DEFAULT_FEILD_CHAR_LIMIT"))
	}
}

var (
	defaultHeaders = []string{"ID", "CVSS", "Severity", "EPSS", "Product", "Age", "Template"}

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

func ParseOptions() *Options {
	var options Options

	flagset := goflags.NewFlagSet()
	flagset.SetDescription(`Navigate the CVE jungle with ease.`)

	flagset.CreateGroup("config", "Config",
		flagset.BoolVar(&options.PdcpAuth, "auth", false, "configure projectdiscovery cloud (pdcp) api key"),
	)

	flagset.CreateGroup("OPTIONS", "options",
		// currently only one cve id is supported
		flagset.StringSliceVar(&options.CveIds, "id", nil, "cve to list for given id", goflags.FileCommaSeparatedStringSliceOptions),
		// flagset.StringSliceVarP(&options.cweIds, "cwe-id", "cwe", nil, "cve to list for given cwe id", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringSliceVarP(&options.Vendor, "vendor", "v", nil, "cve to list for given vendor", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringSliceVarP(&options.Product, "product", "p", nil, "cve to list for given product", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringSliceVar(&options.Eproduct, "eproduct", nil, "cves to exclude based on products", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringSliceVarP(&options.Severity, "severity", "s", nil, "cve to list for given severity", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringSliceVarP(&options.CvssScore, "cvss-score", "cs", nil, "cve to list for given cvss score", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringVarP(&options.Cpe, "cpe", "c", "", "cve to list for given cpe"),
		flagset.StringVarP(&options.EpssScore, "epss-score", "es", "", "cve to list for given epss score"),
		flagset.StringSliceVarP(&options.EpssPercentile, "epss-percentile", "ep", nil, "cve to list for given epss percentile", goflags.CommaSeparatedStringSliceOptions),
		flagset.StringVar(&options.Age, "age", "", "cve to list published by given age in days"),
		flagset.StringSliceVarP(&options.Assignees, "assignee", "a", nil, "cve to list for given publisher assignee", goflags.CommaSeparatedStringSliceOptions),
		//flagset.StringSliceVarP(&options.vulnType, "type", "vt", nil, "cve to list for given vulnerability type", goflags.CommaSeparatedStringSliceOptions),
		flagset.EnumVarP(&options.VulnStatus, "vstatus", "vs", goflags.EnumVariable(-1), strings.Replace(fmt.Sprintf("cve to list for given vulnerability status in cli output. supported: %s", allowedVstatus.String()), " ,", "", -1), allowedVstatus),
	)

	flagset.CreateGroup("update", "Update",
		flagset.CallbackVarP(GetUpdateCallback(), "update", "up", "update cvemap to latest version"),
		flagset.BoolVarP(&options.DisableUpdateCheck, "disable-update-check", "duc", false, "disable automatic cvemap update check"),
	)

	flagset.CreateGroup("FILTER", "filter",
		flagset.StringVarP(&options.Search, "search", "q", "", "search in cve data"),
		flagset.DynamicVarP(&options.Kev, "kev", "k", "true", "display cves marked as exploitable vulnerabilities by cisa"),
		flagset.DynamicVarP(&options.HasNucleiTemplate, "template", "t", "true", "display cves that has public nuclei templates"),
		flagset.DynamicVar(&options.HasPoc, "poc", "true", "display cves that has public published poc"),
		flagset.DynamicVarP(&options.Hackerone, "hackerone", "h1", "true", "display cves reported on hackerone"),
		flagset.DynamicVarP(&options.RemotlyExploitable, "remote", "re", "true", "display remotely exploitable cves (AV:N & PR:N | PR:L)"),
	)

	flagset.CreateGroup("OUTPUT", "output",
		flagset.EnumSliceVarP(&options.IncludeColumns, "field", "f", []goflags.EnumVariable{goflags.EnumVariable(-1)}, strings.Replace(fmt.Sprintf("fields to display in cli output. supported: %s", allowedHeaderString), " ,", "", -1), allowedHeader),
		flagset.EnumSliceVarP(&options.ExcludeColumns, "exclude", "fe", []goflags.EnumVariable{goflags.EnumVariable(-1)}, strings.Replace(fmt.Sprintf("fields to exclude from cli output. supported: %s", allowedHeaderString), " ,", "", -1), allowedHeader),
		flagset.BoolVarP(&options.ListId, "list-id", "lsi", false, "list only the cve ids in the output"),
		flagset.IntVarP(&options.Limit, "limit", "l", 50, "limit the number of results to display"),
		flagset.IntVar(&options.Offset, "offset", 0, "offset the results to display"),
		flagset.BoolVarP(&options.Json, "json", "j", false, "return output in json format"),
		// experimental
		flagset.BoolVarP(&options.EnablePageKeys, "enable-page-keys", "epk", false, "enable page keys to navigate results"),
	)

	flagset.CreateGroup("DEBUG", "debug",
		flagset.BoolVar(&options.Version, "version", false, "Version"),
		flagset.BoolVar(&options.Silent, "silent", false, "Silent"),
		flagset.BoolVar(&options.Verbose, "verbose", false, "Verbose"),
	)

	if err := flagset.Parse(); err != nil {
		gologger.Fatal().Msgf("Error parsing flags: %s\n", err)
	}

	if options.Limit > maxLimit {
		options.Limit = maxLimit
	}

	if fileutil.HasStdin() {
		// Read from stdin
		bin, err := io.ReadAll(os.Stdin)
		if err != nil {
			gologger.Fatal().Msgf("couldn't read stdin: %s\n", err)
		}
		options.CveIds = append(options.CveIds, strings.Split(strings.TrimSpace(string(bin)), "\n")...)
	}

	return &options
}

func Run(options Options) {

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	if options.PdcpAuth {
		AuthWithPDCP()
	}

	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}

	// Show the user the banner
	showBanner()

	if !options.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("cvemap", Version)()
		if err != nil {
			if options.Verbose {
				gologger.Error().Msgf("cvemap version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current cvemap version %v %v", Version, updateutils.GetVersionDescription(Version, latestVersion))
		}
	}

	// on default, enable kev
	if isDefaultRun(options) {
		options.Kev = "true"
	}

	parseHeaders(&options)

	if options.EnablePageKeys && len(options.CveIds) == 0 {
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

	if options.Json {
		outputJson(cvesResp.Cves)
		return cvesResp
	}

	nPages := cvesResp.TotalResults / options.Limit
	if cvesResp.TotalResults%options.Limit > 0 {
		nPages++
	}
	currentPage := (options.Offset / options.Limit) + 1
	if len(options.CveIds) == 0 && (options.Verbose || options.EnablePageKeys) {
		gologger.Print().Msgf("\n Limit: %v Page: %v TotalPages: %v TotalResults: %v\n", options.Limit, currentPage, nPages, cvesResp.TotalResults)
	}

	if options.ListId {
		for _, cve := range cvesResp.Cves {
			fmt.Println(cve.CveID)
		}
		return cvesResp
	}

	// limit headers to 10, otherwise it will be too wide
	if len(options.TableHeaders) > 10 {
		options.TableHeaders = options.TableHeaders[:10]
	}

	headers, rows := generateTableData(cvesResp.Cves, options.TableHeaders)

	renderTable(headers, rows)

	if options.EnablePageKeys {
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
				if options.Offset+options.Limit < cveResp.TotalResults {
					options.Offset += options.Limit
					clearScreen()
					cveResp = process(options)
				}
			case keyboard.KeyArrowLeft:
				if options.Offset-options.Limit >= 0 {
					options.Offset -= options.Limit
					clearScreen()
					cveResp = process(options)
				}
			}
		}
	}()

	waitGroup.Wait()
}

func parseHeaders(options *Options) {
	// construct headers
	headers := make([]string, 0)

	if options.Hackerone == "true" {
		defaultHeaders = []string{"ID", "CVSS", "Severity", "Rank", "Reports", "Product", "Age", "Template"}
	}

	options.IncludeColumns = getValidHeaders(options.IncludeColumns)
	options.ExcludeColumns = getValidHeaders(options.ExcludeColumns)

	options.IncludeColumns = append(defaultHeaders, options.IncludeColumns...)
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
	for _, header := range options.IncludeColumns {
		if !contains(options.ExcludeColumns, header) && !contains(headers, header) {
			headers = append(headers, header)
		}
	}
	options.TableHeaders = headers
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
	// t.SetColumnConfigs([]table.ColumnConfig{
	// 	{Number: 5, WidthMax: 20},
	// })
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
			row[i] = getCellValueByLimit(cve.CveID)
		case "epss":
			row[i] = getCellValueByLimit(cve.Epss.Score)
		case "cvss":
			row[i] = ""
			if cve.CvssMetrics != nil {
				row[i] = getCellValueByLimit(getLatestVersionCVSSScore(*cve.CvssMetrics))
			}
		case "severity":
			row[i] = getCellValueByLimit(strings.ToTitle(cve.Severity))
		case "cwe":
			row[i] = ""
			if len(cve.Weaknesses) > 0 {
				row[i] = getCellValueByLimit(cve.Weaknesses[0].CWEID)
			}
		case "vendor":
			row[i] = ""
			if cve.Cpe != nil {
				row[i] = getCellValueByLimit(*cve.Cpe.Vendor)
			}
		case "product":
			row[i] = ""
			if cve.Cpe != nil {
				row[i] = getCellValueByLimit(*cve.Cpe.Product)
			}
		case "vstatus":
			row[i] = getCellValueByLimit(strings.ToUpper(cve.VulnStatus))
		case "assignee":
			row[i] = ""
			if len(cve.Assignee) > 0 {
				row[i] = getCellValueByLimit(cve.Assignee)
			}
		case "age":
			row[i] = ""
			if cve.AgeInDays > 0 {
				row[i] = getCellValueByLimit(cve.AgeInDays)
			}
		case "kev":
			row[i] = getCellValueByLimit(strings.ToUpper(strconv.FormatBool(cve.IsKev)))
		case "template":
			if cve.IsTemplate {
				row[i] = "✅"
			} else {
				row[i] = "❌"
			}
		case "poc":
			row[i] = getCellValueByLimit(strings.ToUpper(strconv.FormatBool(cve.IsPoc)))
		case "rank":
			row[i] = ""
			if cve.Hackerone.Rank > 0 {
				row[i] = getCellValueByLimit(cve.Hackerone.Rank)
			}
		case "reports":
			row[i] = getCellValueByLimit(cve.Hackerone.Count)

		default:
			row[i] = ""
		}
	}
	return row
}

func getCellValueByLimit(cell interface{}) string {
	if cell == nil {
		return ""
	}
	cellValue := fmt.Sprintf("%v", cell)
	if len(cellValue) > DEFAULT_FEILD_CHAR_LIMIT {
		cellValue = cellValue[:DEFAULT_FEILD_CHAR_LIMIT] + "..."
	}
	return cellValue
}

func getCves(options Options) (*CVEBulkData, error) {
	if len(options.CveIds) > 0 {
		return getCvesByIds(options.CveIds)
	}
	if options.ListId {
		return getCvesForSpecificFields([]string{"cve_id"}, options.Limit, options.Offset)
	}
	if options.Search != "" {
		query := constructQueryByOptions(options)
		return getCvesBySearchString(query, options.Limit, options.Offset)
	}
	return getCvesByFilters(constructQueryParams(options))
}

func getCvesByFilters(encodedParams string) (*CVEBulkData, error) {
	url := fmt.Sprintf("%s/cves?%s", baseUrl, encodedParams)
	// Send an HTTP GET request
	response, err := makeGetRequest(url)
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

func getCvesByIds(cveIds []string) (*CVEBulkData, error) {
	url := fmt.Sprintf("%s/cves", baseUrl)
	// send only 100 cve ids max
	if len(cveIds) > 100 {
		cveIds = cveIds[:100]
	}
	var cveIdList CVEIdList
	cveIdList.Cves = append(cveIdList.Cves, cveIds...)
	reqData, err := json.Marshal(cveIdList)
	if err != nil {
		return nil, err
	}
	// Send an HTTP POST request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(xPDCPKeyHeader, pdcpApiKey)

	response, err := doRequest(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	// Check the response status code
	if response.StatusCode != http.StatusOK {
		return nil, errorutil.New("unexpected status code: %d", response.StatusCode)
	}
	var cvesInBulk CVEBulkData
	// Decode the JSON response into an array of CVEData structs
	err = json.NewDecoder(response.Body).Decode(&cvesInBulk)
	if err != nil {
		return nil, err
	}
	return &cvesInBulk, nil
}

func getCvesBySearchString(query string, limit, offset int) (*CVEBulkData, error) {
	u, err := url.Parse(fmt.Sprintf("%s/cves/search", baseUrl))
	if err != nil {
		return nil, err
	}
	// Construct query parameters
	q := u.Query()
	q.Set("q", query)
	q.Set("limit", fmt.Sprintf("%v", limit))
	q.Set("offset", fmt.Sprintf("%v", offset))
	u.RawQuery = q.Encode()
	response, err := makeGetRequest(u.String())
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
	response, err := makeGetRequest(url)
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

var UNAUTHORIZEDERR = errorutil.New(`unexpected status code: 401 (get your free api key from https://cloud.projectdiscovery.io)`)

func makeGetRequest(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		gologger.Fatal().Msgf("Error creating request: %s\n", err)
	}
	req.Header.Set(xPDCPKeyHeader, pdcpApiKey)
	return doRequest(req)
}

func doRequest(req *http.Request) (*http.Response, error) {
	if os.Getenv("DEBUG") == "true" {
		// dump request
		dump, err := httputil.DumpRequest(req, true)
		if err != nil {
			gologger.Fatal().Msgf("Error dumping request: %s\n", err)
		}
		fmt.Println(string(dump))
	}
	resp, err := httpCleint.Do(req)
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		var errResp ErrorMessage
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if os.Getenv("DEBUG") == "true" {
			gologger.Error().Msgf("unauthorized: %s\n", errResp.Message)
		}
		return nil, UNAUTHORIZEDERR
	}
	return resp, err
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
	if len(opts.Severity) > 0 {
		addQueryParams(queryParams, "severity", opts.Severity)
	}
	if len(opts.Assignees) > 0 {
		addQueryParams(queryParams, "assignee", opts.Assignees)
	}
	if len(opts.CvssScore) > 0 {
		var cvsKey string
		for _, cvssScore := range opts.CvssScore {
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

	if len(opts.Age) > 0 {
		ageKey := "age_in_days"
		if opts.Age[0] == '>' {
			ageKey = "age_in_days_gte"
			opts.Age = opts.Age[1:]
		} else if opts.Age[0] == '<' {
			ageKey = "age_in_days_lte"
			opts.Age = opts.Age[1:]
		}
		queryParams.Add(ageKey, opts.Age)
	}
	if len(opts.VulnStatus) > 0 {
		queryParams.Add("vuln_status", strings.ToLower(opts.VulnStatus))
	}
	if len(opts.Reference) > 0 {
		addQueryParams(queryParams, "reference", opts.Reference)
	}
	if len(opts.EpssScore) > 0 {
		epssKey := "epss.epss_score"
		if opts.EpssScore[0] == '>' {
			epssKey = "epss.epss_score_gte"
			opts.EpssScore = opts.EpssScore[1:]
		} else if opts.EpssScore[0] == '<' {
			epssKey = "epss.epss_score_lte"
			opts.EpssScore = opts.EpssScore[1:]
		}
		queryParams.Add(epssKey, opts.EpssScore)
	}
	if len(opts.EpssPercentile) > 0 {
		addQueryParams(queryParams, "epss.epss_percentile", opts.EpssPercentile)
	}
	if len(opts.CweIds) > 0 {
		addQueryParams(queryParams, "cwe_id", opts.CweIds)
	}
	if len(opts.Cpe) > 0 {
		queryParams.Add("cpe.cpe", opts.Cpe)
	}
	if len(opts.Product) > 0 {
		addQueryParams(queryParams, "cpe.product", opts.Product)
	}
	if len(opts.Eproduct) > 0 {
		addQueryParams(queryParams, "cpe.product_ne", opts.Eproduct)
	}
	if len(opts.Vendor) > 0 {
		addQueryParams(queryParams, "cpe.vendor", opts.Vendor)
	}
	if opts.Kev == "true" {
		queryParams.Add("is_exploited", "true")
	} else if opts.Kev == "false" {
		queryParams.Add("is_exploited", "false")
	}
	if opts.HasNucleiTemplate == "true" {
		queryParams.Add("is_template", "true")
	} else if opts.HasNucleiTemplate == "false" {
		queryParams.Add("is_template", "false")
	}
	if opts.HasPoc == "true" {
		queryParams.Add("is_poc", "true")
	} else if opts.HasPoc == "false" {
		queryParams.Add("is_poc", "false")
	}
	if opts.Hackerone == "true" {
		queryParams.Add("hackerone.rank_gte", "1")
		queryParams.Add("sort_asc", "hackerone.rank")
	} else {
		queryParams.Add("sort_desc", "cve_id")
	}
	if opts.RemotlyExploitable == "true" {
		queryParams.Add("is_remote", "true")
	}
	if opts.Limit > 0 {
		queryParams.Add("limit", strconv.Itoa(opts.Limit))
	}
	if opts.Offset >= 0 {
		queryParams.Add("offset", strconv.Itoa(opts.Offset))
	}
	return queryParams.Encode()
}

func constructQueryByOptions(opts Options) string {
	query := opts.Search
	if len(opts.Vendor) > 0 {
		query = fmt.Sprintf("%s cpe.vendor:%s", query, strings.Join(opts.Vendor, ","))
	}
	if len(opts.Product) > 0 {
		query = fmt.Sprintf("%s cpe.product:%s", query, strings.Join(opts.Product, ","))
	}
	if len(opts.Eproduct) > 0 {
		query = fmt.Sprintf("%s cpe.product_ne:%s", query, strings.Join(opts.Eproduct, ","))
	}
	if len(opts.Severity) > 0 {
		query = fmt.Sprintf("%s severity:%s", query, strings.Join(opts.Severity, ","))
	}
	if len(opts.CvssScore) > 0 {
		var cvsKey string
		for _, cvssScore := range opts.CvssScore {
			cvsKey = "cvss_score"
			if cvssScore[0] == '>' {
				cvsKey = "cvss_score_gte"
				cvssScore = cvssScore[1:]
			} else if cvssScore[0] == '<' {
				cvsKey = "cvss_score_lte"
				cvssScore = cvssScore[1:]
			}
			query = fmt.Sprintf("%s %s:%s", query, cvsKey, cvssScore)
		}
	}
	if len(opts.EpssScore) > 0 {
		epssKey := "epss.epss_score"
		if opts.EpssScore[0] == '>' {
			epssKey = "epss.epss_score_gte"
			opts.EpssScore = opts.EpssScore[1:]
		} else if opts.EpssScore[0] == '<' {
			epssKey = "epss.epss_score_lte"
			opts.EpssScore = opts.EpssScore[1:]
		}
		query = fmt.Sprintf("%s %s:%s", query, epssKey, opts.EpssScore)
	}
	if len(opts.Cpe) > 0 {
		query = fmt.Sprintf(`%s cpe.cpe:"%s"`, query, opts.Cpe)
	}
	if len(opts.EpssPercentile) > 0 {
		query = fmt.Sprintf("%s epss.epss_percentile:%s", query, strings.Join(opts.EpssPercentile, ","))
	}
	if len(opts.CweIds) > 0 {
		query = fmt.Sprintf("%s cwe_id:%s", query, strings.Join(opts.CweIds, ","))
	}
	if len(opts.Age) > 0 {
		ageKey := "age_in_days"
		if opts.Age[0] == '>' {
			ageKey = "age_in_days_gte"
			opts.Age = opts.Age[1:]
		} else if opts.Age[0] == '<' {
			ageKey = "age_in_days_lte"
			opts.Age = opts.Age[1:]
		}
		query = fmt.Sprintf("%s %s:%s", query, ageKey, opts.Age)
	}
	if len(opts.Assignees) > 0 {
		query = fmt.Sprintf("%s assignee:%s", query, strings.Join(opts.Assignees, ","))
	}
	if len(opts.VulnStatus) > 0 {
		query = fmt.Sprintf("%s vuln_status:%s", query, strings.ToLower(opts.VulnStatus))
	}
	if opts.Kev == "true" {
		query = fmt.Sprintf("%s is_exploited:true", query)
	} else if opts.Kev == "false" {
		query = fmt.Sprintf("%s is_exploited:false", query)
	}
	if opts.HasNucleiTemplate == "true" {
		query = fmt.Sprintf("%s is_template:true", query)
	} else if opts.HasNucleiTemplate == "false" {
		query = fmt.Sprintf("%s is_template:false", query)
	}
	if opts.HasPoc == "true" {
		query = fmt.Sprintf("%s is_poc:true", query)
	} else if opts.HasPoc == "false" {
		query = fmt.Sprintf("%s is_poc:false", query)
	}
	if opts.Hackerone == "true" {
		query = fmt.Sprintf("%s hackerone.rank_gte:1 sort_asc:hackerone.rank", query)
	} else {
		query = fmt.Sprintf("%s sort_desc:cve_id", query)
	}
	if opts.RemotlyExploitable == "true" {
		query = fmt.Sprintf("%s is_remote:true", query)
	}

	parts := strings.Split(query, " ")
	parts = sliceutil.PruneEmptyStrings(parts)
	parts = sliceutil.Dedupe(parts)
	query = strings.Join(parts, " ")
	if os.Getenv("DEBUG") == "true" {
		fmt.Println("constructed query: ", query)
	}
	return query
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
