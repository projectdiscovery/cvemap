package runner

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/eiannone/keyboard"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/projectdiscovery/cvemap/pkg/service"
	"github.com/projectdiscovery/cvemap/pkg/types"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/projectdiscovery/utils/env"
	fileutil "github.com/projectdiscovery/utils/file"
	sliceutil "github.com/projectdiscovery/utils/slice"
	updateutils "github.com/projectdiscovery/utils/update"
	urlutil "github.com/projectdiscovery/utils/url"
)

var (
	BaseUrl                  = env.GetEnvOrDefault("CVEMAP_API_URL", "https://cve.projectdiscovery.io/api/v1")
	PDCPApiKey               = ""
	DEFAULT_FEILD_CHAR_LIMIT = env.GetEnvOrDefault("DEFAULT_FEILD_CHAR_LIMIT", 20)
)

func init() {
	pch := pdcp.PDCPCredHandler{}
	if os.Getenv("PDCP_API_KEY") != "" {
		PDCPApiKey = os.Getenv("PDCP_API_KEY")
	} else if creds, err := pch.GetCreds(); err == nil {
		PDCPApiKey = creds.APIKey
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
		flagset.DynamicVar(&options.PdcpAuth, "auth", "true", "configure projectdiscovery cloud (pdcp) api key"),
	)

	flagset.CreateGroup("OPTIONS", "options",
		// currently only one cve id is supported
		flagset.StringSliceVar(&options.CveIds, "id", nil, "cve to list for given id", goflags.FileCommaSeparatedStringSliceOptions),
		flagset.StringSliceVarP(&options.CweIds, "cwe-id", "cwe", nil, "cve to list for given cwe id", goflags.CommaSeparatedStringSliceOptions),
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
		flagset.StringVarP(&options.Output, "output", "o", "", "output to file"),
		// experimental
		flagset.BoolVarP(&options.EnablePageKeys, "enable-page-keys", "epk", false, "enable page keys to navigate results"),
	)

	flagset.CreateGroup("DEBUG", "debug",
		flagset.BoolVar(&options.Version, "version", false, "Version"),
		flagset.BoolVar(&options.Silent, "silent", false, "Silent"),
		flagset.BoolVar(&options.Verbose, "verbose", false, "Verbose"),
		flagset.BoolVar(&options.Debug, "debug", false, "Debug"),
		flagset.BoolVarP(&options.HealthCheck, "health-check", "hc", false, "run diagnostic check up"),
	)

	if err := flagset.Parse(); err != nil {
		gologger.Fatal().Msgf("Error parsing flags: %s\n", err)
	}
	if !options.Debug {
		options.Debug = env.GetEnvOrDefault("DEBUG", false)
	}
	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	if options.HealthCheck {
		showBanner()
		gologger.Print().Msgf("%s\n", DoHealthCheck(options))
		os.Exit(0)
	}

	// api key hierarchy: cli flag > env var > .pdcp/credential file
	if options.PdcpAuth == "true" {
		AuthWithPDCP()
	} else if len(options.PdcpAuth) == 36 {
		PDCPApiKey = options.PdcpAuth
		ph := pdcp.PDCPCredHandler{}
		if _, err := ph.GetCreds(); err == pdcp.ErrNoCreds {
			apiServer := env.GetEnvOrDefault("PDCP_API_SERVER", pdcp.DefaultApiServer)
			if validatedCreds, err := ph.ValidateAPIKey(PDCPApiKey, apiServer, "cvemap"); err == nil {
				_ = ph.SaveCreds(validatedCreds)
			}
		}
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
		stdinStr := strings.TrimSpace(string(bin))
		if stdinStr != "" {
			options.CveIds = append(options.CveIds, strings.Split(stdinStr, "\n")...)
		}
	}

	// convert cve-ids and cwe-ids to uppercase
	for i, cveId := range options.CveIds {
		options.CveIds[i] = strings.ToUpper(cveId)
	}
	for i, cweId := range options.CweIds {
		options.CweIds[i] = strings.ToUpper(cweId)
	}
	return &options
}

type Runner struct {
	Options       *Options
	CvemapService *service.Cvemap
}

func New(options *Options) *Runner {
	r := &Runner{
		Options:       options,
		CvemapService: service.NewCvemap(BaseUrl, PDCPApiKey),
	}
	if r.Options.Debug {
		r.CvemapService.Debug = true
	}
	return r
}

func (r *Runner) Run() {
	if r.Options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else if r.Options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}

	// Show the user the banner
	showBanner()

	if !r.Options.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("cvemap", Version)()
		if err != nil {
			if r.Options.Verbose {
				gologger.Error().Msgf("cvemap version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current cvemap version %v %v", Version, updateutils.GetVersionDescription(Version, latestVersion))
		}
	}

	// on default, enable kev
	if isDefaultRun(r.Options) {
		r.Options.Kev = "true"
	}

	parseHeaders(r.Options)

	if r.Options.EnablePageKeys && len(r.Options.CveIds) == 0 {
		r.processWithPageKeyEvents()
	} else {
		_ = r.process()
	}
}

func (r *Runner) GetCves() (*types.CVEBulkData, error) {
	if len(r.Options.CveIds) > 0 {
		return r.CvemapService.GetCvesByIds(r.Options.CveIds)
	}
	if r.Options.Search != "" {
		query := constructQueryByOptions(*r.Options)
		if r.Options.Debug {
			gologger.Print().Msgf("constructed query: %s\n", query)
		}
		return r.CvemapService.GetCvesBySearchString(query, r.Options.Limit, r.Options.Offset)
	}
	return r.CvemapService.GetCvesByFilters(constructQueryParams(r.Options))
}

func (r *Runner) process() *types.CVEBulkData {
	var cvesResp *types.CVEBulkData
	var err error
	cvesResp, err = r.GetCves()
	if err != nil {
		gologger.Fatal().Msgf("Error getting CVEs: %s\n", err)
		return nil
	}

	if r.Options.Json {
		outputJson(cvesResp.Cves)
		return cvesResp
	}

	if r.Options.Output != "" {
		writeToFile(r.Options.Output, cvesResp.Cves)
	}

	nPages := cvesResp.TotalResults / r.Options.Limit
	if cvesResp.TotalResults%r.Options.Limit > 0 {
		nPages++
	}
	currentPage := (r.Options.Offset / r.Options.Limit) + 1
	if len(r.Options.CveIds) == 0 && (r.Options.Verbose || r.Options.EnablePageKeys) {
		gologger.Print().Msgf("\n Limit: %v Page: %v TotalPages: %v TotalResults: %v\n", r.Options.Limit, currentPage, nPages, cvesResp.TotalResults)
	}

	if r.Options.ListId {
		for _, cve := range cvesResp.Cves {
			fmt.Println(cve.CveID)
		}
		return cvesResp
	}

	// limit headers to 10, otherwise it will be too wide
	if len(r.Options.TableHeaders) > 10 {
		r.Options.TableHeaders = r.Options.TableHeaders[:10]
	}

	headers, rows := generateTableData(cvesResp.Cves, r.Options.TableHeaders)

	renderTable(headers, rows)

	if r.Options.EnablePageKeys {
		pageString := ""
		if currentPage > 1 {
			pageString += " ◀     "
		}
		if currentPage < nPages {
			pageString += "     ▶"
		}
		gologger.Print().Msgf("%s", pageString)
	}
	return cvesResp
}

func (r *Runner) processWithPageKeyEvents() {
	cveResp := r.process()
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
				if r.Options.Offset+r.Options.Limit < cveResp.TotalResults {
					r.Options.Offset += r.Options.Limit
					clearScreen()
					cveResp = r.process()
				}
			case keyboard.KeyArrowLeft:
				if r.Options.Offset-r.Options.Limit >= 0 {
					r.Options.Offset -= r.Options.Limit
					clearScreen()
					cveResp = r.process()
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
		defaultHeaders = []string{"ID", "CVSS", "Severity", "EPSS", "Rank", "Reports", "Age", "Product", "Template"}
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

func generateTableData(cves []types.CVEData, headers []string) ([]string, [][]interface{}) {
	dataRows := make([][]interface{}, len(cves))
	for r, cve := range cves {
		dataRows[r] = getRow(headers, cve)
	}
	return headers, dataRows
}

func getRow(headers []string, cve types.CVEData) []interface{} {
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

func outputJson(cve []types.CVEData) {
	json, err := json.MarshalIndent(cve, "", "  ")
	if err != nil {
		gologger.Error().Msgf("Error marshalling json: %s\n", err)
		return
	}
	gologger.Silent().Msgf("%s\n", string(json))
}

func writeToFile(filename string, cves []types.CVEData) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		gologger.Fatal().Msgf("failed to open or create file: %v", err)
	}
	defer file.Close()
	json, err := json.MarshalIndent(cves, "", "  ")
	if err != nil {
		gologger.Error().Msgf("Error marshalling json: %s\n", err)
	}
	// Write to the file
	_, err = file.WriteString(string(json))
	if err != nil {
		gologger.Fatal().Msgf("failed to write to file: %v", err)
	}
}

func constructQueryParams(opts *Options) string {
	queryParams := urlutil.NewOrderedParams()
	if len(opts.Severity) > 0 {
		addQueryParams(queryParams, "severity", opts.Severity)
	}
	if len(opts.Assignees) > 0 {
		addQueryParams(queryParams, "assignee", opts.Assignees)
	}
	if len(opts.CvssScore) > 0 {
		var cvsKey string
		for _, cvssScore := range opts.CvssScore {
			cvsKey = "cvss_score"
			if cvssScore[0] == '>' {
				cvsKey = "cvss_score_gte"
				cvssScore = strings.TrimSpace(cvssScore[1:])
			} else if cvssScore[0] == '<' {
				cvsKey = "cvss_score_lte"
				cvssScore = strings.TrimSpace(cvssScore[1:])
			}
			queryParams.Add(cvsKey, cvssScore)
		}
	}

	if len(opts.Age) > 0 {
		ageKey := "age_in_days"
		if opts.Age[0] == '>' {
			ageKey = "age_in_days_gte"
			opts.Age = strings.TrimSpace(opts.Age[1:])
		} else if opts.Age[0] == '<' {
			ageKey = "age_in_days_lte"
			opts.Age = strings.TrimSpace(opts.Age[1:])
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
			opts.EpssScore = strings.TrimSpace(opts.EpssScore[1:])
		} else if opts.EpssScore[0] == '<' {
			epssKey = "epss.epss_score_lte"
			opts.EpssScore = strings.TrimSpace(opts.EpssScore[1:])
		}
		queryParams.Add(epssKey, opts.EpssScore)
	}
	if len(opts.EpssPercentile) > 0 {
		var epKey string
		for _, ep := range opts.EpssPercentile {
			epKey = "epss.epss_percentile"
			if ep[0] == '>' {
				epKey = "epss.epss_percentile_gte"
				ep = strings.TrimSpace(ep[1:])
			} else if ep[0] == '<' {
				epKey = "epss.epss_percentile_lte"
				ep = strings.TrimSpace(ep[1:])
			}
			queryParams.Add(epKey, ep)
		}
	}
	if len(opts.CweIds) > 0 {
		addQueryParams(queryParams, "weaknesses.$.cwe_id", opts.CweIds)
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
	if opts.RemotlyExploitable == "true" {
		queryParams.Add("is_remote", "true")
	}
	subQuery := ""
	if opts.Hackerone == "true" {
		subQuery = "hackerone.rank_gte=1"
		subQuery += "&sort_asc=hackerone.rank"
	} else {
		subQuery = "sort_desc=cve_id"
	}
	if opts.Limit > 0 {
		if len(subQuery) > 0 {
			subQuery += "&"
		}
		subQuery += fmt.Sprintf("limit=%d", opts.Limit)
	}
	if opts.Offset >= 0 {
		if len(subQuery) > 0 {
			subQuery += "&"
		}
		subQuery += fmt.Sprintf("offset=%d", opts.Offset)
	}
	query := queryParams.Encode()
	if len(opts.CweIds) == 1 {
		if len(query) > 0 && len(subQuery) > 0 {
			query += "&"
		}
		return query + subQuery
	}
	if len(query) > 0 && len(subQuery) > 0 {
		query = "&" + query
	}
	return subQuery + query
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
				cvssScore = strings.TrimSpace(cvssScore[1:])
			} else if cvssScore[0] == '<' {
				cvsKey = "cvss_score_lte"
				cvssScore = strings.TrimSpace(cvssScore[1:])
			}
			query = fmt.Sprintf("%s %s:%s", query, cvsKey, cvssScore)
		}
	}
	if len(opts.EpssScore) > 0 {
		epssKey := "epss.epss_score"
		if opts.EpssScore[0] == '>' {
			epssKey = "epss.epss_score_gte"
			opts.EpssScore = strings.TrimSpace(opts.EpssScore[1:])
		} else if opts.EpssScore[0] == '<' {
			epssKey = "epss.epss_score_lte"
			opts.EpssScore = strings.TrimSpace(opts.EpssScore[1:])
		}
		query = fmt.Sprintf("%s %s:%s", query, epssKey, opts.EpssScore)
	}
	if len(opts.EpssPercentile) > 0 {
		var epKey string
		for _, ep := range opts.EpssPercentile {
			epKey = "epss.epss_percentile"
			if ep[0] == '>' {
				epKey = "epss.epss_percentile_gte"
				ep = strings.TrimSpace(ep[1:])
			} else if ep[0] == '<' {
				epKey = "epss.epss_percentile_lte"
				ep = strings.TrimSpace(ep[1:])
			}
			query = fmt.Sprintf("%s %s:%s", query, epKey, ep)
		}
	}
	if len(opts.Cpe) > 0 {
		query = fmt.Sprintf(`%s cpe.cpe:"%s"`, query, opts.Cpe)
	}
	if len(opts.CweIds) > 0 {
		query = fmt.Sprintf("%s %s:%s", query, "weaknesses.$.cwe_id", strings.Join(opts.CweIds, ","))
	}
	if len(opts.Age) > 0 {
		ageKey := "age_in_days"
		if opts.Age[0] == '>' {
			ageKey = "age_in_days_gte"
			opts.Age = strings.TrimSpace(opts.Age[1:])
		} else if opts.Age[0] == '<' {
			ageKey = "age_in_days_lte"
			opts.Age = strings.TrimSpace(opts.Age[1:])
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
	return query
}

func addQueryParams(queryParams *urlutil.OrderedParams, key string, values []string) *urlutil.OrderedParams {
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
