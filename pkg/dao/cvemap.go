package dao

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/projectdiscovery/cvemap/pkg/constant"
	"github.com/projectdiscovery/cvemap/pkg/runner"
	"github.com/projectdiscovery/cvemap/pkg/service"
	"github.com/projectdiscovery/cvemap/pkg/types"
	"github.com/projectdiscovery/gologger"
	errorutil "github.com/projectdiscovery/utils/errors"
)

type Cvemap struct {
	Accessor
	ctx context.Context
}

func (cvemap *Cvemap) Init(ctx context.Context) {
	cvemap.ctx = ctx
}

func (e *Cvemap) List(ctx context.Context) ([]Object, error) {
	e.ctx = ctx
	options, ok := e.ctx.Value(constant.KeyOptions).(runner.Options)
	if !ok {
		msg := fmt.Sprintf("conversion err: Expected options but got %v", options)
		gologger.Error().Msgf(msg)
		return nil, errorutil.New(msg)
	}

	// Start time for GetCvesByOptions
	start := time.Now()
	var cvesInBulk *types.CVEBulkData
	var err error
	var searchString string

	if e.ctx != nil && e.ctx.Value(constant.KeySearchString) != nil {
		searchString = e.ctx.Value(constant.KeySearchString).(string)
		// TODO: Make limit and offset dynamic
		cvesInBulk, err = service.GetCvesBySearchString(searchString, 100, 0)
		e.ctx = context.WithValue(e.ctx, constant.KeySearchString, "")
		elapsed := time.Since(start)
		gologger.Info().Msgf("Time taken for GetCvesBySearchString: %.2fs", elapsed.Seconds())
	} else {
		cvesInBulk, err = runner.GetCvesByOptions(options)
		elapsed := time.Since(start)
		gologger.Info().Msgf("Time taken for GetCvesByOptions: %.2fs", elapsed.Seconds())
	}

	if err != nil {
		gologger.Error().Msgf("Error getting cves: %v", err)
		return nil, err
	}

	objs := make([]Object, len(cvesInBulk.Cves))
	for i, obj := range cvesInBulk.Cves {
		objs[i] = obj
	}

	return objs, err
}

func (e *Cvemap) Get(ctx context.Context, path string) (Object, error) {
	return nil, nil
}

func (e *Cvemap) Describe(cveId string) (string, error) {
	start := time.Now()
	cveData, err := service.GetCveById(cveId)
	if err != nil {
		gologger.Error().Msgf("Error getting cve data for %s: %v", cveId, err)
		return "", err
	}
	elapsed := time.Since(start)
	gologger.Info().Msgf("Time taken for GetCveById: %.2fs", elapsed.Seconds())

	// Convert to colorized JSON string
	colorfulJSON := colorizeJSON(cveData)
	return colorfulJSON, nil
}

// colorizeJSON applies basic color formatting to a JSON string for terminal output
func colorizeJSON(data interface{}) string {
	formattedJSON, err := json.MarshalIndent(data, "", "  ") // Indent for readability
	if err != nil {
		return fmt.Sprintf("Error formatting JSON: %v", err)
	}

	// Apply colors (modify for desired color scheme)
	// colorfulJSON := strings.Replace(string(formattedJSON), ":", ":\033[36m", -1)     // Colorize colons
	// colorfulJSON = strings.Replace(colorfulJSON, "\"", "\033[33m\"", -1)             // Colorize double quotes
	// colorfulJSON = strings.Replace(colorfulJSON, "\033[36m\033[33m", "\033[36m", -1) // Fix double-coloring
	// return colorfulJSON
	return string(formattedJSON)
}
