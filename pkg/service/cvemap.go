package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	"github.com/projectdiscovery/cvemap/pkg/types"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/utils/auth/pdcp"
	errorutil "github.com/projectdiscovery/utils/errors"
)

var (
	BaseUrl        = "https://cve.projectdiscovery.io/api/v1"
	XPDCPKeyHeader = "X-PDCP-Key"
	PDCPApiKey     = ""
	httpCleint     = &http.Client{}
)

func init() {
	pch := pdcp.PDCPCredHandler{}
	if creds, err := pch.GetCreds(); err == nil {
		PDCPApiKey = creds.APIKey
	}
	if os.Getenv(XPDCPKeyHeader) != "" {
		PDCPApiKey = os.Getenv(XPDCPKeyHeader)
	}
}

var UNAUTHORIZEDERR = errorutil.New(`unexpected status code: 401 (get your free api key from https://cloud.projectdiscovery.io)`)

func GetCvesByParams(encodedParams string) (*types.CVEBulkData, error) {
	url := fmt.Sprintf("%s/cves?%s", BaseUrl, encodedParams)
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
	var cvesInBulk types.CVEBulkData
	// Decode the JSON response into an array of CVEData structs
	err = json.NewDecoder(response.Body).Decode(&cvesInBulk)
	if err != nil {
		return nil, err
	}
	return &cvesInBulk, nil
}

func GetCvesBySearchString(query string, limit, offset int) (*types.CVEBulkData, error) {
	url := fmt.Sprintf("%s/cves/search?q=%s&limit=%v&offset=%v", BaseUrl, query, limit, offset)
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
	var cvesInBulk types.CVEBulkData
	// Decode the JSON response into an array of CVEData structs
	err = json.NewDecoder(response.Body).Decode(&cvesInBulk)
	if err != nil {
		return nil, err
	}
	return &cvesInBulk, nil
}

func GetCveById(cveId string) (*types.CVEData, error) {
	url := fmt.Sprintf("%s/cves?cve_id=%s", BaseUrl, cveId)
	// Send an HTTP GET request
	response, err := makeRequest(url)
	if err != nil {
		return nil, errorutil.New("Error getting CVEs: %s\n", err)
	}
	defer response.Body.Close()
	// Check the response status code
	if response.StatusCode != http.StatusOK {
		return nil, errorutil.New("unexpected status code: %d", response.StatusCode)
	}
	// Create a variable to store the response data
	var cveBulkData types.CVEBulkData
	// Decode the JSON response into an array of CVEData structs
	err = json.NewDecoder(response.Body).Decode(&cveBulkData)
	if err != nil {
		return nil, errorutil.New("Error decoding response: %s\n", err)
	}
	if len(cveBulkData.Cves) == 0 {
		return nil, errorutil.New("cve not found")
	}
	return &cveBulkData.Cves[0], nil
}

// all the root level fields are supported
func GetCvesForSpecificFields(fields []string, limit, offset int) (*types.CVEBulkData, error) {
	url := fmt.Sprintf("%s/cves?fields=%s&limit=%v&offset=%v", BaseUrl, strings.Join(fields, ","), limit, offset)
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
	var cvesInBulk types.CVEBulkData
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
	req.Header.Set(XPDCPKeyHeader, PDCPApiKey)
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
		var errResp types.ErrorMessage
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if os.Getenv("DEBUG") == "true" {
			gologger.Error().Msgf("unauthorized: %s\n", errResp.Message)
		}
		return nil, UNAUTHORIZEDERR
	}
	return resp, err
}
