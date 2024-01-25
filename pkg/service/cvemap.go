package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/projectdiscovery/cvemap/pkg/types"
	"github.com/projectdiscovery/gologger"
	errorutil "github.com/projectdiscovery/utils/errors"
)

const xPDCPHeaderKey = "X-PDCP-Key"

var (
	httpCleint = &http.Client{}
)

type Cvemap struct {
	BaseUrl    string
	PDCPApiKey string
	Debug      bool
}

func NewCvemap(baseUrl string, pdcpApiKey string) *Cvemap {
	return &Cvemap{
		BaseUrl:    baseUrl,
		PDCPApiKey: pdcpApiKey,
	}
}

func (c *Cvemap) GetCvesByIds(cveIds []string) (*types.CVEBulkData, error) {
	url := fmt.Sprintf("%s/cves", c.BaseUrl)
	// send only 100 cve ids max
	if len(cveIds) > 100 {
		cveIds = cveIds[:100]
	}
	var cveIdList types.CVEIdList
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
	req.Header.Set(xPDCPHeaderKey, c.PDCPApiKey)

	response, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	// Check the response status code
	if response.StatusCode != http.StatusOK {
		return nil, errorutil.New("unexpected status code: %d", response.StatusCode)
	}
	var cvesInBulk types.CVEBulkData
	// Decode the JSON response into an array of CVEData structs
	err = json.NewDecoder(response.Body).Decode(&cvesInBulk)
	if err != nil {
		return nil, err
	}
	return &cvesInBulk, nil
}

func (c *Cvemap) GetCvesByFilters(encodedParams string) (*types.CVEBulkData, error) {
	url := fmt.Sprintf("%s/cves?%s", c.BaseUrl, encodedParams)
	// Send an HTTP GET request
	response, err := c.makeGetRequest(url)
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

func (c *Cvemap) GetCvesBySearchString(query string, limit, offset int) (*types.CVEBulkData, error) {
	u, err := url.Parse(fmt.Sprintf("%s/cves/search", c.BaseUrl))
	if err != nil {
		return nil, err
	}
	// Construct query parameters
	q := u.Query()
	q.Set("q", query)
	q.Set("limit", fmt.Sprintf("%v", limit))
	q.Set("offset", fmt.Sprintf("%v", offset))
	u.RawQuery = q.Encode()
	response, err := c.makeGetRequest(u.String())
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

// all the root level fields are supported
func (c *Cvemap) GetCvesForSpecificFields(fields []string, encodedParams string, limit, offset int) (*types.CVEBulkData, error) {
	url := fmt.Sprintf("%s/cves?fields=%s&%s&limit=%v&offset=%v", c.BaseUrl, strings.Join(fields, ","), encodedParams, limit, offset)
	// Send an HTTP GET request
	response, err := c.makeGetRequest(url)
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

var UNAUTHORIZEDERR = errorutil.New(`unauthorized: 401 (get your free api key from https://cloud.projectdiscovery.io)`)

func (c *Cvemap) makeGetRequest(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		gologger.Fatal().Msgf("Error creating request: %s\n", err)
	}
	req.Header.Set(xPDCPHeaderKey, c.PDCPApiKey)
	return c.doRequest(req)
}

func (c *Cvemap) doRequest(req *http.Request) (*http.Response, error) {
	if c.Debug {
		// dump request
		dump, err := httputil.DumpRequest(req, true)
		if err != nil {
			gologger.Fatal().Msgf("Error dumping request: %s\n", err)
		}
		gologger.Print().Msgf("%s\n", string(dump))
	}
	resp, err := httpCleint.Do(req)

	if err == nil && resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, UNAUTHORIZEDERR
		}
		if c.Debug {
			var errResp types.ErrorMessage
			err = json.NewDecoder(resp.Body).Decode(&errResp)
			if err == nil {
				return nil, errorutil.New("error %d: %s\n", resp.StatusCode, errResp.Message)
			}
		}
	}
	return resp, err
}
