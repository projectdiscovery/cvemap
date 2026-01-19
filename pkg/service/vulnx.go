package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/projectdiscovery/vulnx/pkg/types"
	"github.com/projectdiscovery/gologger"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/env"
	errorutil "github.com/projectdiscovery/utils/errors"
)

const xPDCPHeaderKey = "X-PDCP-Key"

var (
	BaseUrl         = env.GetEnvOrDefault("VULNX_API_URL", "https://cve.projectdiscovery.io/api/v1")
	ErrUnAuthorized = errorutil.New(`unauthorized: 401 (get your free api key from https://cloud.projectdiscovery.io)`)
)

type Vulnx struct {
	opts   *Options
	client *retryablehttp.Client
}

type Options struct {
	// ApiKey is the api key for the vulnx api
	ApiKey string
	// RetryableHttpOptions contains options for the http client (optional)
	RetryableHttpOptions *retryablehttp.Options
	// HttpClient is the http client to use (optional)
	HttpClient *http.Client
	// Debug is a flag that enables debugging output
	Debug bool
}

func NewVulnx(opts *Options) (*Vulnx, error) {
	if opts == nil {
		return nil, fmt.Errorf("Options cannot be nil")
	}
	if opts.ApiKey == "" {
		return nil, fmt.Errorf("api key cannot be empty")
	}
	clientOpts := retryablehttp.DefaultOptionsSingle
	if opts.RetryableHttpOptions != nil {
		clientOpts = *opts.RetryableHttpOptions
	}
	if opts.HttpClient != nil {
		clientOpts.HttpClient = opts.HttpClient
	}
	httpClient := retryablehttp.NewClient(clientOpts)

	return &Vulnx{
		opts:   opts,
		client: httpClient,
	}, nil
}

func (c *Vulnx) GetCvesByIds(cveIds []string) (*types.CVEBulkData, error) {
	url := fmt.Sprintf("%s/cves", BaseUrl)
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
	req, err := retryablehttp.NewRequest("POST", url, bytes.NewBuffer(reqData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(xPDCPHeaderKey, c.opts.ApiKey)

	response, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			gologger.Error().Msgf("Failed to close response body: %s", err)
		}
	}()
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

func (c *Vulnx) GetCvesByFilters(encodedParams string) (*types.CVEBulkData, error) {
	url := fmt.Sprintf("%s/cves?%s", BaseUrl, encodedParams)
	// Send an HTTP GET request
	response, err := c.makeGetRequest(url)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			gologger.Error().Msgf("Failed to close response body: %s", err)
		}
	}()
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

func (c *Vulnx) GetCvesBySearchString(query string, limit, offset int) (*types.CVEBulkData, error) {
	u, err := url.Parse(fmt.Sprintf("%s/cves/search", BaseUrl))
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
	defer func() {
		if err := response.Body.Close(); err != nil {
			gologger.Error().Msgf("Failed to close response body: %s", err)
		}
	}()
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
func (c *Vulnx) GetCvesForSpecificFields(fields []string, encodedParams string, limit, offset int) (*types.CVEBulkData, error) {
	url := fmt.Sprintf("%s/cves?fields=%s&%s&limit=%v&offset=%v", BaseUrl, strings.Join(fields, ","), encodedParams, limit, offset)
	// Send an HTTP GET request
	response, err := c.makeGetRequest(url)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			gologger.Error().Msgf("Failed to close response body: %s", err)
		}
	}()
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

func (c *Vulnx) makeGetRequest(url string) (*http.Response, error) {
	req, err := retryablehttp.NewRequest("GET", url, nil)
	if err != nil {
		gologger.Fatal().Msgf("Error creating request: %s\n", err)
	}
	req.Header.Set(xPDCPHeaderKey, c.opts.ApiKey)
	return c.doRequest(req)
}

func (c *Vulnx) doRequest(req *retryablehttp.Request) (*http.Response, error) {
	if c.opts.Debug {
		// dump request
		dump, err := req.Dump()
		if err != nil {
			gologger.Fatal().Msgf("Error dumping request: %s\n", err)
		}
		gologger.Print().Msgf("%s\n", string(dump))
	}
	resp, err := c.client.Do(req)

	if err == nil && resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, ErrUnAuthorized
		}
		if c.opts.Debug {
			var errResp types.ErrorMessage
			err = json.NewDecoder(resp.Body).Decode(&errResp)
			if err == nil {
				return nil, errorutil.New("error %d: %s\n", resp.StatusCode, errResp.Message)
			}
		}
	}
	return resp, err
}
