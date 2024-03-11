// package cvemap implements library for querying CVE data from ProjectDiscovery cvemap Project
package cvemap

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/projectdiscovery/cvemap/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/env"
	errorutil "github.com/projectdiscovery/utils/errors"
	updateutils "github.com/projectdiscovery/utils/update"
	urlutil "github.com/projectdiscovery/utils/url"
)

const (
	//BaseApiPath is the base route for the cvemap api
	BaseApiPath           = "/api/v1"
	RouteSupportedFilters = "/filters"
	RouteCveDetails       = "/cve/:id" // :id is cve-id (required)
	RouteQueryCves        = "/cves"
	RouteTextSearch       = "/cves/search"
	RouteCPESearch        = "/cves/:cpe" // :cpe is cpestring (optional)
)

const (
	// AuthHeader is the header for the api key
	AuthHeader    = "X-PDCP-Key"
	CvemapVersion = "v0.0.7-dev"
)

var (
	// CveMapBaseUrl is the base url for the cvemap api
	CveMapBaseUrl         = env.GetEnvOrDefault("CVEMAP_API_URL", "https://cve.projectdiscovery.io/")
	ErrBadRequest         = errorutil.NewWithFmt("failed to query cve due to incorrect filters : %v")
	ErrUnAuthorized       = errorutil.New(`unauthorized: 401 (get your free api key from https://cloud.projectdiscovery.io)`)
	ErrUnexpectedResponse = errorutil.NewWithFmt("unexpected response from cvemap api: %v : %v")
)

// GetCveMapURL returns the url for the given path
// It uses the CveMapBaseUrl to construct the url
func GetCveMapURL(path string) string {
	return strings.TrimSuffix(CveMapBaseUrl, "/") + path + "/" + strings.TrimPrefix(path, "/")
}

// Client is a client for the cvemap api
type Client struct {
	client *retryablehttp.Client
	opts   *Options
}

type Options struct {
	// ApiKey is the api key for the cvemap api
	ApiKey string
	// RetryableHttpOptions contains options for the http client (optional)
	RetryableHttpOptions *retryablehttp.Options
	// HttpClient is the http client to use (optional)
	HttpClient *http.Client
}

// NewClient creates a new client for the cvemap api
func NewClient(opts *Options) (*Client, error) {
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
	return &Client{client: httpClient, opts: opts}, nil
}

// GetSupportedFilters returns the supported filters for the cvemap api
func (c *Client) GetSupportedFilters() (map[string]interface{}, error) {
	var result map[string]interface{}
	resp, err := c.get(RouteSupportedFilters, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	return result, nil
}

// GetCve returns the details of a particular cve
func (c *Client) GetCve(cveId string) (*types.CVEData, error) {
	resp, err := c.get(strings.Replace(RouteCveDetails, ":id", cveId, -1), nil)
	if err != nil {
		return nil, err
	}

	if resp.Body != nil {
		defer resp.Body.Close()
	}
	dec := json.NewDecoder(resp.Body)
	var cve types.CVEData
	if err := dec.Decode(&cve); err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("invalid cve received")
	}
	return &cve, nil
}

// SearchCVEsByText returns the cves with the given text search
func (c *Client) SearchCVEsByText(query string, params *urlutil.OrderedParams) ([]types.CVEData, error) {
	if params == nil {
		params = urlutil.NewOrderedParams()
	}
	params.Add("q", query)
	resp, err := c.get(RouteTextSearch, params)
	if err != nil {
		return nil, err
	}

	if resp.Body != nil {
		defer resp.Body.Close()
	}
	dec := json.NewDecoder(resp.Body)
	var cves []types.CVEData
	if err := dec.Decode(&cves); err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("invalid cve received")
	}
	return cves, nil
}

// SearchCvesWithFilters returns the cves with the given filters
func (c *Client) SearchCvesWithFilters(params *urlutil.OrderedParams) ([]types.CVEData, error) {
	if params == nil {
		params = urlutil.NewOrderedParams()
	}
	resp, err := c.get(RouteQueryCves, params)
	if err != nil {
		return nil, err
	}

	if resp.Body != nil {
		defer resp.Body.Close()
	}
	dec := json.NewDecoder(resp.Body)
	var cves []types.CVEData
	if err := dec.Decode(&cves); err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("invalid cve received")
	}
	return cves, nil
}

// getCveDetails returns the details of a cve
func (c *Client) get(path string, params *urlutil.OrderedParams) (*http.Response, error) {
	parsed, err := urlutil.ParseAbsoluteURL(GetCveMapURL(path), false)
	if err != nil {
		return nil, err
	}
	if params != nil {
		params.Iterate(func(key string, value []string) bool {
			parsed.Query().Add(key, strings.Join(value, ","))
			return true
		})
	}
	// add metadata params
	parsed.Params.Merge(updateutils.GetpdtmParams(CvemapVersion))
	req, err := retryablehttp.NewRequest("GET", GetCveMapURL(path), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(AuthHeader, c.opts.ApiKey)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnAuthorized
	}
	if resp.StatusCode == http.StatusBadRequest {
		return nil, ErrBadRequest.Msgf(path)
	}
	if resp.StatusCode != http.StatusOK {
		var bin []byte
		if resp.Body != nil {
			bin, _ = io.ReadAll(resp.Body)
			defer resp.Body.Close()
		}
		return nil, ErrUnexpectedResponse.Msgf(resp.Status, string(bin))
	}
	return resp, nil
}
