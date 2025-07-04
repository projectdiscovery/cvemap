// Package cvemap provides a robust, idiomatic Go client for interacting
// with the ProjectDiscovery CVE Map (CVEMap) REST API. The client focuses on
// the "/v2/vulnerability" endpoints, exposing high-level helper methods that
// handle authentication, request construction, network-level retries, and JSON
// decoding so that callers can concentrate on business logic.
//
// # Quick Start
//
// The snippet below demonstrates a minimal, production-ready workflow. The
// example uses an API key that is resolved from your local ProjectDiscovery
// credential store, falling back to the `PDCP_API_KEY` environment variable.
//
//	ctx := context.Background()
//
//	client, err := cvemap.New(
//	    cvemap.WithKeyFromEnv(), // or cvemap.WithPDCPKey("<YOUR_KEY>")
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	out, err := client.SearchVulnerabilities(ctx, cvemap.SearchParams{
//	    Query: cvemap.Ptr("id:CVE-2023-4799"),
//	    Limit: cvemap.Ptr(10),
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	fmt.Println(len(out.Vulnerabilities))
//
// The client is safe for concurrent use by multiple goroutines.
//
// For complete API semantics refer to https://api.projectdiscovery.io/docs.
package cvemap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/projectdiscovery/utils/errkit"
)

const (
	// DefaultBaseURL is the default base URL for the API.
	DefaultBaseURL = "https://api.projectdiscovery.io"
	// UserAgent is the default user agent for the client.
	UserAgent = "cvemap-client/1.0"
)

// Client errors
var (
	ErrAPIKeyRequired      = errkit.New("api key is required (use WithPDCPKey or WithKeyFromEnv)")
	ErrBadRequest          = errkit.New("bad request: client sent an invalid request")
	ErrUnauthorized        = errkit.New("unauthorized: invalid or missing API key")
	ErrNotFound            = errkit.New("not found: resource does not exist")
	ErrInternalServerError = errkit.New("internal server error: something went wrong on the server")
	ErrUnknownAPIError     = errkit.New("unknown api error")

	ErrRequestBuildFailure = errkit.New("failed to build request")
	ErrRequestFailed       = errkit.New("request failed")
	ErrMarshalBody         = errkit.New("failed to marshal request body")
	ErrCreateHTTPRequest   = errkit.New("failed to create http request")
	ErrDecodeResponse      = errkit.New("failed to decode response")
)

// Option represents a functional option that mutates a *Client* during
// construction. It follows the standard "functional options" pattern popularised
// by Google and is the preferred way to add optional parameters without an
// explosion of constructor variants.
//
// A typical call site looks like this:
//
//	client, err := cvemap.New(
//	    cvemap.WithPDCPKey("<YOUR_KEY>"),
//	    cvemap.WithRetryableHTTPOptions(retryablehttp.Options{RetryMax: 5}),
//	)
//	if err != nil {
//	    // handle error
//	}
type Option func(*Client)

// Client provides high-level helpers around the CVEMap API. It is safe for
// concurrent use. Zero values for *Client* fields are not meaningful—always use
// the *New* constructor.
type Client struct {
	baseURL   string
	apiKey    string
	httpc     *retryablehttp.Client
	userAgent string
	// Optional debug hooks
	debugRequest  func(*http.Request)
	debugResponse func(*http.Response)
}

// New returns a new *Client* configured by the supplied *Option*s. At least one
// option that sets an authentication key—*WithPDCPKey* or *WithKeyFromEnv*—must
// be provided or the constructor returns *ErrAPIKeyRequired*.
//
// The returned client is ready for immediate use:
//
//	c, err := cvemap.New(cvemap.WithPDCPKey("<YOUR_KEY>"))
//	if err != nil { /* handle */ }
//
// Custom HTTP behaviour (timeouts, retries, logging) can be injected via
// *WithClient* or *WithRetryableHTTPOptions*.
func New(opts ...Option) (*Client, error) {
	c := &Client{
		baseURL:   DefaultBaseURL,
		userAgent: UserAgent,
		httpc:     retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle), // Default retryablehttp client
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.apiKey == "" {
		return nil, ErrAPIKeyRequired
	}
	// If a custom httpc was not provided, set the default retryablehttp client
	if c.httpc == nil {
		c.httpc = retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	}
	return c, nil
}

// WithClient overrides the default *retryablehttp.Client* used for all network
// operations. It enables advanced users to specify custom transports, proxy
// settings, or instrumentation hooks.
func WithClient(hc *retryablehttp.Client) Option {
	return func(c *Client) {
		c.httpc = hc
	}
}

// WithPDCPKey sets the ProjectDiscovery Cloud Platform (PDCP) API key that will
// be sent in the `X-PDCP-Key` HTTP header.
func WithPDCPKey(apiKey string) Option {
	return func(c *Client) {
		c.apiKey = apiKey
	}
}

// WithKeyFromEnv attempts to discover a PDCP API key from the local credential
// store (managed by `pdcp`) or the `PDCP_API_KEY` environment variable.
func WithKeyFromEnv() Option {
	return func(c *Client) {
		pch := pdcp.PDCPCredHandler{}
		if creds, err := pch.GetCreds(); err == nil {
			c.apiKey = creds.APIKey
			return
		}
	}
}

// WithBaseURL points the client at an alternative endpoint—useful for testing
// against staging or mock servers.
func WithBaseURL(url string) Option {
	return func(c *Client) {
		c.baseURL = url
	}
}

// WithRetryableHTTPOptions constructs a fresh *retryablehttp.Client* with the
// supplied options and wires it into the *Client* instance.
func WithRetryableHTTPOptions(clientOpts retryablehttp.Options) Option {
	return func(c *Client) {
		c.httpc = retryablehttp.NewClient(clientOpts)
	}
}

// WithDebugRequest sets a callback that is invoked with the *http.Request before it is sent.
func WithDebugRequest(cb func(*http.Request)) Option {
	return func(c *Client) {
		c.debugRequest = cb
	}
}

// WithDebugResponse sets a callback that is invoked with the *http.Response after it is received (before decoding).
func WithDebugResponse(cb func(*http.Response)) Option {
	return func(c *Client) {
		c.debugResponse = cb
	}
}

// SearchVulnerabilities performs a full-text search across all vulnerability
// documents and returns a paginated *SearchResponse*.
//
// The behaviour of the search is controlled via *SearchParams*; see that type
// for field-level documentation.
//
// SearchVulnerabilities may contact the network multiple times if retries are
// enabled on the underlying HTTP client. It is safe to call concurrently.
func (c *Client) SearchVulnerabilities(ctx context.Context, params SearchParams) (SearchResponse, error) {
	var resp SearchResponse
	req, err := c.newRequest(ctx, http.MethodGet, "/v2/vulnerability/search", paramsToQuery(params), nil)
	if err != nil {
		return resp, errkit.Append(ErrRequestBuildFailure, err)
	}
	err = c.do(req, &resp)
	if err != nil {
		return resp, errkit.Append(ErrRequestFailed, err)
	}
	return resp, nil
}

// GetVulnerabilityByID fetches a single vulnerability document identified by
// its canonical ID (for example "CVE-2023-1234").
//
// When *params* is non-nil the *Fields* slice can be used to limit the response
// payload to a subset of fields, reducing bandwidth.
func (c *Client) GetVulnerabilityByID(ctx context.Context, id string, params *GetByIDParams) (VulnerabilityResponse, error) {
	var resp VulnerabilityResponse
	path := fmt.Sprintf("/v2/vulnerability/%s", id)
	var query url.Values
	if params != nil && len(params.Fields) > 0 {
		query = make(url.Values)
		query.Set("fields", strings.Join(params.Fields, ","))
	}
	req, err := c.newRequest(ctx, http.MethodGet, path, query, nil)
	if err != nil {
		return resp, errkit.Append(ErrRequestBuildFailure, err)
	}
	err = c.do(req, &resp)
	if err != nil {
		return resp, errkit.Append(ErrRequestFailed, err)
	}
	return resp, nil
}

// GetVulnerabilityFilters lists all filter definitions that can be applied to
// search queries. Filters are stable identifiers used for building rich UI
// facets or powering autocomplete experiences.
func (c *Client) GetVulnerabilityFilters(ctx context.Context) ([]VulnerabilityFilter, error) {
	var filters []VulnerabilityFilter
	req, err := c.newRequest(ctx, http.MethodGet, "/v2/vulnerability/filters", nil, nil)
	if err != nil {
		return nil, errkit.Append(ErrRequestBuildFailure, err)
	}
	err = c.do(req, &filters)
	if err != nil {
		return nil, errkit.Append(ErrRequestFailed, err)
	}
	return filters, nil
}

// newRequest builds an HTTP request with authentication and query params.
func (c *Client) newRequest(ctx context.Context, method, path string, query url.Values, body any) (*http.Request, error) {
	requestURL := c.baseURL + path
	if len(query) > 0 {
		requestURL += "?" + query.Encode()
	}
	var req *http.Request
	var err error
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, errkit.Append(ErrMarshalBody, err)
		}
		req, err = http.NewRequestWithContext(ctx, method, requestURL, strings.NewReader(string(b)))
		if err != nil {
			return nil, errkit.Append(ErrCreateHTTPRequest, err)
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequestWithContext(ctx, method, requestURL, nil)
		if err != nil {
			return nil, errkit.Append(ErrCreateHTTPRequest, err)
		}
	}
	req.Header.Set("X-PDCP-Key", c.apiKey)
	req.Header.Set("User-Agent", c.userAgent)
	return req, nil
}

// do executes the HTTP request and decodes the JSON response.
func (c *Client) do(req *http.Request, out any) error {
	if c.debugRequest != nil {
		c.debugRequest(req)
	}
	resp, err := c.httpc.HTTPClient.Do(req)
	if err != nil {
		return errkit.Append(ErrRequestFailed, err)
	}
	if c.debugResponse != nil {
		c.debugResponse(resp)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return c.handleAPIError(resp)
	}

	if out != nil {
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(out); err != nil {
			return errkit.Append(ErrDecodeResponse, err)
		}
	}
	return nil
}

// handleAPIError processes non-2xx HTTP responses, normalising them into the
// rich errkit error hierarchy so that callers can unwrap and inspect the root
// cause.
func (c *Client) handleAPIError(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusNotFound:
		return ErrNotFound // Return ErrNotFound directly for 404 as it indicates no content
	}

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return errkit.Wrap(ErrUnknownAPIError, fmt.Sprintf("api error (failed to read response body): %s", resp.Status))
	}

	var errorBody map[string]interface{}
	unmarshalErr := json.Unmarshal(bodyBytes, &errorBody)

	var detailedErr error
	if unmarshalErr == nil {
		// Check for common error message keys
		if errMsg, ok := errorBody["error"]; ok {
			detailedErr = errkit.New("api error", "status_code", resp.StatusCode, "error", errMsg)
		} else if errMsg, ok := errorBody["msg"]; ok {
			detailedErr = errkit.New("api error", "status_code", resp.StatusCode, "error", errMsg)
		} else if errMsg, ok := errorBody["message"]; ok {
			detailedErr = errkit.New("api error", "status_code", resp.StatusCode, "error", errMsg)
		} else if errMsg, ok := errorBody["cause"]; ok {
			detailedErr = errkit.New("api error", "status_code", resp.StatusCode, "error", errMsg)
		}
	}

	if detailedErr == nil {
		// Fallback to raw body if no specific keys found or unmarshalling failed
		detailedErr = errkit.New("api error", "status_code", resp.StatusCode, "error", strings.TrimSpace(string(bodyBytes)))
	}

	switch resp.StatusCode {
	case http.StatusBadRequest:
		return errkit.Append(ErrBadRequest, detailedErr)
	case http.StatusUnauthorized:
		return errkit.Append(ErrUnauthorized, detailedErr)
	case http.StatusInternalServerError:
		return errkit.Append(ErrInternalServerError, detailedErr)
	default:
		return errkit.Append(ErrUnknownAPIError, detailedErr)
	}
}

// paramsToQuery converts SearchParams to url.Values for query string.
func paramsToQuery(params SearchParams) url.Values {
	q := make(url.Values)
	if params.Limit != nil {
		q.Set("limit", fmt.Sprintf("%d", *params.Limit))
	}
	if params.Offset != nil {
		q.Set("offset", fmt.Sprintf("%d", *params.Offset))
	}
	if params.SortAsc != nil {
		q.Set("sort_asc", *params.SortAsc)
	}
	if params.SortDesc != nil {
		q.Set("sort_desc", *params.SortDesc)
	}
	if len(params.Fields) > 0 {
		q.Set("fields", strings.Join(params.Fields, ","))
	}
	if len(params.TermFacets) > 0 {
		q.Set("term_facets", strings.Join(params.TermFacets, ","))
	}
	if len(params.RangeFacets) > 0 {
		q.Set("range_facets", strings.Join(params.RangeFacets, ","))
	}
	if params.Query != nil {
		q.Set("q", *params.Query)
	}
	if params.Highlight != nil {
		q.Set("highlight", fmt.Sprintf("%t", *params.Highlight))
	}
	if params.FacetSize != nil {
		q.Set("facet_size", fmt.Sprintf("%d", *params.FacetSize))
	}
	return q
}
