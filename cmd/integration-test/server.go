package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/vulnx"
	"github.com/projectdiscovery/vulnx/pkg/types"
)

var cveData *types.CVEBulkData

func SetupMockServer() {
	var err error
	// Load data from the JSON file
	cveData, err = loadData("test-data.json")
	if err != nil {
		fmt.Println("Error loading data:", err)
		return
	}

	// Setup HTTP server with mux for path-based routing
	mux := http.NewServeMux()

	// Legacy v1 endpoint
	mux.HandleFunc("/api/v1/cves", RequireAPIKey(handleLegacyRequest))

	// New v2 endpoints
	mux.HandleFunc("/v2/vulnerability/search", RequireAPIKey(handleSearchRequest))
	mux.HandleFunc("/v2/vulnerability/", RequireAPIKey(handleGetByIDRequest))

	go func() {
		// Start the server on port 8080
		fmt.Println("Vulnx test server listening on 8080...")
		if err := http.ListenAndServe(":8080", mux); err != nil {
			fmt.Println("Error starting server:", err)
		}
	}()
}

// RequireAPIKey is a middleware that checks for the X-PDCP-Key header.
func RequireAPIKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-PDCP-Key")
		if apiKey != xPDCPHeaderTestKey {
			http.Error(w, "Unauthorized: X-PDCP-Key header is required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// handleLegacyRequest handles the legacy /api/v1/cves endpoint
func handleLegacyRequest(w http.ResponseWriter, r *http.Request) {
	// Handle the case where "cve_id" is a query parameter
	cveID := r.URL.Query().Get("cve_id")
	if cveID == "" {
		http.NotFound(w, r)
		return
	}
	for _, data := range cveData.Cves {
		if data.CveID == cveID {
			// Return the data corresponding to the given CVE ID
			if err := json.NewEncoder(w).Encode(cveData); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
	}
	http.NotFound(w, r)
}

// handleGetByIDRequest handles GET /v2/vulnerability/{id} endpoint
func handleGetByIDRequest(w http.ResponseWriter, r *http.Request) {
	// Extract CVE ID from path: /v2/vulnerability/{id}
	path := r.URL.Path
	prefix := "/v2/vulnerability/"
	if !strings.HasPrefix(path, prefix) {
		http.NotFound(w, r)
		return
	}

	cveID := strings.TrimPrefix(path, prefix)
	if cveID == "" || cveID == "search" || cveID == "filters" {
		http.NotFound(w, r)
		return
	}

	// Find the CVE in our test data
	for i := range cveData.Cves {
		if cveData.Cves[i].CveID == cveID {
			// Return the v2 response format
			resp := vulnx.VulnerabilityResponse{
				Data: convertToVulnerability(&cveData.Cves[i]),
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
	}
	http.NotFound(w, r)
}

// handleSearchRequest handles GET /v2/vulnerability/search endpoint
func handleSearchRequest(w http.ResponseWriter, r *http.Request) {
	termFacets := r.URL.Query().Get("term_facets")

	// Build response - always return all test data for search queries
	resp := vulnx.SearchResponse{
		Total:   len(cveData.Cves),
		Results: make([]vulnx.Vulnerability, 0),
	}

	// If term_facets is provided, return facet data (for analyze command)
	if termFacets != "" {
		facets := make(map[string]any)
		fields := strings.Split(termFacets, ",")
		for _, field := range fields {
			fieldName := strings.Split(field, ":")[0]
			facets[fieldName] = map[string]any{
				"buckets": []map[string]any{
					{"key": "critical", "count": 10},
					{"key": "high", "count": 20},
					{"key": "medium", "count": 30},
					{"key": "low", "count": 40},
				},
			}
		}
		resp.Facets = facets
	}

	// Add all vulnerabilities to response (mock server returns all test data)
	for i := range cveData.Cves {
		resp.Results = append(resp.Results, *convertToVulnerability(&cveData.Cves[i]))
	}

	resp.Count = len(resp.Results)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// convertToVulnerability converts legacy CVEData to the new Vulnerability type
func convertToVulnerability(data *types.CVEData) *vulnx.Vulnerability {
	return &vulnx.Vulnerability{
		ID:          data.CveID,
		CVEID:       data.CveID,
		Description: data.CveDescription,
		Severity:    data.Severity,
		CvssScore:   data.CvssScore,
		EpssScore:   data.Epss.Score,
		IsKev:       data.IsKev,
		IsPoc:       data.IsPoc,
		IsTemplate:  data.IsTemplate,
		PocCount:    len(data.Poc),
	}
}

// LoadData loads data from a JSON file into a slice of CVEData.
func loadData(filename string) (*types.CVEBulkData, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			gologger.Error().Msgf("Failed to close file: %s", err)
		}
	}()

	var data types.CVEBulkData
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return nil, err
	}

	return &data, nil
}
