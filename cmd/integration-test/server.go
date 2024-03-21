package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/projectdiscovery/cvemap"
)

var cveData *cvemap.CVEBulkData

func SetupMockServer() {
	var err error
	// Load data from the JSON file
	cveData, err = loadData("test-data.json")
	if err != nil {
		fmt.Println("Error loading data:", err)
		return
	}
	// Setup HTTP server
	http.HandleFunc("/api/v1/cves", RequireAPIKey(http.HandlerFunc(handleRequest)))

	go func() {
		// Start the server on port 8080
		fmt.Println("Cvemap test server listening on 8080...")
		if err := http.ListenAndServe(":8080", nil); err != nil {
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

// handleRequest handles HTTP requests.
func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Handle the case where "cve_id" is a query parameter
	cveID := r.URL.Query().Get("cve_id")
	if cveID == "" {
		http.NotFound(w, r)
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

// LoadData loads data from a JSON file into a slice of CVEData.
func loadData(filename string) (*cvemap.CVEBulkData, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var data cvemap.CVEBulkData
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return nil, err
	}

	return &data, nil
}
