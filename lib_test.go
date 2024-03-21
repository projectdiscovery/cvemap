package cvemap

import (
	"testing"

	"github.com/projectdiscovery/utils/env"
	"github.com/stretchr/testify/require"
)

func TestFetchCVE(t *testing.T) {
	cve_id := "CVE-2023-41265"
	if env.GetEnvOrDefault("CI", false) {
		// temporarily disabled in CI
		return
	}
	key := env.GetEnvOrDefault("PDCP_API_KEY", "")
	require.NotEmpty(t, key, "PDCP_API_KEY is not set")

	client, err := NewClient(&Options{
		ApiKey: key,
	})
	require.NoError(t, err)

	data, err := client.GetCve(cve_id)
	require.NoError(t, err)
	require.NotNil(t, data)
	require.NotEmpty(t, data.CveID)
	require.True(t, data.CveID == cve_id)
}
