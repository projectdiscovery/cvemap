package id

import (
	"context"

	"github.com/projectdiscovery/cvemap"
)

type Handler struct {
	client *cvemap.Client
}

// NewHandler returns a new Handler instance
func NewHandler(client *cvemap.Client) *Handler {
	return &Handler{
		client: client,
	}
}

// Get fetches a single vulnerability document by its ID.
func (h *Handler) Get(id string) (*cvemap.Vulnerability, error) {
	resp, err := h.client.GetVulnerabilityByID(context.Background(), id, nil)
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}
