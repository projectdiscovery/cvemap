package ui

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/cvemap/pkg/color"
	"github.com/projectdiscovery/cvemap/pkg/render"
	"github.com/projectdiscovery/gologger"
)

const (
	descIndicator = "↓"
	ascIndicator  = "↑"
)

// TrimCell removes superfluous padding.
func TrimCell(tv *SelectTable, row, col int) string {
	c := tv.GetCell(row, col)
	if c == nil {
		gologger.Error().Msgf(fmt.Sprintf("No cell at location [%d:%d]", row, col), "Trim cell failed!")
		return ""
	}
	return strings.TrimSpace(c.Text)
}

func sortIndicator(sort, asc bool, hc render.HeaderColumn) string {
	if !sort {
		return color.ColorizeAt(hc.Name, hc.SortIndicatorIdx, "wheat", true)
	}

	order := descIndicator
	if asc {
		order = ascIndicator
	}
	return fmt.Sprintf("%s%s", color.ColorizeAt(hc.Name, hc.SortIndicatorIdx, "red", true), color.ColorizeAt(order, 0, "green", false))
}
