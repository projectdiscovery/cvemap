package render

import "github.com/projectdiscovery/gologger"

// HeaderColumn represent a table header.
// SortIndicatorIdx is the position of alphabet in header name to highlight.
// Set SortIndicatorIdx to -1 to ignore highlighting any alphabet in header name.
type HeaderColumn struct {
	Name             string
	SortIndicatorIdx int
	Align            int
	Hide             bool
	Wide             bool
	MX               bool
	Time             bool
}

// Clone copies a header.
func (h HeaderColumn) Clone() HeaderColumn {
	return h
}

// ----------------------------------------------------------------------------

// Header represents a table header.
type Header []HeaderColumn

// Clone duplicates a header.
func (h Header) Clone() Header {
	header := make(Header, len(h))
	for i, c := range h {
		header[i] = c.Clone()
	}

	return header
}

// Columns return header as a collection of strings.
func (h Header) Columns(wide bool) []string {
	if len(h) == 0 {
		return nil
	}
	cc := make([]string, 0, len(h))
	for _, c := range h {
		if !wide && c.Wide {
			continue
		}
		cc = append(cc, c.Name)
	}

	return cc
}

// MapIndices returns a collection of mapped column indices based of the requested columns.
func (h Header) MapIndices(cols []string, wide bool) []int {
	ii := make([]int, 0, len(cols))
	cc := make(map[int]struct{}, len(cols))
	for _, col := range cols {
		idx := h.IndexOf(col, true)
		if idx < 0 {
			gologger.Info().Msgf("Column %q not found on resource", col)
		}
		ii, cc[idx] = append(ii, idx), struct{}{}
	}
	if !wide {
		return ii
	}

	for i := range h {
		if _, ok := cc[i]; ok {
			continue
		}
		ii = append(ii, i)
	}
	return ii
}

// Customize builds a header from custom col definitions.
func (h Header) Customize(cols []string, wide bool) Header {
	if len(cols) == 0 {
		return h
	}
	cc := make(Header, 0, len(h))
	xx := make(map[int]struct{}, len(h))
	for _, c := range cols {
		idx := h.IndexOf(c, true)
		if idx == -1 {
			gologger.Debug().Msgf("Column %s is not available on this resource", c)
			col := HeaderColumn{
				Name: c,
			}
			cc = append(cc, col)
			continue
		}
		xx[idx] = struct{}{}
		col := h[idx].Clone()
		col.Wide = false
		cc = append(cc, col)
	}

	if !wide {
		return cc
	}

	for i, c := range h {
		if _, ok := xx[i]; ok {
			continue
		}
		col := c.Clone()
		col.Wide = true
		cc = append(cc, col)
	}

	return cc
}

// IsMetricsCol checks if given column index represents metrics.
func (h Header) IsMetricsCol(col int) bool {
	if col < 0 || col >= len(h) {
		return false
	}

	return h[col].MX
}

// IsTimeCol checks if given column index represents a timestamp.
func (h Header) IsTimeCol(col int) bool {
	if col < 0 || col >= len(h) {
		return false
	}

	return h[col].Time
}

// IndexOf returns the col index or -1 if none.
func (h Header) IndexOf(colName string, includeWide bool) int {
	for i, c := range h {
		if c.Wide && !includeWide {
			continue
		}
		if c.Name == colName {
			return i
		}
	}
	return -1
}

// Dump for debugging.
func (h Header) Dump() {
	gologger.Debug().Msgf("HEADER")
	for i, c := range h {
		gologger.Debug().Msgf("%d %q -- %t", i, c.Name, c.Wide)
	}
}
