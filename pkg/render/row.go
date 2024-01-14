package render

import (
	"strings"

	"github.com/fvbommel/sortorder"
)

// Fields represents a collection of row fields.
type Fields []string

// Customize returns a subset of fields.
func (f Fields) Customize(cols []int, out Fields) {
	for i, c := range cols {
		if c < 0 {
			continue
		}
		if c < len(f) {
			out[i] = f[c]
		}
	}
}

// Clone returns a copy of the fields.
func (f Fields) Clone() Fields {
	cp := make(Fields, len(f))
	copy(cp, f)

	return cp
}

// ----------------------------------------------------------------------------

// Row represents a collection of columns.
type Row struct {
	ID     string
	Fields Fields
}

// NewRow returns a new row with initialized fields.
func NewRow(size int) Row {
	return Row{Fields: make([]string, size)}
}

// Customize returns a row subset based on given col indices.
func (r Row) Customize(cols []int) Row {
	out := NewRow(len(cols))
	r.Fields.Customize(cols, out.Fields)
	out.ID = r.ID

	return out
}

// Clone copies a row.
func (r Row) Clone() Row {
	return Row{
		ID:     r.ID,
		Fields: r.Fields.Clone(),
	}
}

// Len returns the length of the row.
func (r Row) Len() int {
	return len(r.Fields)
}

// ----------------------------------------------------------------------------

// Rows represents a collection of rows.
type Rows []Row

// Delete removes an element by id.
func (rr Rows) Delete(id string) Rows {
	idx, ok := rr.Find(id)
	if !ok {
		return rr
	}

	if idx == 0 {
		return rr[1:]
	}
	if idx+1 == len(rr) {
		return rr[:len(rr)-1]
	}

	return append(rr[:idx], rr[idx+1:]...)
}

// Upsert adds a new item.
func (rr Rows) Upsert(r Row) Rows {
	idx, ok := rr.Find(r.ID)
	if !ok {
		return append(rr, r)
	}
	rr[idx] = r

	return rr
}

// Find locates a row by id. Returns false is not found.
func (rr Rows) Find(id string) (int, bool) {
	for i, r := range rr {
		if r.ID == id {
			return i, true
		}
	}

	return 0, false
}

// ----------------------------------------------------------------------------
// Helpers...

// Less return true if c1 < c2.
func Less(isNumber, isDuration bool, id1, id2, v1, v2 string) bool {
	var less bool
	switch {
	case isNumber:
		v1, v2 = strings.Replace(v1, ",", "", -1), strings.Replace(v2, ",", "", -1)
		less = sortorder.NaturalLess(v1, v2)
	case isDuration:
		d1, d2 := durationToSeconds(v1), durationToSeconds(v2)
		less = d1 <= d2
	default:
		less = sortorder.NaturalLess(v1, v2)
	}
	if v1 == v2 {
		return sortorder.NaturalLess(id1, id2)
	}

	return less
}
