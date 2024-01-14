package render

import (
	"fmt"
	"strings"
)

// Alias renders a aliases to screen.
type Alias struct {
}

// Header returns a header row.
func (Alias) Header(ns string) Header {
	return Header{
		HeaderColumn{Name: "RESOURCE"},
		HeaderColumn{Name: "COMMAND"},
	}
}

// BOZO!! Pass in a row with pre-alloc fields??
func (Alias) Render(o interface{}, ns string, r *Row) error {
	a, ok := o.(AliasRes)
	if !ok {
		return fmt.Errorf("expected AliasRes, but got %T", o)
	}

	r.ID = a.Resource
	r.Fields = append(r.Fields,
		a.Resource,
		strings.Join(a.Aliases, ","),
	)

	return nil
}

// ----------------------------------------------------------------------------
// Helpers...

// AliasRes represents an alias resource.
type AliasRes struct {
	Resource string
	Aliases  []string
}

// DeepCopyObject returns a container copy.
func (a AliasRes) DeepCopyObject() interface{} {
	return a
}
