package render

import "sort"

const (
	// EventUnchanged notifies listener resource has not changed.
	EventUnchanged ResEvent = 1 << iota

	// EventAdd notifies listener of a resource was added.
	EventAdd

	// EventUpdate notifies listener of a resource updated.
	EventUpdate

	// EventDelete  notifies listener of a resource was deleted.
	EventDelete

	// EventClear the stack was reset.
	EventClear
)

// ResEvent represents a resource event.
type ResEvent int

// RowEvent tracks resource instance events.
type RowEvent struct {
	Kind ResEvent
	Row  Row
}

// NewRowEvent returns a new row event.
func NewRowEvent(kind ResEvent, row Row) RowEvent {
	return RowEvent{
		Kind: kind,
		Row:  row,
	}
}

// Customize returns a new subset based on the given column indices.
func (r RowEvent) Customize(cols []int) RowEvent {
	return RowEvent{
		Kind: r.Kind,
		Row:  r.Row.Customize(cols),
	}
}

// Clone returns a row event deep copy.
func (r RowEvent) Clone() RowEvent {
	return RowEvent{
		Kind: r.Kind,
		Row:  r.Row.Clone(),
	}
}

// ----------------------------------------------------------------------------

// RowEvents a collection of row events.
type RowEvents []RowEvent

// Customize returns custom row events based on columns layout.
func (r RowEvents) Customize(cols []int) RowEvents {
	ee := make(RowEvents, 0, len(cols))
	for _, re := range r {
		ee = append(ee, re.Customize(cols))
	}
	return ee
}

// Clone returns a rowevents deep copy.
func (r RowEvents) Clone() RowEvents {
	res := make(RowEvents, len(r))
	for i, re := range r {
		res[i] = re.Clone()
	}

	return res
}

// Upsert add or update a row if it exists.
func (r RowEvents) Upsert(re RowEvent) RowEvents {
	if idx, ok := r.FindIndex(re.Row.ID); ok {
		r[idx] = re
	} else {
		r = append(r, re)
	}
	return r
}

// Delete removes an element by id.
func (r RowEvents) Delete(id string) RowEvents {
	victim, ok := r.FindIndex(id)
	if !ok {
		return r
	}
	return append(r[0:victim], r[victim+1:]...)
}

// Clear delete all row events.
func (r RowEvents) Clear() RowEvents {
	return RowEvents{}
}

// FindIndex locates a row index by id. Returns false is not found.
func (r RowEvents) FindIndex(id string) (int, bool) {
	for i, re := range r {
		if re.Row.ID == id {
			return i, true
		}
	}

	return 0, false
}

// Sort rows based on column index and order.
func (r RowEvents) Sort(sortCol int, isDuration, numCol, asc bool) {
	if sortCol == -1 {
		return
	}

	t := RowEventSorter{
		Events:     r,
		Index:      sortCol,
		Asc:        asc,
		IsNumber:   numCol,
		IsDuration: isDuration,
	}
	sort.Sort(t)
}

// ----------------------------------------------------------------------------

// RowEventSorter sorts row events by a given colon.
type RowEventSorter struct {
	Events     RowEvents
	Index      int
	IsNumber   bool
	IsDuration bool
	Asc        bool
}

func (r RowEventSorter) Len() int {
	return len(r.Events)
}

func (r RowEventSorter) Swap(i, j int) {
	r.Events[i], r.Events[j] = r.Events[j], r.Events[i]
}

func (r RowEventSorter) Less(i, j int) bool {
	f1, f2 := r.Events[i].Row.Fields, r.Events[j].Row.Fields
	id1, id2 := r.Events[i].Row.ID, r.Events[j].Row.ID
	less := Less(r.IsNumber, r.IsDuration, id1, id2, f1[r.Index], f2[r.Index])
	if r.Asc {
		return less
	}

	return !less
}
