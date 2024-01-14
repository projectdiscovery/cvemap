package render

import "sync"

type TableData struct {
	Header    Header
	RowEvents RowEvents
	mx        sync.RWMutex
}

// NewTableData returns a new table.
func NewTableData() *TableData {
	return &TableData{}
}

// Empty checks if there are no entries.
func (t *TableData) Empty() bool {
	t.mx.RLock()
	defer t.mx.RUnlock()

	return len(t.RowEvents) == 0
}

// Count returns the number of entries.
func (t *TableData) Count() int {
	t.mx.RLock()
	defer t.mx.RUnlock()

	return len(t.RowEvents)
}

// IndexOfHeader return the index of the header.
func (t *TableData) IndexOfHeader(h string) int {
	return t.Header.IndexOf(h, false)
}

// Customize returns a new model with customized column layout.
func (t *TableData) Customize(cols []string, wide bool) *TableData {
	res := TableData{
		Header:    t.Header.Customize(cols, wide),
	}
	ids := t.Header.MapIndices(cols, wide)
	res.RowEvents = t.RowEvents.Customize(ids)

	return &res
}


// Clear clears out the entire table.
func (t *TableData) Clear() {
	t.Header, t.RowEvents = Header{}, RowEvents{}
}

// Clone returns a copy of the table.
func (t *TableData) Clone() *TableData {
	return &TableData{
		Header:    t.Header.Clone(),
		RowEvents: t.RowEvents.Clone(),
	}
}

// SetHeader sets table header.
func (t *TableData) SetHeader(h Header) {
	t.Header = h
}

// Update computes row deltas and update the table data.
func (t *TableData) Update(rows Rows) {
	empty := t.Empty()
	kk := make(map[string]struct{}, len(rows))
	t.mx.Lock()
	{
		for _, row := range rows {
			kk[row.ID] = struct{}{}
			if empty {
				t.RowEvents = append(t.RowEvents, NewRowEvent(EventAdd, row))
				continue
			}
			t.RowEvents = append(t.RowEvents, NewRowEvent(EventAdd, row))
		}
	}
	t.mx.Unlock()

	if !empty {
		t.Delete(kk)
	}
}

// Delete removes items in cache that are no longer valid.
func (t *TableData) Delete(newKeys map[string]struct{}) {
	t.mx.Lock()
	{
		var victims []string
		for _, re := range t.RowEvents {
			if _, ok := newKeys[re.Row.ID]; !ok {
				victims = append(victims, re.Row.ID)
			}
		}
		for _, id := range victims {
			t.RowEvents = t.RowEvents.Delete(id)
		}
	}
	t.mx.Unlock()
}
