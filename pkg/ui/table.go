package ui

import (
	"context"
	"fmt"
	"strings"

	"github.com/derailed/tcell/v2"
	"github.com/derailed/tview"
	"github.com/projectdiscovery/cvemap/pkg/model"
	"github.com/projectdiscovery/cvemap/pkg/render"
	"github.com/projectdiscovery/gologger"
)

// Table represents tabular data.
type Table struct {
	resource string
	sortCol  SortColumn
	header   render.Header
	*SelectTable
	actions KeyActions
	wide    bool
	toast   bool
}

// NewTable returns a new table view.
func NewTable(res string) *Table {
	return &Table{
		SelectTable: &SelectTable{
			Table: tview.NewTable(),
			model: model.NewTable(res),
			marks: make(map[string]struct{}),
		},
		resource: res,
		actions:  make(KeyActions),
	}
}

// Init initializes the component.
func (t *Table) Init(ctx context.Context) {
	t.SetFixed(1, 0)
	t.SetBorder(true)
	t.SetBorderColor(tcell.ColorLightSkyBlue)
	t.SetBorderFocusColor(tcell.ColorDeepSkyBlue)
	t.SetBorderPadding(0, 0, 1, 1)
	t.SetSelectable(true, false)
	t.SetSelectionChangedFunc(t.selectionChanged)
	t.SetBackgroundColor(tcell.ColorDefault)
	t.Select(1, 0)
}

func (t *Table) Resource() string { return t.resource }

// ResetToast resets toast flag.
func (t *Table) ResetToast() {
	t.toast = false
	t.Refresh()
}

// ToggleToast toggles to show toast resources.
func (t *Table) ToggleToast() {
	t.toast = !t.toast
	t.Refresh()
}

// ToggleWide toggles wide col display.
func (t *Table) ToggleWide() {
	t.wide = !t.wide
	t.Refresh()
}

// Actions returns active menu bindings.
func (t *Table) Actions() KeyActions {
	return t.actions
}

// Hints returns the view hints.
func (t *Table) Hints() model.MenuHints {
	return t.actions.Hints()
}

// Update table content.
func (t *Table) Update(data *render.TableData) {
	t.header = data.Header
	t.doUpdate(data)
	t.UpdateTitle()
}

func (t *Table) doUpdate(data *render.TableData) {
	cols := t.header.Columns(t.wide)

	custData := data.Customize(cols, t.wide)
	t.Clear()
	var col int
	for _, h := range custData.Header {
		t.AddHeaderCell(col, h)
		col++
	}

	colIndex := custData.Header.IndexOf(t.sortCol.name, false)
	custData.RowEvents.Sort(
		colIndex,
		custData.Header.IsTimeCol(colIndex),
		custData.Header.IsMetricsCol(colIndex),
		t.sortCol.asc,
	)

	for row, re := range custData.RowEvents {
		idx, _ := data.RowEvents.FindIndex(re.Row.ID)
		t.buildRow(row+1, re, data.RowEvents[idx], custData.Header)
	}
	t.updateSelection(true)
}

func (t *Table) buildRow(r int, re, ore render.RowEvent, h render.Header) {

	marked := t.IsMarked(re.Row.ID)
	var col int
	for c, field := range re.Row.Fields {
		if c >= len(h) {
			gologger.Error().Msgf("field/header overflow detected for %q -- %d::%d. Check your mappings!", t.resource, c, len(h))
			continue
		}

		if h[c].Hide {
			col++
			continue
		}

		cell := tview.NewTableCell(field)
		cell.SetAttributes(tcell.AttrNone)
		cell.SetTextColor(tcell.ColorSkyblue)
		cell.SetExpansion(1)
		cell.SetAlign(h[c].Align)
		if marked {
			cell.SetTextColor(tcell.ColorOrangeRed)
		}
		if col == 0 {
			cell.SetReference(re.Row.ID)
		}

		t.SetCell(r, col, cell)
		col++
	}
}

// AddHeaderCell configures a table cell header.
func (t *Table) AddHeaderCell(col int, h render.HeaderColumn) {
	if h.Hide {
		return
	}
	sort := h.Name == t.sortCol.name
	//c := tview.NewTableCell(sortIndicator(sort, t.sortCol.asc, h))
	c := tview.NewTableCell(sortIndicator(sort, t.sortCol.asc, h))
	c.SetTextColor(tcell.ColorBeige)
	c.SetAttributes(tcell.AttrBold)
	c.SetExpansion(1)
	c.SetAlign(h.Align)
	t.SetCell(0, col, c)
}

// ClearMarks clear out marked items.
func (t *Table) ClearMarks() {
	t.SelectTable.ClearMarks()
	t.Refresh()
}

// Refresh update the table data.
func (t *Table) Refresh() {
	data := t.model.Peek()
	if len(data.Header) == 0 {
		return
	}
	// BOZO!! Really want to tell model reload now. Refactor!
	t.Update(data)
}

// UpdateTitle refreshes the table title.
func (t *Table) UpdateTitle() {
	title := strings.Join([]string{" ", strings.ToUpper(t.Resource()), " "}, "")
	t.SetTitle(fmt.Sprintf("[aqua::b]%s", title))
}

// SortColCmd designates a sorted column.
func (t *Table) SortColCmd(name string, asc bool) func(evt *tcell.EventKey) *tcell.EventKey {
	return func(evt *tcell.EventKey) *tcell.EventKey {
		t.sortCol.asc = !t.sortCol.asc
		if t.sortCol.name != name {
			t.sortCol.asc = asc
		}
		t.sortCol.name = name
		t.Refresh()
		return nil
	}
}
