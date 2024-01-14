package view

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/derailed/tcell/v2"
	"github.com/projectdiscovery/cvemap/pkg/ui"
	"github.com/projectdiscovery/gologger"
)

const (
	DefaultRefreshRate = time.Second * 20
)

// Table represents a table viewer.
type Table struct {
	*ui.Table

	app        *App
	enterFn    EnterFunc
	bindKeysFn []BindKeysFunc
}

// NewTable returns a new viewer.
func NewTable(res string) *Table {
	t := Table{
		Table: ui.NewTable(res),
	}
	return &t
}

// Init initializes the component.
func (t *Table) Init(ctx context.Context) (err error) {
	if t.app, err = extractApp(ctx); err != nil {
		return err
	}

	t.Table.Init(ctx)
	t.SetInputCapture(t.keyboard)
	t.bindKeys()
	t.GetModel().SetRefreshRate(DefaultRefreshRate)

	return nil
}

// App returns the current app handle.
func (t *Table) App() *App {
	return t.app
}

// Start runs the component.
func (t *Table) Start() {
}

// Stop terminates the component.
func (t *Table) Stop() {
}

// SetEnterFn specifies the default enter behavior.
func (t *Table) SetEnterFn(f EnterFunc) {
	t.enterFn = f
}

func (t *Table) keyboard(evt *tcell.EventKey) *tcell.EventKey {
	key := evt.Key()
	if key == tcell.KeyUp || key == tcell.KeyDown {
		return evt
	}

	if a, ok := t.Actions()[ui.AsKey(evt)]; ok {
		return a.Action(evt)
	}

	return evt
}

func (t *Table) bindKeys() {
	t.Actions().Add(ui.KeyActions{
		tcell.KeyCtrlW: ui.NewKeyAction("Toggle Wide", t.toggleWideCmd, false),
		ui.KeyHelp:     ui.NewKeyAction("Help", t.App().helpCmd, true),
		ui.KeyZ:        ui.NewKeyAction("Import as csv", t.importAsCSV, true),
	})
}

// Name returns the table name.
func (t *Table) Name() string { return t.Table.Resource() }

// AddBindKeysFn adds additional key bindings.
func (t *Table) AddBindKeysFn(f BindKeysFunc) {
	t.bindKeysFn = append(t.bindKeysFn, f)
}

func (t *Table) toggleWideCmd(evt *tcell.EventKey) *tcell.EventKey {
	t.ToggleWide()
	return nil
}
func (t *Table) importAsCSV(evt *tcell.EventKey) *tcell.EventKey {

	var tableData [][]string
	rowCount := t.GetRowCount()
	colCount := t.GetColumnCount()
	for i := 0; i < rowCount; i++ {
		var row []string
		for j := 0; j < colCount; j++ {
			text := t.GetCell(i, j).Text
			text = decolorize(text)
			row = append(row, text)
		}
		tableData = append(tableData, row)
	}
	usr, err := user.Current()
	if err != nil {
		gologger.Info().Msg(fmt.Sprintf("error in getting the machine's user: %v", err))
		return nil
	}
	path := usr.HomeDir + "/.cvemap"
	err = os.MkdirAll(path, os.ModePerm)
	if err != nil {
		gologger.Info().Msg(fmt.Sprintf("error in creating csv directory: %v", err))
		return nil
	}
	path = filepath.Join(path + "/" + "data.csv")

	file, err := os.Create(path)
	if err != nil {
		gologger.Info().Msg(fmt.Sprintf("error in creating csv file: %v", err))
		return nil
	}
	writer := csv.NewWriter(file)
	for _, record := range tableData {
		err := writer.Write(record)
		if err != nil {
			gologger.Info().Msg(fmt.Sprintf("error in writing records to csv file: %v", err))
			return nil
		}
	}
	writer.Flush()
	t.app.Flash().Info("CSV file created and CSV file path copied to clipboard.")
	clipboard.WriteAll(path)
	return nil
}

func decolorize(input string) string {
	input = strings.Replace(input, "↑", "", 1)
	input = strings.Replace(input, "↓", "", 1)
	re := regexp.MustCompile(`\[.*?\]`)
	return re.ReplaceAllString(input, "")
}
