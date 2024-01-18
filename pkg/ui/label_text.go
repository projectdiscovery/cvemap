package ui

import (
    "github.com/derailed/tview"
    "github.com/derailed/tcell/v2"
)

// InfoPrimitive is a custom primitive to display version and label-value pairs.
type InfoPrimitive struct {
    *tview.Box
    Labels  map[string]string
}

// NewInfoPrimitive creates a new InfoPrimitive.
func NewInfoPrimitive(version string, labels map[string]string) *InfoPrimitive {
    return &InfoPrimitive{
        Box:    tview.NewBox().SetBorder(false),
        Labels:  labels,
    }
}

// Draw draws the primitive onto the screen.
func (i *InfoPrimitive) Draw(screen tcell.Screen) {
    i.Box.Draw(screen)

    // Draw the version
    // tview.Print(screen, "Version:", 1, 1, 8, tview.AlignRight, tcell.ColorYellow)
    // tview.Print(screen, i.Version, 10, 1, len(i.Version), tview.AlignLeft, tcell.ColorWhite)

    // Draw the labels
    y := 1
    for label, value := range i.Labels {
        tview.Print(screen, label+":", 1, y, len(label)+1, tview.AlignRight, tcell.ColorDarkOrange)
        tview.Print(screen, value, 10, y, len(value), tview.AlignLeft, tcell.ColorWhite)
        y++
    }
}
