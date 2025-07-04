package utils

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/printer"
	"github.com/mattn/go-colorable"
	cvemap "github.com/projectdiscovery/cvemap"
)

// PrintColorYAMLTo renders a Go value as colourised YAML to the provided
// writer. It uses the same styling rules as the original PrintColorYAML but is
// writer-agnostic so it can be used with pagers, files, etc.
func PrintColorYAMLTo(w io.Writer, v any, header ...string) error {
	yamlStr, err := yaml.MarshalWithOptions(
		v,
		yaml.Indent(2),
		yaml.UseLiteralStyleIfMultiline(true),
	)
	if err != nil {
		return err
	}

	var headerStr string
	if len(header) > 0 && strings.TrimSpace(header[0]) != "" {
		headerStr = header[0]
	}

	tokens := lexer.Tokenize(string(yamlStr))
	var p printer.Printer
	p.LineNumber = true
	p.LineNumberFormat = func(num int) string {
		return fmt.Sprintf("%s%4d │ %s", format(color.FgHiBlack), num, format(color.Reset))
	}
	p.Bool = func() *printer.Property {
		return &printer.Property{Prefix: format(color.FgYellow), Suffix: format(color.Reset)}
	}
	p.Number = p.Bool
	p.MapKey = func() *printer.Property {
		return &printer.Property{Prefix: format(color.FgBlue), Suffix: format(color.Reset)}
	}
	p.Anchor = func() *printer.Property {
		return &printer.Property{Prefix: format(color.FgMagenta), Suffix: format(color.Reset)}
	}
	p.Alias = p.Anchor
	p.String = func() *printer.Property {
		return &printer.Property{Prefix: format(color.FgGreen), Suffix: format(color.Reset)}
	}
	p.Comment = func() *printer.Property {
		return &printer.Property{Prefix: format(color.FgWhite), Suffix: format(color.Reset)}
	}

	var out io.Writer
	if w == os.Stdout {
		out = colorable.NewColorableStdout()
	} else {
		out = w
	}

	if headerStr != "" {
		prefix := "     │ "
		if _, err = fmt.Fprintf(out, "%s%s%s%s\n", format(color.FgHiBlack), prefix, headerStr, format(color.Reset)); err != nil {
			return err
		}
		sep := strings.Repeat("-", len([]rune(prefix+headerStr)))
		if _, err = fmt.Fprintf(out, "%s%s%s\n", format(color.FgHiBlack), sep, format(color.Reset)); err != nil {
			return err
		}
	}

	_, err = out.Write([]byte(p.PrintTokens(tokens) + "\n"))
	return err
}

// PrintYaml streams an entire SearchResponse through a pager (if possible).
// The first page shows summary (count/total/facets); each subsequent page shows
// one vulnerability. Page boundaries are separated using the form-feed
// `pageBreak` so pagers like `less` clear the screen between sections.
func PrintYaml(resp cvemap.SearchResponse, disablePager bool) error {
	w, closePager, err := OpenPager(disablePager)
	if err != nil {
		w = os.Stdout
		closePager = func() error { return nil }
	}
	defer closePager()

	// 1. Summary page
	summary := struct {
		Count  int            `json:"count"`
		Total  int            `json:"total"`
		Facets map[string]any `json:"facets,omitempty"`
	}{
		Count:  resp.Count,
		Total:  resp.Total,
		Facets: resp.Facets,
	}
	if err := PrintColorYAMLTo(w, summary, "Search Summary"); err != nil {
		return err
	}

	if len(resp.Results) > 0 {
		if _, err := io.WriteString(w, pageBreak); err != nil {
			return err
		}
	}

	// 2. One page per vulnerability
	for i, v := range resp.Results {
		hdr := fmt.Sprintf("(%d/%d) %s", i+1, len(resp.Results), v.CVEID)
		if err := PrintColorYAMLTo(w, v, hdr); err != nil {
			return err
		}
		if i < len(resp.Results)-1 {
			if _, err := io.WriteString(w, pageBreak); err != nil {
				return err
			}
		}
	}
	return nil
}
