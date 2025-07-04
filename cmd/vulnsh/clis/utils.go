package clis

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/printer"
	"github.com/mattn/go-colorable"
)

const escape = "\x1b"

func format(attr color.Attribute) string {
	return fmt.Sprintf("%s[%dm", escape, attr)
}

// PrintColorYAML prints the given value as colorized YAML to stdout.
// If a header string is provided, it is rendered above the YAML output in a style
// similar to the "bat" utility.
//
// Example:
//
//	PrintColorYAML(data)                     // prints YAML only
//	PrintColorYAML(data, "Vulnerability ID: CVE-2021-xyz") // prints header + YAML
func PrintColorYAML(v interface{}, header ...string) error {
	yamlStr, err := yaml.MarshalWithOptions(
		v,
		yaml.Indent(2),
		yaml.UseLiteralStyleIfMultiline(true),
	)
	if err != nil {
		return err
	}

	// Prepare header, if provided.
	var headerStr string
	if len(header) > 0 && strings.TrimSpace(header[0]) != "" {
		headerStr = header[0]
	}

	tokens := lexer.Tokenize(string(yamlStr))
	var p printer.Printer
	p.LineNumber = true
	p.LineNumberFormat = func(num int) string {
		// Format line numbers similar to the `bat` utility.
		// 1. Right-align numbers in a 4-character field.
		// 2. Prepend them with a dim grey colour for better readability.
		// 3. Append a thin vertical bar separator followed by a space.
		// Example output: "   7 │ "
		ln := fmt.Sprintf("%4d │ ", num)
		return fmt.Sprintf("%s%s%s", format(color.FgHiBlack), ln, format(color.Reset))
	}
	p.Bool = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgYellow),
			Suffix: format(color.Reset),
		}
	}
	p.Number = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgYellow),
			Suffix: format(color.Reset),
		}
	}
	p.MapKey = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgBlue),
			Suffix: format(color.Reset),
		}
	}
	p.Anchor = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgMagenta),
			Suffix: format(color.Reset),
		}
	}
	p.Alias = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgMagenta),
			Suffix: format(color.Reset),
		}
	}
	p.String = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgGreen),
			Suffix: format(color.Reset),
		}
	}
	p.Comment = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgWhite),
			Suffix: format(color.Reset),
		}
	}
	writer := colorable.NewColorableStdout()

	// Render header if present.
	if headerStr != "" {
		// Prefix matches the width used by the line numbers: 4 spaces + " │ " (space, unicode bar, space)
		headerPrefix := "     │ "
		// Dim grey colour for header prefix and text
		coloredHeader := fmt.Sprintf("%s%s%s%s", format(color.FgHiBlack), headerPrefix, headerStr, format(color.Reset))
		if _, err = writer.Write([]byte(coloredHeader + "\n")); err != nil {
			return err
		}

		// Separator line using dashes. Length equals headerPrefix + headerStr.
		sepLen := len([]rune(headerPrefix + headerStr))
		if sepLen < 1 {
			sepLen = 1
		}
		separator := strings.Repeat("-", sepLen)
		// Use the same dim grey colour for the horizontal separator as the header line.
		coloredSeparator := fmt.Sprintf("%s%s%s", format(color.FgHiBlack), separator, format(color.Reset))
		if _, err = writer.Write([]byte(coloredSeparator + "\n")); err != nil {
			return err
		}
	}

	_, err = writer.Write([]byte(p.PrintTokens(tokens) + "\n"))
	return err
}
