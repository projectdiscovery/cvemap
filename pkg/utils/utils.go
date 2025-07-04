package utils

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/mattn/go-colorable"
)

const escape = "\x1b"

func format(attr color.Attribute) string {
	return fmt.Sprintf("%s[%dm", escape, attr)
}

// PrintColorYAML prints the given value as colourised YAML to stdout.
// It delegates to the writer-agnostic PrintColorYAMLTo defined in yaml_printer.go.
func PrintColorYAML(v interface{}, header ...string) error {
	return PrintColorYAMLTo(colorable.NewColorableStdout(), v, header...)
}

// PrintColorYAMLNoPager prints the given value as colourised YAML to os.Stdout without colorable pager output.
func PrintColorYAMLNoPager(v interface{}, header ...string) error {
	return PrintColorYAMLTo(os.Stdout, v, header...)
}
