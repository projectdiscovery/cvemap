package main

import (
	"embed"
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/cvemap/pkg/runner"
	"github.com/projectdiscovery/cvemap/pkg/view"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

//go:embed suggestion.txt
var content embed.FS

var keywords []string

func init() {
	loadSuggestionKeys()
}

func loadSuggestionKeys() {
	f, err := content.ReadFile("suggestion.txt")
	if err != nil {
		panic(fmt.Sprintf("failed to load suggestion keys %v", err))
	}
	keywords = append(keywords, strings.Split(string(f), "\n")...)
}

func main() {
	options := runner.ParseOptions()

	wt, err := NewFileWriter("cvemap.log")
	if err != nil {
		panic(fmt.Sprintf("failed to create log file %v", err))
	}

	gologger.DefaultLogger.SetWriter(wt)

	app := view.NewApp()
	err = app.Init(runner.Version, *options, keywords)
	if err != nil {
		gologger.Fatal().Msgf("Could not initialize application: %s\n", err)
	}
	if err := app.Run(); err != nil {
		panic(fmt.Sprintf("app run failed %v", err))
	}
}

// FileWriter is a custom implementation of the Writer interface that writes data to a file
type FileWriter struct {
	file *os.File
}

// NewFileWriter creates a new FileWriter that writes to a specified file
func NewFileWriter(filename string) (*FileWriter, error) {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &FileWriter{file: file}, nil
}

// Write writes data to the file
func (fw *FileWriter) Write(data []byte, level levels.Level) {
	// Optionally, you can add timestamp, log level, etc. to the log entry
	logEntry := fmt.Sprintf("[%s] %s", level, string(data))

	_, _ = fw.file.WriteString(logEntry + "\n")
}
