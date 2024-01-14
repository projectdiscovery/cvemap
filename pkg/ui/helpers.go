package ui

import (
	"sort"

	"github.com/derailed/tview"
)

func SortMapByKeys(m map[string]tview.Primitive) map[string]tview.Primitive {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	sortedMap := make(map[string]tview.Primitive, len(m))
	for _, k := range keys {
		sortedMap[k] = m[k]
	}
	return sortedMap
}

func SortMapKeys(m map[string]tview.Primitive) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
