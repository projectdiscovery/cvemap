package color

import (
	"fmt"
	"strconv"
)

const colorFmt = "\x1b[%dm%s\x1b[0m"

// Paint describes a terminal color.
type Paint int

// Defines basic ANSI colors.
const (
	Black     Paint = iota + 30 // 30
	Red                         // 31
	Green                       // 32
	Yellow                      // 33
	Blue                        // 34
	Magenta                     // 35
	Cyan                        // 36
	LightGray                   // 37
	DarkGray  = 90

	Bold = 1
)

// Colorize returns an ASCII colored string based on given color.
func Colorize(s string, c Paint) string {

	if c == 0 {
		return s
	}
	return fmt.Sprintf(colorFmt, c, s)
}

func ColorizeAt(s string, idx int, color string, underscore bool) string {
	if idx < 0 || len(s) <= idx {
		return s
	}
	//colr := color.New(c).FprintfFunc()

	chrs := []rune(s)
	left := string(chrs[:idx])

	mid := fmt.Sprintf("[-:-:-][%s::b]%s[-:-:-]", color, string(chrs[idx]))
	if underscore {
		mid = fmt.Sprintf("[-:-:-][%s::bu]%s[-:-:-]", color, string(chrs[idx]))
	}
	right := string(chrs[idx+1:])
	return fmt.Sprintf("%s%s%s", left, mid, right)
}

// ANSIColorize colors a string.
func ANSIColorize(text string, color int) string {
	return "\033[38;5;" + strconv.Itoa(color) + "m" + text + "\033[0m"
}

// Highlight colorize bytes at given indices.
func Highlight(bb []byte, ii []int, c int) []byte {
	b := make([]byte, 0, len(bb))
	for i, j := 0, 0; i < len(bb); i++ {
		if j < len(ii) && ii[j] == i {
			b = append(b, colorizeByte(bb[i], 209)...)
			j++
		} else {
			b = append(b, bb[i])
		}
	}

	return b
}

func colorizeByte(b byte, color int) []byte {
	return []byte(ANSIColorize(string(b), color))
}
