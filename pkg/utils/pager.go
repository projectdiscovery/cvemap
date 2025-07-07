package utils

import (
	"io"
	"os"
	"os/exec"

	isatty "github.com/mattn/go-isatty"
)

// pageBreak is an ASCII Form-Feed (0x0c) that most pagers (e.g. `less`) treat
// as a "clear-screen" marker, giving the user a visual hard page boundary.
const pageBreak = "\f"

// OpenPager returns a writer that streams to the system pager (defined by
// $PAGER or falling back to "less -R -N -M") when stdout is an interactive
// TTY. A no-op cleanup function is always returned; the caller *must* defer it.
//
// If paging is not possible (stdout is not a terminal or the pager cannot be
// launched) the function degrades gracefully and simply returns os.Stdout so
// the caller can continue writing directly to the console.
func OpenPager(disablePager bool) (io.WriteCloser, func() error, error) {
	// If pager is disabled or stdout isn't a terminal (piped to file/program) don't page.
	if disablePager || !isatty.IsTerminal(os.Stdout.Fd()) {
		return os.Stdout, func() error { return nil }, nil
	}

	// Check for required binaries: 'sh' and 'less'
	if _, err := exec.LookPath("sh"); err != nil {
		return os.Stdout, func() error { return nil }, nil
	}
	if _, err := exec.LookPath("less"); err != nil {
		return os.Stdout, func() error { return nil }, nil
	}

	pager := os.Getenv("PAGER")
	if pager == "" {
		// -R keep colours, -N add line numbers, -M verbose status line
		pager = "less -R -N -M"
	}

	// Use `sh -c` so we respect flags inside $PAGER.
	cmd := exec.Command("sh", "-c", pager)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	w, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	cleanup := func() error {
		_ = w.Close()
		return cmd.Wait()
	}
	return w, cleanup, nil
}
