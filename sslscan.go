package sslscan

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// ScanRunner represents something that can run a scan.
type ScanRunner interface {
	Run() (result *Run, warnings []string, err error)
}

// Streamer constantly streams the stdout.
type Streamer interface {
	Write(d []byte) (int, error)
	Bytes() []byte
}

// Scanner represents an Nmap scanner.
type Scanner struct {
	cmd *exec.Cmd

	args       []string
	binaryPath string
	ctx        context.Context
	target     string

	// portFilter func(Port) bool
	// hostFilter func(Host) bool

	stderr, stdout bufio.Scanner
}

// Option is a function that is used for grouping of Scanner options.
// Option adds or removes nmap command line arguments.
type Option func(*Scanner)

// NewScanner creates a new Scanner, and can take options to apply to the scanner.
func NewScanner(options ...Option) (*Scanner, error) {
	scanner := &Scanner{}

	for _, option := range options {
		option(scanner)
	}

	if scanner.binaryPath == "" {
		var err error
		scanner.binaryPath, err = exec.LookPath("sslscan")
		if err != nil {
			return nil, ErrNmapNotInstalled
		}
	}

	if scanner.ctx == nil {
		scanner.ctx = context.Background()
	}

	return scanner, nil
}

// Run runs nmap synchronously and returns the result of the scan.
func (s *Scanner) Run() (result *Run, warnings []string, err error) {
	var (
		stdout, stderr bytes.Buffer
		// resume         bool
	)

	args := s.args

	// for _, arg := range args {
	// 	if arg == "--resume" {
	// 		resume = true
	// 		break
	// 	}
	// }

	// if !resume {
	// Enable XML output
	args = append(args, "--xml=-")
	// args = append(args, "cgcnets.com")

	// Get XML output in stdout instead of writing it in a file
	// args = append(args, "-")
	// }

	// Add Target to Command
	args = append(args, s.target)

	// Prepare nmap process
	cmd := exec.Command(s.binaryPath, args...)
	// cmd := exec.Command("cat", "text2.xml")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run nmap process
	err = cmd.Start()
	if err != nil {
		return nil, warnings, err
	}

	// Make a goroutine to notify the select when the scan is done.
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Wait for nmap process or timeout
	select {
	case <-s.ctx.Done():

		// Context was done before the scan was finished.
		// The process is killed and a timeout error is returned.
		_ = cmd.Process.Kill()

		return nil, warnings, ErrScanTimeout
	case <-done:

		// Process nmap stderr output containing none-critical errors and warnings
		// Everyone needs to check whether one or some of these warnings is a hard issue in their use case
		// if stderr.Len() > 0 {
		// 	warnings = strings.Split(strings.Trim(stderr.String(), "\n"), "\n")
		// }

		// Check for warnings that will inevitably lead to parsing errors, hence, have priority.
		// if err := analyzeWarnings(warnings); err != nil {
		// 	return nil, warnings, err
		// }

		// Parse nmap xml output. Usually nmap always returns valid XML, even if there is a scan error.
		// Potentially available warnings are returned too, but probably not the reason for a broken XML.
		result, err := Parse(stdout.Bytes())
		if err != nil {
			fmt.Println(err)
			warnings = append(warnings, err.Error()) // Append parsing error to warnings for those who are interested.
			return nil, warnings, ErrParseOutput
		}

		// // Critical scan errors are reflected in the XML.
		// if result != nil && len(result.Stats.Finished.ErrorMsg) > 0 {
		// 	switch {
		// 	case strings.Contains(result.Stats.Finished.ErrorMsg, "Error resolving name"):
		// 		return result, warnings, ErrResolveName
		// 	// TODO: Add cases for other known errors we might want to guard.
		// 	default:
		// 		return result, warnings, fmt.Errorf(result.Stats.Finished.ErrorMsg)
		// 	}
		// }

		// // Call filters if they are set.
		// if s.portFilter != nil {
		// 	result = choosePorts(result, s.portFilter)
		// }
		// if s.hostFilter != nil {
		// 	result = chooseHosts(result, s.hostFilter)
		// }

		// Return result, optional warnings but no error
		return result, warnings, nil
	}
}

// WithContext adds a context to a scanner, to make it cancellable and able to timeout.
func WithContext(ctx context.Context) Option {
	return func(s *Scanner) {
		s.ctx = ctx
	}
}

func WithTarget(target string) Option {
	return func(s *Scanner) {
		s.target = target
	}
}
