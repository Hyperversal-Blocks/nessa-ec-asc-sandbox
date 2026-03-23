package asc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// RunOptions configures execution of the Python ASC demo core.
type RunOptions struct {
	Deterministic bool
	Benchmark     bool
	RootArtifacts bool

	ArtifactsDir string
	ReportPath   string

	PythonBinary string
	PythonRoot   string
}

// Run executes the Python ASC end-to-end flow and returns the JSON result.
//
// This function intentionally integrates the existing Python protocol core
// without rewriting cryptographic or protocol logic in Go.
func Run(ctx context.Context, opts RunOptions) (map[string]any, error) {
	pythonRoot, err := resolvePythonRoot(opts.PythonRoot)
	if err != nil {
		return nil, err
	}
	pythonBin := resolvePythonBin(opts.PythonBinary)
	return runPythonJSON(ctx, pythonBin, pythonRoot, buildArgs(opts), nil)
}

func resolvePythonBin(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if fromEnv := os.Getenv("NESSA_PYTHON_BIN"); fromEnv != "" {
		return fromEnv
	}
	return "python3"
}

func buildArgs(opts RunOptions) []string {
	args := []string{"app.py", "asc-ad-demo", "--json"}
	if opts.Deterministic {
		args = append(args, "--deterministic")
	}
	if opts.Benchmark {
		args = append(args, "--benchmark")
	}
	if opts.ArtifactsDir != "" {
		args = append(args, "--artifacts-dir", opts.ArtifactsDir)
	}
	if opts.RootArtifacts {
		args = append(args, "--root-artifacts")
	}
	if opts.ReportPath != "" {
		args = append(args, "--report", opts.ReportPath)
	}
	return args
}

func runPythonJSON(ctx context.Context, pythonBin, pythonRoot string, args []string, extraEnv []string) (map[string]any, error) {
	cmd := exec.CommandContext(ctx, pythonBin, args...)
	cmd.Dir = pythonRoot
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run python flow: %w (stderr: %s)", err, stderr.String())
	}

	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return nil, fmt.Errorf("decode python json output: %w (stdout: %s)", err, stdout.String())
	}
	return report, nil
}

func resolvePythonRoot(explicit string) (string, error) {
	candidates := []string{}
	if explicit != "" {
		candidates = append(candidates, explicit)
	}
	if fromEnv := os.Getenv("NESSA_PY_ROOT"); fromEnv != "" {
		candidates = append(candidates, fromEnv)
	}

	if _, thisFile, _, ok := runtime.Caller(0); ok {
		moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
		candidates = append(candidates,
			filepath.Join(moduleRoot, "third_party", "nessa-paper"),
			filepath.Join(moduleRoot, "..", "..", "nessa-paper"),
			filepath.Join(moduleRoot, "..", "nessa-paper"),
		)
	}

	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(wd, "third_party", "nessa-paper"),
			filepath.Join(wd, "..", "..", "nessa-paper"),
			filepath.Join(wd, "..", "nessa-paper"),
			filepath.Join(wd, "nessa-paper"),
		)
	}

	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		abs, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		if _, ok := seen[abs]; ok {
			continue
		}
		seen[abs] = struct{}{}
		if err := validatePythonRoot(abs); err == nil {
			return abs, nil
		}
	}

	return "", errors.New("could not locate Python protocol repo; set --python-root or NESSA_PY_ROOT to the nessa-paper directory")
}

func validatePythonRoot(root string) error {
	appPath := filepath.Join(root, "app.py")
	implPath := filepath.Join(root, "impl", "asc_ad_demo.py")

	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return fmt.Errorf("invalid python root %q", root)
	}
	if _, err := os.Stat(appPath); err != nil {
		return fmt.Errorf("missing app.py in %q", root)
	}
	if _, err := os.Stat(implPath); err != nil {
		return fmt.Errorf("missing impl/asc_ad_demo.py in %q", root)
	}
	return nil
}
