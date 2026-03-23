package asc

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestBuildArgs(t *testing.T) {
	args := buildArgs(RunOptions{
		Deterministic: true,
		Benchmark:     true,
		RootArtifacts: true,
		ArtifactsDir:  "/tmp/audit",
		ReportPath:    "/tmp/report",
	})

	want := []string{
		"app.py",
		"asc-ad-demo",
		"--json",
		"--deterministic",
		"--benchmark",
		"--artifacts-dir",
		"/tmp/audit",
		"--root-artifacts",
		"--report",
		"/tmp/report",
	}

	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args mismatch\nwant=%v\ngot =%v", want, args)
	}
}

func TestResolvePythonRoot_Explicit(t *testing.T) {
	t.Setenv("NESSA_PY_ROOT", "")

	tmp := t.TempDir()
	if err := writeFile(filepath.Join(tmp, "app.py"), "#!/usr/bin/env python3\n"); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(tmp, "impl", "asc_ad_demo.py"), "# stub\n"); err != nil {
		t.Fatal(err)
	}

	got, err := resolvePythonRoot(tmp)
	if err != nil {
		t.Fatalf("resolvePythonRoot returned error: %v", err)
	}

	absWant, err := filepath.Abs(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if got != absWant {
		t.Fatalf("root mismatch\nwant=%q\ngot =%q", absWant, got)
	}
}

func TestValidatePythonRoot_Invalid(t *testing.T) {
	if err := validatePythonRoot(t.TempDir()); err == nil {
		t.Fatal("expected error for invalid python root")
	}
}

func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}
