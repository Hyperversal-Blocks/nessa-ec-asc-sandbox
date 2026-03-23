package testdata

import (
    "path/filepath"
    "runtime"
)

// RepoRoot attempts to locate the repository root relative to the location of
// this file.  It walks up the directory hierarchy to determine the parent
// directory containing the nessago module.  Tests rely on this to read
// verification artefacts from the docs bundle.
func RepoRoot() string {
    _, thisFile, _, _ := runtime.Caller(0)
    // thisFile = <repo>/nessa-go/internal/testdata/paths.go
    nessaGoDir := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
    // repo root is the parent of nessa-go
    return filepath.Dir(nessaGoDir)
}