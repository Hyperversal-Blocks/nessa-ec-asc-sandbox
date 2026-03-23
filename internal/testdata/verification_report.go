package testdata

import (
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
)

// report is a partial representation of the verification report JSON.  It
// focuses on the "sections" structure used by the tests in vectors_test.go.
type report struct {
    Sections map[string]struct {
        Items []struct {
            Label string      `json:"label"`
            Value interface{} `json:"value"`
        } `json:"items"`
    } `json:"sections"`
}

// LoadVerificationReport reads the verification report JSON from the
// repository's docs bundle and unmarshals it into a report structure.  It
// returns an error if the file cannot be read or parsed.
func LoadVerificationReport() (*report, error) {
    p := filepath.Join(RepoRoot(), "docs", "generated", "protocol", "verification", "verification_report.json")
    b, err := os.ReadFile(p)
    if err != nil {
        return nil, fmt.Errorf("read verification_report.json: %w", err)
    }
    var r report
    if err := json.Unmarshal(b, &r); err != nil {
        return nil, fmt.Errorf("decode verification_report.json: %w", err)
    }
    return &r, nil
}

// Lookup searches the report for an item with the given section key and label.
// It returns the associated value and true if found, or nil and false otherwise.
func (r *report) Lookup(sectionKey, label string) (interface{}, bool) {
    sec, ok := r.Sections[sectionKey]
    if !ok {
        return nil, false
    }
    for _, it := range sec.Items {
        if it.Label == label {
            return it.Value, true
        }
    }
    return nil, false
}