package cborcanon

import (
    "fmt"

    cbor "github.com/fxamacker/cbor/v2"
)

// encMode is a deterministic CBOR encoder.  It uses the "Core Deterministic"
// encoding options defined in RFC 8949 to match the Python reference's
// canonical CBOR behaviour (sorted map keys, definite lengths, etc.).
var encMode cbor.EncMode

func init() {
    opts := cbor.CoreDetEncOptions()
    em, err := opts.EncMode()
    if err != nil {
        panic(fmt.Errorf("cbor encmode init: %w", err))
    }
    encMode = em
}

// Marshal serializes v into deterministic CBOR bytes.  It is equivalent to
// json.Marshal but uses the deterministic CBOR mode.  The result should
// match the Python implementation's canonical encoding.
func Marshal(v any) ([]byte, error) {
    return encMode.Marshal(v)
}