package nessa

import (
    "encoding/hex"
    "fmt"
    "math/big"

    "github.com/gtank/ristretto255"

    "github.com/Hyperversal-Blocks/nessa-ec/nessa-go/pkg/h2c"
)

const (
    scalarBytes        = 32
    h2sUniformBytesLen = 48 // (bitlen(L)+128+7)/8 for ristretto255 order
)

// H2G maps msg to a ristretto255 group element using the ExpandMessageXMD_SHA512
// primitive and the standard SetUniformBytes mapping.  The dst must include any
// necessary domain separation for the protocol context.
func H2G(dst, msg []byte) ([]byte, error) {
    u, err := h2c.ExpandMessageXMD_SHA512(msg, dst, 64)
    if err != nil {
        return nil, err
    }
    var e ristretto255.Element
    if _, err := e.SetUniformBytes(u); err != nil {
        return nil, fmt.Errorf("SetUniformBytes: %w", err)
    }
    return e.Bytes(), nil
}

// H2S maps msg to a scalar in the ristretto255 field.  It follows the
// implementation strategy from the Python reference: perform ExpandMessageXMD,
// interpret the result as a big‑endian integer, reduce modulo L, and
// output a canonical little‑endian 32‑byte encoding.
func H2S(dst, msg []byte) ([]byte, error) {
    u, err := h2c.ExpandMessageXMD_SHA512(msg, dst, h2sUniformBytesLen)
    if err != nil {
        return nil, err
    }
    n := new(big.Int).SetBytes(u)
    n.Mod(n, ScalarFieldOrder)
    out := make([]byte, scalarBytes)
    be := n.Bytes()
    // tmp holds the big‑endian representation padded to scalarBytes
    tmp := make([]byte, scalarBytes)
    copy(tmp[scalarBytes-len(be):], be)
    // reverse for little‑endian output
    for i := 0; i < scalarBytes; i++ {
        out[i] = tmp[scalarBytes-1-i]
    }
    return out, nil
}

// MustDecodeHex decodes a hexadecimal string into bytes and panics on error.
func MustDecodeHex(s string) []byte {
    b, err := hex.DecodeString(s)
    if err != nil {
        panic(err)
    }
    return b
}