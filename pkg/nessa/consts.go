package nessa

import "math/big"

// ProtocolVersion is the human‑readable identifier for this protocol implementation.
const ProtocolVersion = "NESSA-EC-RISTRETTO255-SHA512-v1"

// ProtocolVersionNumber is a monotonic numeric version matching the docs bundle.
const ProtocolVersionNumber = 1

// H2GId is the domain separation tag used for hash‑to‑group derivation.
// It follows the naming convention in RFC 9496 and the Python reference.
const H2GId = "ristretto255_XMD:SHA-512_R255MAP_RO_"

// ScalarFieldOrder defines the order of the ristretto255 scalar field.
// L = 2^252 + 27742317777372353535851937790883648493
var ScalarFieldOrder = func() *big.Int {
    two := big.NewInt(2)
    a := new(big.Int).Exp(two, big.NewInt(252), nil)
    b, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
    return new(big.Int).Add(a, b)
}()

// DSTAlpha is the domain separation tag used for computing α values in the
// transcript binding.  It matches the Python implementation and verification
// report.
var DSTAlpha = []byte("NESSA-EC:v1:alpha")