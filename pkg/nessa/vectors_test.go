package nessa

import (
    "crypto/sha512"
    "encoding/hex"
    "testing"

    "github.com/gtank/ristretto255"

    "github.com/Hyperversal-Blocks/nessa-ec/nessa-go/internal/testdata"
    "github.com/Hyperversal-Blocks/nessa-ec/nessa-go/pkg/cborcanon"
    "github.com/Hyperversal-Blocks/nessa-ec/nessa-go/pkg/h2c"
)

// TestVerificationReport_GeneratorDerivation_Br1 validates the generator derivation
// inputs and outputs for Br[1] as recorded in the verification report.  It
// checks that ExpandMessageXMD and SetUniformBytes match the expected
// intermediate uniform bytes and resulting group element.
func TestVerificationReport_GeneratorDerivation_Br1(t *testing.T) {
    r, err := testdata.LoadVerificationReport()
    if err != nil {
        t.Fatal(err)
    }
    msgHexAny, ok := r.Lookup("B", "Br[1] msg_cbor_hex")
    if !ok {
        t.Fatal("missing Br[1] msg_cbor_hex")
    }
    dstHexAny, ok := r.Lookup("B", "Br[1] dst_hex")
    if !ok {
        t.Fatal("missing Br[1] dst_hex")
    }
    uniformHexAny, ok := r.Lookup("B", "Br[1] xmd_uniform_hex")
    if !ok {
        t.Fatal("missing Br[1] xmd_uniform_hex")
    }
    pointHexAny, ok := r.Lookup("B", "Br[1] point_hex")
    if !ok {
        t.Fatal("missing Br[1] point_hex")
    }
    msg := MustDecodeHex(msgHexAny.(string))
    dst := MustDecodeHex(dstHexAny.(string))
    wantUniform := MustDecodeHex(uniformHexAny.(string))
    wantPoint := MustDecodeHex(pointHexAny.(string))
    gotUniform, err := h2c.ExpandMessageXMD_SHA512(msg, dst, 64)
    if err != nil {
        t.Fatal(err)
    }
    if hex.EncodeToString(gotUniform) != hex.EncodeToString(wantUniform) {
        t.Fatalf("uniform mismatch\nwant=%x\ngot =%x", wantUniform, gotUniform)
    }
    var e ristretto255.Element
    if _, err := e.SetUniformBytes(gotUniform); err != nil {
        t.Fatal(err)
    }
    gotPoint := e.Bytes()
    if hex.EncodeToString(gotPoint) != hex.EncodeToString(wantPoint) {
        t.Fatalf("point mismatch\nwant=%x\ngot =%x", wantPoint, gotPoint)
    }
}

// TestVerificationReport_TagsCBOR_AndHash verifies that deterministic CBOR
// encoding of tags and the resulting SHA‑512 hash match the values recorded in
// the verification report.  It also exercises the conversion of numeric map
// keys represented as strings in the JSON artefact.
func TestVerificationReport_TagsCBOR_AndHash(t *testing.T) {
    r, err := testdata.LoadVerificationReport()
    if err != nil {
        t.Fatal(err)
    }
    tagsMapAny, ok := r.Lookup("C", "tags_map")
    if !ok {
        t.Fatal("missing tags_map")
    }
    tagsCborHexAny, ok := r.Lookup("C", "tags_cbor_hex")
    if !ok {
        t.Fatal("missing tags_cbor_hex")
    }
    tagsHashHexAny, ok := r.Lookup("C", "tags_hash_hex")
    if !ok {
        t.Fatal("missing tags_hash_hex")
    }
    // Convert map[string]interface{} with numeric keys encoded as strings to
    // map[int]interface{} expected by the protocol.  Keys 4, 7, and 9 are
    // hex‑encoded SHA‑512 outputs in the JSON source; convert them to byte slices.
    tagsObj := tagsMapAny.(map[string]interface{})
    tags := make(map[int]interface{})
    for kStr, v := range tagsObj {
        var key int
        for _, ch := range kStr {
            key = key*10 + int(ch-'0')
        }
        if key == 4 || key == 7 || key == 9 {
            tags[key] = MustDecodeHex(v.(string))
        } else {
            tags[key] = v
        }
    }
    wantCbor := MustDecodeHex(tagsCborHexAny.(string))
    wantHash := MustDecodeHex(tagsHashHexAny.(string))
    gotCbor, err := cborcanon.Marshal(tags)
    if err != nil {
        t.Fatal(err)
    }
    if hex.EncodeToString(gotCbor) != hex.EncodeToString(wantCbor) {
        t.Fatalf("tags cbor mismatch\nwant=%x\ngot =%x", wantCbor, gotCbor)
    }
    h := sha512.Sum512(gotCbor)
    if hex.EncodeToString(h[:]) != hex.EncodeToString(wantHash) {
        t.Fatalf("tags hash mismatch\nwant=%x\ngot =%x", wantHash, h[:])
    }
}

// TestVerificationReport_Alpha1 verifies that the alpha value derived by H2S
// matches the first alpha in the verification report.  It exercises the
// endianness and reduction semantics of the scalar derivation.
func TestVerificationReport_Alpha1(t *testing.T) {
    r, err := testdata.LoadVerificationReport()
    if err != nil {
        t.Fatal(err)
    }
    preimageHexAny, ok := r.Lookup("C", "alpha_1_preimage_cbor_hex")
    if !ok {
        t.Fatal("missing alpha_1_preimage_cbor_hex")
    }
    alphaHexAny, ok := r.Lookup("C", "alpha_1_hex")
    if !ok {
        t.Fatal("missing alpha_1_hex")
    }
    preimage := MustDecodeHex(preimageHexAny.(string))
    wantAlpha := MustDecodeHex(alphaHexAny.(string))
    gotAlpha, err := H2S(DSTAlpha, preimage)
    if err != nil {
        t.Fatal(err)
    }
    if hex.EncodeToString(gotAlpha) != hex.EncodeToString(wantAlpha) {
        t.Fatalf("alpha mismatch\nwant=%x\ngot =%x", wantAlpha, gotAlpha)
    }
}