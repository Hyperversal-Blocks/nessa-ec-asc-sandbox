package h2c

import (
    "crypto/sha512"
    "encoding/binary"
    "errors"
)

// ErrDstTooLong is returned when the DST exceeds the RFC 9380 length limit.
var ErrDstTooLong = errors.New("dst too long")

// ErrOutputTooBig is returned when the requested output length exceeds
// specification limits.
var ErrOutputTooBig = errors.New("requested output too long")

// ExpandMessageXMD_SHA512 implements the RFC 9380 expand_message_xmd primitive
// using SHA‑512 as the underlying hash function.  It is designed to be
// byte‑for‑byte compatible with the Python reference implementation included in
// this repository.  dst must be at most 255 bytes long and lenInBytes must be
// at most 65535.
func ExpandMessageXMD_SHA512(msg, dst []byte, lenInBytes int) ([]byte, error) {
    const bInBytes = 64  // output length of SHA‑512
    const rInBytes = 128 // block size of SHA‑512

    if len(dst) > 255 {
        return nil, ErrDstTooLong
    }
    if lenInBytes > 65535 {
        return nil, ErrOutputTooBig
    }

    ell := (lenInBytes + bInBytes - 1) / bInBytes
    if ell > 255 {
        return nil, ErrOutputTooBig
    }

    // Per RFC 9380, DST_prime = DST || I2OSP(len(DST), 1)
    dstPrime := append(append([]byte{}, dst...), byte(len(dst)))

    // Z_pad = I2OSP(0, r_in_bytes)
    zPad := make([]byte, rInBytes)

    // l_i_b_str = I2OSP(lenInBytes, 2)
    lIBStr := make([]byte, 2)
    binary.BigEndian.PutUint16(lIBStr, uint16(lenInBytes))

    // msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0,1) || DST_prime
    msgPrime := make([]byte, 0, len(zPad)+len(msg)+len(lIBStr)+1+len(dstPrime))
    msgPrime = append(msgPrime, zPad...)
    msgPrime = append(msgPrime, msg...)
    msgPrime = append(msgPrime, lIBStr...)
    msgPrime = append(msgPrime, 0x00)
    msgPrime = append(msgPrime, dstPrime...)

    b0Arr := sha512.Sum512(msgPrime)
    b0 := b0Arr[:]

    // b1 = H(b0 || I2OSP(1,1) || DST_prime)
    b1Input := make([]byte, 0, len(b0)+1+len(dstPrime))
    b1Input = append(b1Input, b0...)
    b1Input = append(b1Input, 0x01)
    b1Input = append(b1Input, dstPrime...)
    b1Arr := sha512.Sum512(b1Input)
    bi := b1Arr[:]

    uniform := make([]byte, 0, ell*bInBytes)
    uniform = append(uniform, bi...)

    for i := 2; i <= ell; i++ {
        // XOR b0 and the previous bi
        xored := make([]byte, bInBytes)
        for j := 0; j < bInBytes; j++ {
            xored[j] = b0[j] ^ bi[j]
        }
        in := make([]byte, 0, len(xored)+1+len(dstPrime))
        in = append(in, xored...)
        in = append(in, byte(i))
        in = append(in, dstPrime...)
        biArr2 := sha512.Sum512(in)
        bi = biArr2[:]
        uniform = append(uniform, bi...)
    }

    return uniform[:lenInBytes], nil
}