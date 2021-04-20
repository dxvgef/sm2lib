package sm2lib

import (
	"encoding/base64"
	"encoding/hex"
	"unsafe"
)

// []byte转string
func BytesToString(value []byte) string {
	return *(*string)(unsafe.Pointer(&value)) // nolint
}

// 字符串转[]byte
func StringToBytes(s string) []byte {
	x := (*[2]uintptr)(unsafe.Pointer(&s)) // nolint
	h := [3]uintptr{x[0], x[1], x[1]}
	return *(*[]byte)(unsafe.Pointer(&h)) // nolint
}

// Base64编码
func Base64Encode(encoding *base64.Encoding, src []byte) []byte {
	dst := make([]byte, encoding.EncodedLen(len(src)))
	encoding.Encode(dst, src)
	return dst
}

// Base64解码
func Base64Decode(encoding *base64.Encoding, src []byte) ([]byte, error) {
	dst := make([]byte, encoding.DecodedLen(len(src)))
	_, err := encoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

// Hex编码
func HexEncode(src []byte) []byte {
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	return dst
}

// Hex解码
func HexDecode(src []byte) ([]byte, error) {
	dst := make([]byte, hex.DecodedLen(len(src)))
	_, err := hex.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst, nil
}
