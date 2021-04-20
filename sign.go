package sm2lib

import (
	"crypto/rand"
	"encoding/base64"
)

// 私钥签名
func (privateKey *PrivateKey) Sign(data []byte) ([]byte, error) {
	return privateKey.key.Sign(rand.Reader, data, nil)
}

// 公钥验签
func (publicKey *PublicKey) Verify(msg, sign []byte) bool {
	return publicKey.key.Verify(msg, sign)
}

// 私钥签名并转成Base64编码
func (privateKey *PrivateKey) SignToBase64(encoding *base64.Encoding, data []byte) ([]byte, error) {
	sign, err := privateKey.Sign(data)
	if err != nil {
		return nil, err
	}
	dst := Base64Encode(encoding, sign)
	return dst, nil
}

// 私钥签名并转成Hex编码
func (privateKey *PrivateKey) SignToHex(data []byte) ([]byte, error) {
	cipher, err := privateKey.Sign(data)
	if err != nil {
		return nil, err
	}
	dst := HexEncode(cipher)
	return dst, nil
}
