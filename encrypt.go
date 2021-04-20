package sm2lib

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"

	"github.com/tjfoc/gmsm/sm2"
)

// 公钥加密
func (publicKey *PublicKey) Encrypt(data []byte) (result []byte, err error) {
	result, err = sm2.Encrypt(publicKey.key, data, rand.Reader)
	return
}

// 公钥加密成asn.1编码
func (publicKey *PublicKey) EncryptASN1(data []byte) ([]byte, error) {
	return sm2.EncryptAsn1(publicKey.key, data, rand.Reader)
}

// 公钥加密并转成Base64编码
func (publicKey *PublicKey) EncryptToBase64(encoding *base64.Encoding, data []byte) ([]byte, error) {
	buff, err := sm2.Encrypt(publicKey.key, data, rand.Reader)
	if err != nil {
		return nil, err
	}
	dst := Base64Encode(encoding, buff)
	return dst, nil
}

// 公钥加密成asn.1编码并转成Base64编码
func (publicKey *PublicKey) EncryptASN1ToBase64(encoding *base64.Encoding, data []byte) ([]byte, error) {
	buff, err := sm2.EncryptAsn1(publicKey.key, data, rand.Reader)
	if err != nil {
		return nil, err
	}
	dst := Base64Encode(encoding, buff)
	return dst, nil
}

// 公钥加密并转成Hex编码
func (publicKey *PublicKey) EncryptToHex(data []byte) ([]byte, error) {
	buff, err := sm2.Encrypt(publicKey.key, data, rand.Reader)
	if err != nil {
		return nil, err
	}
	dst := HexEncode(buff)
	return dst, nil
}

// 公钥加密成asn.1编码并转成Hex编码
func (publicKey *PublicKey) EncryptASN1ToHex(data []byte) ([]byte, error) {
	buff, err := sm2.EncryptAsn1(publicKey.key, data, rand.Reader)
	if err != nil {
		return nil, err
	}
	dst := HexEncode(buff)
	return dst, nil
}

// 私钥解密
func (privateKey *PrivateKey) Decrypt(data []byte) ([]byte, error) {
	return sm2.Decrypt(privateKey.key, data)
}

// 私钥解密成asn.1编码的密文
func (privateKey *PrivateKey) DecryptASN1(data []byte) ([]byte, error) {
	return sm2.DecryptAsn1(privateKey.key, data)
}

// 私钥解密Base64编码的密文
func (privateKey *PrivateKey) DecryptFromBase64(encoding *base64.Encoding, data []byte) ([]byte, error) {
	buff := make([]byte, encoding.DecodedLen(len(data)))
	_, err := encoding.Decode(buff, data)
	if err != nil {
		return nil, err
	}
	return privateKey.Decrypt(buff)
}

// 私钥解密asn.1以及Base64编码的密文
func (privateKey *PrivateKey) DecryptASN1FromBase64(encoding *base64.Encoding, data []byte) ([]byte, error) {
	buff := make([]byte, encoding.DecodedLen(len(data)))
	_, err := encoding.Decode(buff, data)
	if err != nil {
		return nil, err
	}
	return privateKey.DecryptASN1(buff)
}

// 私钥解密Hex编码的密文
func (privateKey *PrivateKey) DecryptFromHex(data []byte) ([]byte, error) {
	buff := make([]byte, hex.DecodedLen(len(data)))
	_, err := hex.Decode(buff, data)
	if err != nil {
		return nil, err
	}
	return privateKey.Decrypt(buff)
}

// 私钥解密asn.1以及Hex编码的密文
func (privateKey *PrivateKey) DecryptASN1FromHex(data []byte) ([]byte, error) {
	buff := make([]byte, hex.DecodedLen(len(data)))
	_, err := hex.Decode(buff, data)
	if err != nil {
		return nil, err
	}
	return privateKey.DecryptASN1(buff)
}
