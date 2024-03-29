package sm2lib

import (
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/tjfoc/gmsm/x509"

	"github.com/tjfoc/gmsm/sm2"
)

type PublicKey struct {
	key *sm2.PublicKey
}

// 从原生类型中获得公钥
func (publicKey *PublicKey) FromRaw(src *sm2.PublicKey) error {
	var (
		err    error
		p      []byte
		key    *sm2.PublicKey
		errMsg = errors.New("不是有效的SM2公钥")
	)
	if src == nil {
		return errMsg
	}
	p, err = x509.MarshalSm2PublicKey(src)
	if err != nil {
		return errMsg
	}
	key, err = x509.ParseSm2PublicKey(p)
	if err != nil {
		return err
	}
	publicKey.key = key
	return nil
}

// 从[]byte中获得公钥
func (publicKey *PublicKey) FromRawBytes(src []byte) (err error) {
	publicKey.key, err = x509.ParseSm2PublicKey(src)
	return
}

// 从Base64编码中获得公钥
func (publicKey *PublicKey) FromBase64(encoding *base64.Encoding, src []byte) error {
	buff, err := Base64Decode(encoding, src)
	if err != nil {
		return err
	}
	publicKey.key, err = x509.ParseSm2PublicKey(buff)
	if err != nil {
		return err
	}
	return nil
}

// 从Base64编码的文件中获得公钥
func (publicKey *PublicKey) FromBase64File(encoding *base64.Encoding, filePath string) (err error) {
	var fileData []byte
	fileData, err = os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return
	}
	return publicKey.FromBase64(encoding, fileData)
}

// 从Hex编码中获得公钥
func (publicKey *PublicKey) FromHex(src []byte) error {
	buff, err := HexDecode(src)
	if err != nil {
		return err
	}
	publicKey.key, err = x509.ParseSm2PublicKey(buff)
	if err != nil {
		return err
	}
	return nil
}

// 从Hex编码的文件中获得公钥
func (publicKey *PublicKey) FromHexFile(filePath string) (err error) {
	var fileData []byte
	fileData, err = os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return
	}
	return publicKey.FromHex(fileData)
}

// 公钥转为原生类型
func (publicKey PublicKey) ToRaw() *sm2.PublicKey {
	return publicKey.key
}

// 公钥转为原生[]byte
func (publicKey *PublicKey) ToRawBytes() ([]byte, error) {
	return x509.MarshalSm2PublicKey(publicKey.key)
}

// 公钥转为Base64编码
func (publicKey *PublicKey) ToBase64(encoding *base64.Encoding) (data []byte, err error) {
	var buff []byte
	buff, err = x509.MarshalSm2PublicKey(publicKey.key)
	if err != nil {
		return
	}
	data = Base64Encode(encoding, buff)
	return
}

// 公钥保存为Base64编码的文件
func (publicKey *PublicKey) ToBase64File(encoding *base64.Encoding, filePath string, perm fs.FileMode) (err error) {
	var buff []byte
	buff, err = publicKey.ToBase64(encoding)
	if err != nil {
		return
	}
	return os.WriteFile(filepath.Clean(filePath), buff, perm)
}

// 公钥转为Hex编码
func (publicKey *PublicKey) ToHex() (data []byte, err error) {
	var buff []byte
	buff, err = x509.MarshalSm2PublicKey(publicKey.key)
	if err != nil {
		return
	}
	data = HexEncode(buff)
	return
}

// 公钥保存为Hex编码的文件
func (publicKey *PublicKey) ToHexFile(filePath string, perm fs.FileMode) (err error) {
	var buff []byte
	buff, err = publicKey.ToHex()
	if err != nil {
		return
	}
	return os.WriteFile(filepath.Clean(filePath), buff, perm)
}

// 公钥保存为PEM编码的文件
func (publicKey *PublicKey) ToPEMFile(filePath string, perm fs.FileMode) (err error) {
	var buff []byte
	buff, err = x509.WritePublicKeyToPem(publicKey.ToRaw())
	if err != nil {
		return
	}
	return os.WriteFile(filepath.Clean(filePath), buff, perm)
}

// 从PEM编码的文件中读取公钥
func (publicKey *PublicKey) FromPEMFile(filePath string) (err error) {
	var publicKeyRaw *sm2.PublicKey

	// 读取PEM文件
	fileData, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return err
	}

	publicKeyRaw, err = x509.ReadPublicKeyFromPem(fileData)
	if err != nil {
		return err
	}
	return publicKey.FromRaw(publicKeyRaw)
}
