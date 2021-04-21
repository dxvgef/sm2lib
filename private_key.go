package sm2lib

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io/fs"
	"io/ioutil"
	"path/filepath"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

// 私钥
type PrivateKey struct {
	key *sm2.PrivateKey
}

// 创建新私钥
func (privateKey *PrivateKey) New() (err error) {
	privateKey.key, err = sm2.GenerateKey(rand.Reader)
	return
}

// 从原生类型中获得私钥
func (privateKey *PrivateKey) FromRaw(src *sm2.PrivateKey) error {
	var (
		err    error
		p      []byte
		key    *sm2.PrivateKey
		errMsg = errors.New("不是有效的sm2私钥")
	)
	if src == nil {
		return errMsg
	}
	p, err = x509.MarshalSm2PrivateKey(src, nil)
	if err != nil {
		return errMsg
	}
	key, err = x509.ParsePKCS8PrivateKey(p, nil)
	if err != nil {
		return err
	}
	privateKey.key = key
	return nil
}

// 从[]byte中获得私钥
func (privateKey *PrivateKey) FromRawBytes(src []byte, pwd []byte) (err error) {
	privateKey.key, err = x509.ParsePKCS8PrivateKey(src, pwd)
	return
}

// 从Base64数据中获得私钥
func (privateKey *PrivateKey) FromBase64(encoding *base64.Encoding, src, pwd []byte) error {
	buff, err := Base64Decode(encoding, src)
	if err != nil {
		return err
	}
	privateKey.key, err = x509.ParsePKCS8PrivateKey(buff, pwd)
	if err != nil {
		return err
	}
	return nil
}

// 从Base64文件中获得私钥
func (privateKey *PrivateKey) FromBase64File(encoding *base64.Encoding, filePath string, pwd []byte) (err error) {
	var fileData []byte
	fileData, err = ioutil.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return
	}
	return privateKey.FromBase64(encoding, fileData, pwd)
}

// 从Hex数据中获得私钥
func (privateKey *PrivateKey) FromHex(src, pwd []byte) (err error) {
	buff, err := HexDecode(src)
	if err != nil {
		return
	}
	privateKey.key, err = x509.ParsePKCS8PrivateKey(buff, pwd)
	if err != nil {
		return
	}
	return
}

// 从Hex文件中获得私钥
func (privateKey *PrivateKey) FromHexFile(filePath string, pwd []byte) (err error) {
	var fileData []byte
	fileData, err = ioutil.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return
	}
	return privateKey.FromHex(fileData, pwd)
}

// 获得私钥原生类型
func (privateKey *PrivateKey) ToRaw() *sm2.PrivateKey {
	return privateKey.key
}

// 获得私钥的[]byte类型
func (privateKey *PrivateKey) ToRawBytes(pwd []byte) ([]byte, error) {
	return x509.MarshalSm2PrivateKey(privateKey.key, pwd)
}

// 私钥转为Base64数据
func (privateKey *PrivateKey) ToBase64(encoding *base64.Encoding, pwd []byte) (data []byte, err error) {
	var buff []byte
	if len(pwd) == 0 {
		buff, err = x509.MarshalSm2PrivateKey(privateKey.key, nil)
	} else {
		buff, err = x509.MarshalSm2PrivateKey(privateKey.key, pwd)
	}
	if err != nil {
		return
	}
	data = Base64Encode(encoding, buff)
	return
}

// 私钥保存为Base64编码的文件
func (privateKey *PrivateKey) ToBase64File(encoding *base64.Encoding, filePath string, pwd []byte, perm fs.FileMode) (err error) {
	var buff []byte
	buff, err = privateKey.ToBase64(encoding, pwd)
	if err != nil {
		return
	}
	return ioutil.WriteFile(filepath.Clean(filePath), buff, perm)
}

// 私钥转为Hex编码
func (privateKey *PrivateKey) ToHex(pwd []byte) (data []byte, err error) {
	var buff []byte
	if len(pwd) == 0 {
		buff, err = x509.MarshalSm2PrivateKey(privateKey.key, nil)
	} else {
		buff, err = x509.MarshalSm2PrivateKey(privateKey.key, pwd)
	}
	if err != nil {
		return
	}
	data = HexEncode(buff)
	return
}

// 私钥保存为Hex编码的文件
func (privateKey *PrivateKey) ToHexFile(filePath string, pwd []byte, perm fs.FileMode) (err error) {
	var buff []byte
	buff, err = privateKey.ToHex(pwd)
	if err != nil {
		return
	}
	return ioutil.WriteFile(filepath.Clean(filePath), buff, perm)
}

// 获得公钥
func (privateKey *PrivateKey) GetPublicKey() PublicKey {
	return PublicKey{
		key: &privateKey.key.PublicKey,
	}
}
