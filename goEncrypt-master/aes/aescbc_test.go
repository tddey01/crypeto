package aes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	key       = "111"
	key16     = "1234567812345678"
	key24     = "123456781234567812345678"
	key32     = "12345678123456781234567812345678"
	plaintext = "TestAesCbc"
	badiv     = "11111"
	goodiv    = "1234567812345678"
)

func TestAesCbc(t *testing.T) {

	cipherBytes, err := AesCbcEncrypt([]byte(plaintext), []byte(key16), nil)
	assert.Nil(t, err)
	text, err := AesCbcDecrypt(cipherBytes, []byte(key16), nil)
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)

	_, err = AesCbcDecrypt(cipherBytes, []byte(key24), nil)
	assert.NotNil(t, err)
	text, err = AesCbcDecrypt([]byte("badtext"), []byte(key24), nil)
	assert.Equal(t, string(text), "")

	cipherBytes, err = AesCbcEncrypt([]byte(plaintext), []byte(key24), nil)
	assert.Nil(t, err)
	text, err = AesCbcDecrypt(cipherBytes, []byte(key24), nil)
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)

	cipherBytes, err = AesCbcEncrypt([]byte(plaintext), []byte(key32), nil)
	assert.Nil(t, err)
	text, err = AesCbcDecrypt(cipherBytes, []byte(key32), nil)
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)

	cipherBytes, err = AesCbcEncrypt([]byte(plaintext), []byte(key), nil)
	assert.NotNil(t, err)
	text, err = AesCbcDecrypt(cipherBytes, []byte(key), nil)
	assert.NotNil(t, err)

	cipherBytes, err = AesCbcEncrypt([]byte(plaintext), []byte(key16), []byte(badiv))
	assert.NotNil(t, err)
	text, err = AesCbcDecrypt(cipherBytes, []byte(key16), []byte(badiv))
	assert.NotNil(t, err)

	cipherBytes, err = AesCbcEncrypt([]byte(plaintext), []byte(key16), []byte(goodiv))
	assert.Nil(t, err)
	text, err = AesCbcDecrypt(cipherBytes, []byte(key16), []byte(goodiv))
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)
}

func TestAesCbcEncryptBase64(t *testing.T) {
	cipher, err := AesCbcEncryptBase64([]byte(plaintext), []byte(key16), nil)
	assert.Nil(t, err)
	text, err := AesCbcDecryptByBase64(cipher, []byte(key16), nil)
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)

	_, err = AesCbcDecryptByBase64("11111", []byte(key16), nil)
	assert.NotNil(t, err)
}

func TestAesCbcEncryptHex(t *testing.T) {
	cipher, err := AesCbcEncryptHex([]byte(plaintext), []byte(key16), nil)
	assert.Nil(t, err)
	text, err := AesCbcDecryptByHex(cipher, []byte(key16), nil)
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)

	_, err = AesCbcDecryptByHex("11111", []byte(key16), nil)
	assert.NotNil(t, err)
}
