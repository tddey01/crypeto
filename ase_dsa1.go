package crtypeto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/dsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"time"
)

func main() {
	// 生成RSA密钥对
	start := time.Now()
	privateKeyRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// 生成DSA密钥对
	parametersDSA := &dsa.Parameters{}
	if err := dsa.GenerateParameters(parametersDSA, rand.Reader, dsa.L2048N256); err != nil {
		panic(err)
	}
	privateKeyDSA := new(dsa.PrivateKey)
	privateKeyDSA.PublicKey.Parameters = *parametersDSA
	if err := dsa.GenerateKey(privateKeyDSA, rand.Reader); err != nil {
		panic(err)
	}

	// 待加密的数据
	message := []byte("Hello, world!")

	//// 对数据进行哈希
	//hasher := sha256.New()
	//if _, err := hasher.Write(message); err != nil {
	//	panic(err)
	//}
	//hashed := hasher.Sum(nil)

	// 使用公钥加密数据
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKeyRSA.PublicKey, message, nil)
	if err != nil {
		panic(err)
	}

	// 使用私钥解密数据
	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKeyRSA, encrypted, nil)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	//// 检查解密出来的哈希值和原始哈希值是否相同
	//if fmt.Sprintf("%x", decrypted) == fmt.Sprintf("%x", hashed) {
	//	fmt.Println("解密成功")
	//} else {
	//	fmt.Println("解密失败")
	//}
	// 将解密后的字节数组转换为字符串
	decryptedStr := string(decrypted)

	fmt.Printf("原始数据：%s\n", message)
	fmt.Printf("加密后的数据：%x\n", encrypted)
	fmt.Printf("解密后的数据：%s\n", decryptedStr)

	// 使用DSA签名数据
	r, s, err := dsa.Sign(rand.Reader, privateKeyDSA, message)
	if err != nil {
		panic(err)
	}

	// 使用DSA验证签名
	if !dsa.Verify(&privateKeyDSA.PublicKey, message, r, s) {
		panic("签名验证失败")
	}
	fmt.Println("签名验证成功")

	// 使用AES加密数据
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(message))
	stream.XORKeyStream(ciphertext, message)

	// 使用AES解密数据
	stream = cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	if string(message) != string(plaintext) {
		panic("加密解密数据不一致")
	}
	fmt.Println("加密解密数据一致")

	stop := time.Now()
	fmt.Println(stop.Unix() - start.Unix())
}
