package cryptography

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "io"
   

    "golang.org/x/crypto/pbkdf2"
    "go.k6.io/k6/js/modules"
)

// Crypto is the k6 extension struct
type Crypto struct{}

// Ensure the module is registered
func init() {
    modules.Register("k6/x/cryptography", &Crypto{})
}

// pkcs7Pad pads the data to the block size
func pkcs7Pad(data []byte, blockSize int) []byte {
    padding := blockSize - len(data)%blockSize
    padText := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(data, padText...)
}

// EncryptData encrypts the provided value using AES encryption
func (c *Crypto) EncryptData(valueToEncrypt, password string) (string, error) {
    keySizeInBits := 256
    keySizeInBytes := keySizeInBits / 8
    salt := make([]byte, 16)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return "", err
    }

    iv := make([]byte, aes.BlockSize)
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    iterations := 10000
    key := pbkdf2.Key([]byte(password), salt, iterations, keySizeInBytes, sha256.New)

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    mode := cipher.NewCBCEncrypter(block, iv)
    paddedValue := pkcs7Pad([]byte(valueToEncrypt), aes.BlockSize)
    encrypted := make([]byte, len(paddedValue))
    mode.CryptBlocks(encrypted, paddedValue)

    result := append(append(salt, iv...), encrypted...)
    return base64.StdEncoding.EncodeToString(result), nil
}

// HashBody hashes the payload using SHA256 and then encrypts the hash
func (c *Crypto) HashBody(payload, password string) (string, error) {
    hash := sha256.New()
    hash.Write([]byte(payload))
    seedHash := hex.EncodeToString(hash.Sum(nil))

    encryptedSeedHash, err := c.EncryptData(seedHash, password)
    if err != nil {
        return "", err
    }

    return encryptedSeedHash, nil
}

// Exports returns the methods to be exported to JS
func (c *Crypto) Exports() modules.Exports {
    return modules.Exports{
        Default: c,
        Named: map[string]interface{}{
            "encryptData": c.EncryptData,
            "hashBody":    c.HashBody,
        },
    }
}
