package crypto

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "errors"
    "fmt"
    "hash"
    "io"

    "go.k6.io/k6/js/modules"
)

// Crypto is the k6 extension struct
type Crypto struct{}

// Ensure the module is registered
func init() {
    modules.Register("k6/x/crypto", new(Crypto))
}

// CreateCipheriv initializes a new cipher
func (c *Crypto) CreateCipheriv(algorithm, key, iv string) (cipher.Stream, error) {
    if algorithm != "aes-256-cfb" {
        return nil, errors.New("unsupported algorithm")
    }

    keyBytes := []byte(key)
    ivBytes, err := base64.StdEncoding.DecodeString(iv)
    if err != nil {
        return nil, err
    }

    block, err := aes.NewCipher(keyBytes)
    if err != nil {
        return nil, err
    }

    return cipher.NewCFBEncrypter(block, ivBytes), nil
}

// Update encrypts the data
func (c *Crypto) Update(stream cipher.Stream, data string) (string, error) {
    plainText := []byte(data)
    cipherText := make([]byte, len(plainText))
    stream.XORKeyStream(cipherText, plainText)
    return base64.StdEncoding.EncodeToString(cipherText), nil
}

// CreateHash initializes a new hash
func (c *Crypto) CreateHash(algorithm string) (hash.Hash, error) {
    if algorithm != "sha256" {
        return nil, errors.New("unsupported algorithm")
    }
    return sha256.New(), nil
}

// Digest computes the hash
func (c *Crypto) Digest(hash hash.Hash, encoding string) (string, error) {
    hashBytes := hash.Sum(nil)
    if encoding == "hex" {
        return fmt.Sprintf("%x", hashBytes), nil
    }
    return base64.StdEncoding.EncodeToString(hashBytes), nil
}

// RandomBytes generates random bytes
func (c *Crypto) RandomBytes(length int) (string, error) {
    bytes := make([]byte, length)
    if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(bytes), nil
}
