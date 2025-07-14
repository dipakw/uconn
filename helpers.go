package uconn

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand"

	"golang.org/x/crypto/hkdf"
)

func randbytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// AES-128 GCM Encryption
func aes128gcmEnc(data, key []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.New("key must be 16 bytes for AES-128")
	}
	return aesGCMEncrypt(data, key)
}

// AES-128 GCM Decryption
func aes128gcmDec(data, key []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.New("key must be 16 bytes for AES-128")
	}
	return aesGCMDecrypt(data, key)
}

// AES-256 GCM Encryption
func aes256gcmEnc(data, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}
	return aesGCMEncrypt(data, key)
}

// AES-256 GCM Decryption
func aes256gcmDec(data, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}
	return aesGCMDecrypt(data, key)
}

// Internal shared logic for encryption
func aesGCMEncrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, err := randbytes(gcm.NonceSize())

	if err != nil {
		return nil, err
	}

	// Seal: nonce + ciphertext
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...), nil
}

// Internal shared logic for decryption
func aesGCMDecrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("malformed ciphertext")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Encrypts a 16-bit number using AES-CTR with a 6-byte IV, output is always 8 bytes
func enc16num(key []byte, n uint16) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes (AES-256)")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate 6-byte IV
	ivShort := make([]byte, 6)
	if _, err := io.ReadFull(rand.Reader, ivShort); err != nil {
		return nil, err
	}

	// Expand to 16-byte IV for AES-CTR (pad with 10 zero bytes)
	iv := make([]byte, 16)
	copy(iv[10:], ivShort)

	stream := cipher.NewCTR(block, iv)

	// Convert uint16 to 2-byte plaintext
	plain := []byte{byte(n >> 8), byte(n & 0xFF)}
	ciphertext := make([]byte, 2)
	stream.XORKeyStream(ciphertext, plain)

	// Output: [6-byte IV || 2-byte ciphertext] = 8 bytes
	return append(ivShort, ciphertext...), nil
}

// Decrypts 8-byte input produced by enc16num
func dec16num(key []byte, ct []byte) (uint16, error) {
	if len(key) != 32 {
		return 0, errors.New("key must be 32 bytes (AES-256)")
	}
	if len(ct) != 8 {
		return 0, errors.New("ciphertext must be 8 bytes")
	}

	ivShort := ct[:6]
	ciphertext := ct[6:]

	// Rebuild full 16-byte IV
	iv := make([]byte, 16)
	copy(iv[10:], ivShort)

	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, err
	}

	stream := cipher.NewCTR(block, iv)

	plain := make([]byte, 2)
	stream.XORKeyStream(plain, ciphertext)

	// Convert back to uint16
	return uint16(plain[0])<<8 | uint16(plain[1]), nil
}

func hmac256(key []byte, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hkdfkey(info string, master []byte, size int) []byte {
	h := hkdf.New(sha256.New, master, nil, []byte(info))
	out := make([]byte, size)
	io.ReadFull(h, out)
	return out
}

// shuff returns a shuffled version of b based on the order given in ord.
// ord must be a permutation of [0, 1, ..., len(b)-1].
func shuff(ord []byte, b []byte) ([]byte, error) {
	if len(ord) != len(b) {
		return nil, errors.New("ord and b must be of the same length")
	}

	// Validate that ord contains unique values in range
	seen := make(map[byte]bool)
	for _, idx := range ord {
		if int(idx) >= len(b) {
			return nil, errors.New("ord contains index out of range")
		}
		if seen[idx] {
			return nil, errors.New("ord contains duplicate values")
		}
		seen[idx] = true
	}

	shuffled := make([]byte, len(b))
	for i, idx := range ord {
		shuffled[i] = b[idx]
	}

	return shuffled, nil
}

// unshuff reverses the shuffle based on ord.
func unshuff(ord []byte, b []byte) ([]byte, error) {
	if len(ord) != len(b) {
		return nil, errors.New("ord and b must be of the same length")
	}

	// Validate that ord contains unique values in range
	seen := make(map[byte]bool)
	for _, idx := range ord {
		if int(idx) >= len(b) {
			return nil, errors.New("ord contains index out of range")
		}
		if seen[idx] {
			return nil, errors.New("ord contains duplicate values")
		}
		seen[idx] = true
	}

	unshuffled := make([]byte, len(b))
	for i, idx := range ord {
		unshuffled[idx] = b[i]
	}

	return unshuffled, nil
}

func encryptSize(n uint16, c *_conn) ([]byte, error) {
	b := make([]byte, 12)

	ct, err := enc16num(c.keys.forSize, n)

	if err != nil {
		return nil, err
	}

	tag := hmac256(c.keys.forHmac, ct)[:4]

	copy(b, ct)
	copy(b[8:], tag)

	return shuff(c.ord, b)
}

func decryptSize(p []byte, c *_conn) (uint16, error) {
	if len(p) != 12 {
		return 0, errors.New("invalid size of bytes")
	}

	b, err := unshuff(c.ord, p)

	if err != nil {
		return 0, err
	}

	ct := b[:8]

	n, err := dec16num(c.keys.forSize, ct)

	if err != nil {
		return 0, err
	}

	tag := hmac256(c.keys.forHmac, ct)[:4]

	if !bytes.Equal(tag, b[8:]) {
		return 0, errors.New("invalid auth tag")
	}

	return n, nil
}

func genPerm(key []byte, n int) []uint8 {
	seed := int64(binary.LittleEndian.Uint64(key[:8]))

	// Use the seed for deterministic PRNG
	r := mrand.New(mrand.NewSource(seed))

	// Create and shuffle the array
	arr := make([]uint8, n)
	for i := range arr {
		arr[i] = uint8(i)
	}

	// Shuffle using Fisher-Yates
	for i := n - 1; i > 0; i-- {
		j := r.Intn(i + 1)
		arr[i], arr[j] = arr[j], arr[i]
	}

	return arr
}
