package uconn

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

var algos = map[uint8]*_algo{
	ALGO_AES128_GCM: {
		keysize: 16,
	},

	ALGO_AES256_GCM: {
		keysize: 32,
	},
}

var mu sync.Mutex
var keys = map[string]*_keys{}

func New(c net.Conn, opts *Opts) (Conn, error) {
	if opts == nil {
		return nil, errors.New("opts required")
	}

	var algo = algos[opts.Algo]

	if algo == nil {
		return nil, errors.New("unsupported algo")
	}

	mu.Lock()

	var key = hex.EncodeToString(opts.Key) + strconv.Itoa(int(opts.Algo))
	var useKeys *_keys = keys[key]

	if useKeys == nil {
		useKeys = &_keys{
			forData: hkdfkey("for-data", opts.Key, algo.keysize),
			forSize: hkdfkey("for-size", opts.Key, 32),
			forHmac: hkdfkey("for-hmac", opts.Key, 32),
		}

		keys[key] = useKeys
	}

	mu.Unlock()

	conn := &_conn{
		conn: c,
		opt:  opts,
		keys: useKeys,
		ord:  genPerm(hkdfkey("for-shuff", opts.Key, algo.keysize), 12),
		mu:   sync.Mutex{},
	}

	return conn, nil
}

func (c *_conn) Read(p []byte) (int, error) {
	c.mu.Lock()

	if c.remain > 0 {
		defer c.mu.Unlock()
		n := copy(p, c.unread[c.cursor:])
		c.cursor += n
		c.remain -= n

		return n, nil
	}

	c.mu.Unlock()

	buff := make([]byte, 12)
	_, err := io.ReadFull(c.conn, buff)

	if err != nil {
		return 0, err
	}

	size, err := c.decryptSize(buff)

	if err != nil {
		return 0, fmt.Errorf("failed to decrypt size: %s", err.Error())
	}

	buff = make([]byte, size)

	_, err = io.ReadFull(c.conn, buff)

	if err != nil {
		return 0, err
	}

	data, err := c.Decrypt(buff)

	if err != nil {
		return 0, fmt.Errorf("failed to decrypt data: %s", err.Error())
	}

	n := copy(p, data)

	if len(data) > n {
		c.mu.Lock()
		c.remain = len(data) - n
		c.cursor = 0
		c.unread = data[n:]
		c.mu.Unlock()
	}

	return n, nil
}

func (c *_conn) Write(p []byte) (int, error) {
	pLen := len(p)

	if pLen <= MAX_CHUNK_SIZE {
		return c.writeChunk(p)
	}

	var i int = 0
	var n int = 0
	var err error
	var wn int = 0

	done := false

	for {
		from := i * MAX_CHUNK_SIZE
		to := from + MAX_CHUNK_SIZE

		if to > pLen {
			to = pLen
			done = true
		}

		wn, err = c.writeChunk(p[from:to])

		if err != nil {
			return n, err
		}

		n += wn

		if done {
			break
		}
	}

	return n, err
}

func (c *_conn) writeChunk(p []byte) (int, error) {
	pLen := len(p)    // Payload length.
	eLen := 28 + pLen // Encrypted length.

	size, err := c.encryptSize(uint16(eLen))

	if err != nil {
		return 0, err
	}

	b := make([]byte, 12+eLen)

	data, err := c.Encrypt(p)

	if err != nil {
		return 0, err
	}

	copy(b, size)
	copy(b[12:], data)

	if _, err := c.conn.Write(b); err != nil {
		return 0, err
	}

	return pLen, nil
}

func (c *_conn) Close() error {
	return c.conn.Close()
}

func (c *_conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *_conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *_conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *_conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *_conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *_conn) Encrypt(p []byte) ([]byte, error) {
	if c.opt.Algo == ALGO_AES128_GCM {
		return aes128gcmEnc(p, c.opt.Key)
	}

	if c.opt.Algo == ALGO_AES256_GCM {
		return aes256gcmEnc(p, c.opt.Key)
	}

	return nil, errors.New("unsupported algo")
}

func (c *_conn) Decrypt(p []byte) ([]byte, error) {
	if c.opt.Algo == ALGO_AES128_GCM {
		return aes128gcmDec(p, c.opt.Key)
	}

	if c.opt.Algo == ALGO_AES256_GCM {
		return aes256gcmDec(p, c.opt.Key)
	}

	return nil, errors.New("unsupported algo")
}

func (c *_conn) encryptSize(n uint16) ([]byte, error) {
	return encryptSize(n, c)
}

func (c *_conn) decryptSize(p []byte) (uint16, error) {
	return decryptSize(p, c)
}
