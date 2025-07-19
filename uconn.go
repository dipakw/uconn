package uconn

import (
	"errors"
	"fmt"
	"io"
	"net"
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

func New(c net.Conn, opts *Opts) (Conn, error) {
	if opts == nil {
		return nil, errors.New("opts required")
	}

	if opts.Size == 0 {
		opts.Size = DEFAULT_CHUNK_SIZE
	}

	var algo = algos[opts.Algo]

	if algo == nil {
		return nil, fmt.Errorf("unsupported algo: %d", opts.Algo)
	}

	var useKeys = &_keys{
		forData: hkdfkey("for-data", opts.Key, algo.keysize),
		forSize: hkdfkey("for-size", opts.Key, 32),
		forHmac: hkdfkey("for-hmac", opts.Key, 32),
	}

	conn := &_conn{
		conn:   c,
		opt:    opts,
		keys:   useKeys,
		ord:    genPerm(hkdfkey("for-shuff", opts.Key, algo.keysize), 12),
		mu:     sync.Mutex{},
		unread: make([]byte, 0, opts.Size), // Pre-allocate buffer
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
		if c.remain == 0 {
			c.unread = c.unread[:0] // Reset buffer
		}
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
		return 0, fmt.Errorf("failed to decrypt size: %w", err)
	}

	if size > uint16(c.opt.Size) {
		return 0, fmt.Errorf("data size %d exceeds max chunk size %d", size, c.opt.Size)
	}

	buff = make([]byte, size)

	_, err = io.ReadFull(c.conn, buff)

	if err != nil {
		return 0, err
	}

	data, err := c.Decrypt(buff)

	if err != nil {
		return 0, fmt.Errorf("failed to decrypt data: %w", err)
	}

	n := copy(p, data)

	if len(data) > n {
		c.mu.Lock()
		c.remain = len(data) - n
		c.cursor = 0
		c.unread = append(c.unread[:0], data[n:]...)
		c.mu.Unlock()
	}

	return n, nil
}

func (c *_conn) Write(p []byte) (int, error) {
	pLen := len(p)
	dataChunkSize := int(c.opt.Size) - 28

	if pLen <= dataChunkSize {
		return c.writeChunk(p)
	}

	var i int = 0
	var n int = 0
	var err error
	var wn int = 0

	done := false

	for {
		from := i * dataChunkSize
		to := from + dataChunkSize

		if to > pLen {
			to = pLen
			done = true
		}

		wn, err = c.writeChunk(p[from:to])

		if err != nil {
			return n, err
		}

		n += wn
		i++

		if done {
			break
		}
	}

	return n, err
}

func (c *_conn) writeChunk(p []byte) (int, error) {
	pLen := len(p)    // Payload length.
	eLen := 28 + pLen // Encrypted length.

	if pLen > int(c.opt.Size) {
		return 0, fmt.Errorf("chunk size %d exceeds max %d", pLen, c.opt.Size)
	}

	size, err := c.encryptSize(uint16(eLen))

	if err != nil {
		return 0, fmt.Errorf("failed to encrypt size: %w", err)
	}

	b := make([]byte, 12+eLen)

	data, err := c.Encrypt(p)

	if err != nil {
		return 0, fmt.Errorf("failed to encrypt data: %w", err)
	}

	copy(b, size)
	copy(b[12:], data)

	if _, err := c.conn.Write(b); err != nil {
		return 0, fmt.Errorf("failed to write data: %w", err)
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
	switch c.opt.Algo {
	case ALGO_AES128_GCM:
		return aes128gcmEnc(p, c.opt.Key)
	case ALGO_AES256_GCM:
		return aes256gcmEnc(p, c.opt.Key)
	default:
		return nil, fmt.Errorf("unsupported algo: %d", c.opt.Algo)
	}
}

func (c *_conn) Decrypt(p []byte) ([]byte, error) {
	switch c.opt.Algo {
	case ALGO_AES128_GCM:
		return aes128gcmDec(p, c.opt.Key)
	case ALGO_AES256_GCM:
		return aes256gcmDec(p, c.opt.Key)
	default:
		return nil, fmt.Errorf("unsupported algo: %d", c.opt.Algo)
	}
}

func (c *_conn) encryptSize(n uint16) ([]byte, error) {
	return encryptSize(n, c)
}

func (c *_conn) decryptSize(p []byte) (uint16, error) {
	return decryptSize(p, c)
}
