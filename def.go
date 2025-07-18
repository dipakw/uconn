package uconn

import (
	"net"
	"sync"
)

const (
	ALGO_AES256_GCM    uint8  = 1
	ALGO_AES128_GCM    uint8  = 2
	DEFAULT_CHUNK_SIZE uint16 = 32 * 1024
)

type Conn interface {
	net.Conn

	Encrypt(p []byte) (d []byte, err error)
	Decrypt(p []byte) (d []byte, err error)
}

type Opts struct {
	Algo uint8
	Key  []byte
	Size uint16 // Max chunk size.
}

type _keys struct {
	forData []byte
	forSize []byte
	forHmac []byte
}

type _conn struct {
	conn   net.Conn
	opt    *Opts
	keys   *_keys
	ord    []byte
	mu     sync.Mutex
	remain int
	cursor int
	unread []byte
}

type _algo struct {
	keysize int
}
