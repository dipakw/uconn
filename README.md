# Uconn

**Uconn** (uglify connection) is a lightweight Go library that provides seamless encryption for TCP traffic using pre-shared keys. Built for simplicity and security, it allows network communication encryption with minimal overhead.

## Supported encryption algos.
1. AES 256 GCM (Key size: 32 bytes)
2. AES 128 GCM (Key size: 16 bytes)

## Installation

```bash
go get github.com/dipakw/uconn
```

## Example

```go
package main

import (
	"fmt"
	"net"
	"uconn"
)

func main() {
	opts := &uconn.Opts{
		Algo: uconn.ALGO_AES256_GCM,
		Key:  []byte("nbhdhfshdfjgsjhdfgsftqdtdfdfkoko"),
	}

	client, server := net.Pipe()

	cc, _ := uconn.New(client, opts)
	ss, _ := uconn.New(server, opts)

	go func() {
		buff := make([]byte, 20)

		for {
			n, err := ss.Read(buff)

			if err != nil {
				fmt.Println("Read by server err:", err)
				break
			}

			fmt.Println("-- Server received:", buff[:n])

			ss.Write([]byte("Cool"))
		}
	}()

	cc.Write([]byte("hi"))

	buff := make([]byte, 20)

	n, err := cc.Read(buff)

	if err != nil {
		fmt.Println("Read by client err:", err)
		return
	}

	fmt.Println("-- Client received:", buff[:n])
}
```