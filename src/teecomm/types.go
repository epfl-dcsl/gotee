package teecomm

import (
	"crypto/rsa"
)

type DecrRequestMsg struct {
	Key      *rsa.PrivateKey
	Msg      []byte
	Opt      *rsa.PKCS1v15DecryptOptions
	Plaintxt []byte
	Done     chan bool
}
