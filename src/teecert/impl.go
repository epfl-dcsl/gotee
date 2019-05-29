package teecert

import (
	"crypto/rsa"
	"teecomm"
)

func check(err error) {
	if err != nil {
		panic(err.Error())
	}
}

func TeeProtectKey(req chan *rsa.PrivateKey) {
	orig := <-req
	copy := &rsa.PrivateKey{}
	*copy = *orig
	req <- copy
}

func TeeDecryptService(comm chan teecomm.DecrRequestMsg) {
	for {
		req := <-comm
		err := rsa.DecryptPKCS1v15SessionKey(nil, req.Key, req.Msg, req.Plaintxt)
		check(err)
		req.Done <- true
	}
}
