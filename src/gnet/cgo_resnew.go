// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +/*build cgo,!netgo*/
// +/*build darwin linux,!android netbsd solaris*/

package gnet

/*
#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
*/
//import "C"

import "unsafe"

func cgoNameinfoPTR(b []byte, sa *struct_sockaddr, salen socklen_t) (int, error) {
	gerrno, err := getnameinfo(sa, salen, unsafe.Pointer(&b[0]), len(b), nil, 0, NI_NAMEREQD)
	return int(gerrno), err
}
