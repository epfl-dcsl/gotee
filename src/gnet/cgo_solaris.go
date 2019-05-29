// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +/*build cgo,!netgo*/

package gnet

/*
#cgo LDFLAGS: -lsocket -lnsl -lsendfile
#include <netdb.h>
*/
//import "C"

//const cgoAddrInfoFlags = AI_CANONNAME | AI_V4MAPPED | AI_ALL
