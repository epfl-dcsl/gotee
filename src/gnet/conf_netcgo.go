// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +/*build netcgo*/

package gnet

/*

// Fail if cgo isn't available.

*/
//import "C"

// The build tag "gnetcgo" forces use of the cgo DNS resolver.
// It is the opposite of "gnetgo".
func init() { netCgo = true }
