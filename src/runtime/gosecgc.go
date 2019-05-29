package runtime

import (
	"runtime/internal/sys"
	"unsafe"
)

/*
* This file is here to help enclave GC.
* It allocates the msgx + tls part of TCS in the data segment to facilitate
* root marking in the GC.
* Its keeps track of routines that cross the boundary.
* We try to keep a reference to them to prevent garbage collection.
* This should work from both the enclave and non-enclave domains.
* However, for the moment, we try to insert it only in the enclave, as the
* g can be found from scanning channels in non-enclave.
* */

// Check that this is the same as in isgx.go
const (
	_ptr_expected_size = 8 // we expect the size of a pointer to be 8.
	_msgx_size         = _psize
	_tls_size          = _psize
	_tls_reserved_size = _msgx_size + _tls_size
	_padding_alignment = 2 * _psize
	EnclaveMaxTls      = 4 // maximum number of concurrent threads in the enclave.

	//Tricky but basically we need this struct to have some extra buffer so that
	//we have something that is page aligned.
	_msgxtls_arr_len = (_padding_alignment + _tls_reserved_size*EnclaveMaxTls) / _ptr_expected_size
)

var (
	//Place holder for the TCS values, declare it as an array of byte pointers
	//so that it ends up in the bss segment (part of mark root set) and not in
	//the noptrbsss segment (not part of mark root set).
	enclaveMsgxTlsArr [_msgxtls_arr_len]*byte
	allcrossedg       map[int64]*g
	gsindex           int
	allcglock         mutex
)

func InitAllcg() {
	gosecassert(_ptr_expected_size == sys.PtrSize)
	gosecassert((len(enclaveMsgxTlsArr)*sys.PtrSize)%_psize == 0)
	enclaveMsgxTlsArr[0] = nil
	if allcrossedg != nil {
		throw("Trying to reinitialize allcrossedg")
	}
	allcrossedg = make(map[int64]*g)
}

func allcgadd(gp *g) {
	gosecassert(allcrossedg != nil)
	lock(&allcglock)
	allcrossedg[gp.goid] = gp
	unlock(&allcglock)
}

func allcgremove(gp *g) {
	if gp == nil {
		throw("[allcgremove] nil gp")
	}
	lock(&allcglock)
	if v, ok := allcrossedg[gp.goid]; ok {
		gosecassert(v == gp)
		delete(allcrossedg, v.goid)
	} else {
		println("[info] g: ", unsafe.Pointer(gp), "goid: ", gp.goid)
		throw("[allcgremove] trying to remove a gp that does not exist")
	}
	unlock(&allcglock)
}
