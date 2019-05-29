package gosec

import (
	"debug/elf"
	"fmt"
	"runtime"
)

//Not really used, just here for documentation.
const (
	SGX_ENCLU_EENTER  = 0x02
	SGX_ENCLU_ERESUME = 0x03
	SGX_ENCLU_EXIT    = 0x04
)

const (
	PAGE_READ     = 0x1
	PAGE_WRITE    = 0x2
	PAGE_EXEC     = 0x4
	PAGE_TCS      = 0x8
	PAGE_NOEXTEND = 0x10
)

const (
	SGX_SECINFO_R = 0x01
	SGX_SECINFO_W = 0x02
	SGX_SECINFO_X = 0x04
)

const (
	SGX_SECINFO_SECS = 0x000
	SGX_SECINFO_TCS  = 0x100
	SGX_SECINFO_REG  = 0x200
)

const (
	SGX_FS_LIMIT = 0xffffffff
	SGX_GS_LIMIT = 0xffffffff
)

const (
	TCS_N_SSA = 2
)

// Sizes for the different elements
const (
	STACK_SIZE  = 0x8000
	TCS_SIZE    = PSIZE
	SSA_SIZE    = PSIZE
	MSGX_SIZE   = PSIZE
	TLS_SIZE    = PSIZE
	MEMBUF_SIZE = runtime.MEMBUF_SIZE //(PSIZE * 300)
)

// Offsets are of the form FROM_TO_OFF = VALUE
const (
	STACK_TCS_OFF   = PSIZE
	TCS_SSA_OFF     = 0
	SSA_MSGX_OFF    = PSIZE
	MSGX_TLS_OFF    = 0
	TLS_MHSTART_OFF = PSIZE
)

// Elf.Symbol.Name to find addresses
const (
	mtlsArrayName = "runtime.enclaveMsgxTlsArr"
)

var (
	RT_M0 = uintptr(0)
)

type sgx_enclave_create struct {
	src uint64
}

type sgx_enclave_init struct {
	addr       uint64
	sigstruct  uint64
	einittoken uint64
}

type sgx_enclave_add_page struct {
	addr    uint64
	src     uint64
	secinfo uint64
	mrmask  uint16 //bitmask for the 256 byte chunks that are to be measured
}

type isgx_secinfo struct {
	flags    uint64
	reserved [7]uint64
}

type sgx_wrapper struct {
	base    uintptr
	siz     uintptr
	tcss    []sgx_tcs_info
	mhstart uintptr // 0x1000
	mhsize  uintptr // 0x108000
	membuf  uintptr // To satisfy map(nil) requests
	alloc   []byte
	secs    *secs_t
	isSim   bool
	entry   uintptr // where to jump (asm_eenter or file.Entry)
	mtlsarr uintptr
}

type sgx_tcs_info = runtime.SgxTCSInfo

func (s *sgx_wrapper) DumpDebugInfo() {
	if runtime.Cooprt != nil {
		fmt.Printf("Cooprt at %p\n", runtime.Cooprt)
		fmt.Printf("Cooprt.Ecall %p, Cooprt.Ocall %p\n", runtime.Cooprt.EcallSrv, runtime.Cooprt.Ocall)
		fmt.Printf("Unsafe allocation: %x, size: %x\n", runtime.Cooprt.StartUnsafe, runtime.Cooprt.SizeUnsafe)
	}
	fmt.Printf("[DEBUG-INFO] wrapper at %p\n", s)
	fmt.Printf("{base: %x, siz: %x, mhstart: %x, mhsize: %x}\n", s.base, s.siz, s.mhstart, s.mhsize)
	for _, tcs := range s.tcss {
		fmt.Printf("stack: %x, ssiz: %x, tcs: %x, msgx: %x, tls: %x\n", tcs.Stack,
			tcs.Ssiz, tcs.Tcs, tcs.Msgx, tcs.Tls)
	}
}

func (s *sgx_wrapper) defaultTcs() *sgx_tcs_info {
	if s.tcss == nil || len(s.tcss) == 0 {
		panic("Early call to get defaulttcs")
	}
	return &s.tcss[0]
}

func transposeOutWrapper(wrap *sgx_wrapper) *sgx_wrapper {
	trans := &sgx_wrapper{
		transposeOut(wrap.base), wrap.siz, nil,
		transposeOut(wrap.mhstart), wrap.mhsize,
		transposeOut(wrap.membuf), nil, wrap.secs, wrap.isSim,
		wrap.entry, transposeOut(wrap.mtlsarr)}

	trans.tcss = make([]sgx_tcs_info, len(wrap.tcss))
	for i := 0; i < len(wrap.tcss); i++ {
		trans.tcss[i] = transposeOutTCS(wrap.tcss[i])
	}
	return trans
}

func transposeOutTCS(orig sgx_tcs_info) sgx_tcs_info {
	return sgx_tcs_info{
		transposeOut(orig.Stack), orig.Ssiz, transposeOut(orig.Tcs),
		transposeOut(orig.Ssa), transposeOut(orig.Msgx), transposeOut(orig.Tls),
		orig.Rdi, orig.Rsi,
		transposeOut(orig.Entry), orig.Used}
}

// getMtlsArr finds the address of the array that we leverage to put MSGX | TLS
// pages in the enclave as part of the bss segment.
func getMtlsArr(file *elf.File) uintptr {
	syms, err := file.Symbols()
	check(err)
	for _, s := range syms {
		if s.Name == mtlsArrayName {
			return uintptr(palign(s.Value, false))
		}
	}
	//Unable to find the symbol.
	panic("isgx was unable to find the enclaveMsgxTlsArr symbol address.")
	return uintptr(0)
}
