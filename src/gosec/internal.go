package gosec

import (
	"bytes"
	"debug/elf"
	"gosecommon"
	"log"
	"os"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

func check(e error) {
	if e != nil {
		panic(e.Error())
	}
}

type funcval struct {
	fn uintptr
	// variable-size, fn-specific data here
}

var initOnce sync.Once

func asm_oentry(req *runtime.OExitRequest)

func LoadEnclave() {
	p, err := elf.Open(os.Args[0])
	check(err)

	enclave := p.Section(".encl")
	defer func() { check(p.Close()) }()
	if enclave == nil {
		log.Fatalf("Binary %v does not contain an enclave section.", os.Args[0])
	}

	bts, err := enclave.Data()
	check(err)

	// Remove the header by seeking the magic bytes.
	magic := []byte{0x7F, 0x45, 0x4C, 0x46}
	var i = 0
	for i = 0; i < len(bts)-len(magic); i++ {
		if bytes.Compare(bts[i:i+len(magic)], magic) == 0 {
			break
		}
	}
	if i >= len(bts)-len(magic) {
		log.Fatalf("Unable to find the start of the executable in the encl section.")
	}
	bts = bts[i:]
	name := "enclavebin"
	encl, err := os.Create(name)
	check(err)

	//Mmap debugging region
	//prot := _PROT_READ | _PROT_WRITE
	//manon := _MAP_PRIVATE | _MAP_ANON | _MAP_FIXED
	//_, err = syscall.RMmap(runtime.DEBUGMASK, 0x1000, prot, manon, -1, 0)
	//check(err)
	defer func() { check(encl.Close()) }()

	check(os.Chmod(name, 0755))

	_, err = encl.Write(bts)
	check(err)

	//Setup the OEntry in Cooprt for extra threads
	runtime.Cooprt.OEntry = reflect.ValueOf(asm_oentry).Pointer()

	// Set the deep copier
	runtime.SetCopier(gosecommon.DeepCopier, gosecommon.CanShallowCopy)

	//Start loading the program within the correct address space.
	if s := os.Getenv("SIM"); s != "" {
		simLoadProgram(name)
	} else {
		sgxLoadProgram(name)
	}
}

func oCallServer() {
	runtime.MarkNoFutex()
	for {
		sys := <-runtime.Cooprt.Ocall
		var r1 uintptr
		var r2 uintptr
		var err syscall.Errno
		switch sys.Big {
		case runtime.S3:
			r1, r2, err = syscall.Syscall(sys.Trap, sys.A1, sys.A2, sys.A3)
		case runtime.S6:
			r1, r2, err = syscall.Syscall6(sys.Trap, sys.A1, sys.A2, sys.A3, sys.A4, sys.A5, sys.A6)
		case runtime.RS3:
			r1, r2, err = syscall.RawSyscall(sys.Trap, sys.A1, sys.A2, sys.A3)
		case runtime.RS6:
			r1, r2, err = syscall.RawSyscall6(sys.Trap, sys.A1, sys.A2, sys.A3, sys.A4, sys.A5, sys.A6)
		case runtime.MAL:
			manon := int32(_MAP_PRIVATE | _MAP_ANON | _MAP_NORESERVE)
			ur1, e := runtime.RMmap(nil, sys.A2, _PROT_READ|_PROT_WRITE, manon, -1, 0)
			if e != 0 {
				log.Fatalln("Unable to mmap big buffer size:", sys.A2, " and error: ", syscall.Errno(e))
			}
			r1 = uintptr(ur1)
		case runtime.FRE:
			runtime.RMunmap(unsafe.Pointer(sys.A1), sys.A2)
			continue
		default:
			panic("Unsupported syscall forwarding.")
		}
		res := runtime.OcallRes{r1, r2, uintptr(err)}
		go runtime.Cooprt.SysSend(sys.Id, res)
	}
	panic("Should never exit")
}

func bufcopy(dest []uint8, src *uint8, size int32) {
	ptr := uintptr(unsafe.Pointer(src))
	for i := uintptr(0); i < uintptr(size); i += unsafe.Sizeof(uint8(0)) {
		lptr := (*uint8)(unsafe.Pointer(ptr + i))
		dest[i] = *lptr
	}
}

// Gosecload has the same signature as newproc().
// It creates the enclave if it does not exist yet, and write to the cooperative channel.
//go:nosplit
func Gosecload(size int32, fn *funcval, b uint8) {
	pc := runtime.FuncForPC(fn.fn)
	if pc == nil {
		log.Fatalln("Unable to find the name for the func at address ", fn.fn)
	}

	initOnce.Do(func() {
		runtime.InitCooperativeRuntime()
		LoadEnclave()
		// Server to allocate requests & service system calls for the enclave.
		go oCallServer()
	})

	//Copy the stack frame inside a buffer.
	attrib := runtime.EcallReq{Name: pc.Name(), Siz: size, Buf: nil, Argp: nil}
	if size > 0 {
		attrib.Buf = make([]uint8, size, size)
		bufcopy(attrib.Buf, &b, size)
		attrib.Argp = (*uint8)(unsafe.Pointer(&(attrib.Buf[0])))
	}
	runtime.GosecureSend(attrib)
}

// executes without g, m, or p, so might need to do better.
//go:nosplit
func spawnEnclaveThread(req *runtime.OExitRequest) {
	if !enclWrap.tcss[req.Did].Used {
		panic("Error, tcs is not reserved.")
	}
	src := &srcWrap.tcss[req.Did]
	dest := &enclWrap.tcss[req.Did]
	src.Used, dest.Used = true, true

	sgxEEnter(uint64(req.Did), dest, src, req)
	// In the simulation we just return.
	if enclWrap.isSim {
		return
	}
	// For sgx, we call eresume
	sgxEResume(req.Sid)
	panic("gosec: unable to find an available tcs")
}

//go:nosplit
func FutexSleep(req *runtime.OExitRequest) {
	runtime.FutexsleepE(unsafe.Pointer(req.Addr), req.Val)
	if enclWrap.isSim {
		return
	}
	sgxEResume(req.Sid)
}

//go:nosplit
func FutexWakeup(req *runtime.OExitRequest) {
	runtime.FutexwakeupE(unsafe.Pointer(req.Addr), req.Val)
	if enclWrap.isSim {
		return
	}
	sgxEResume(req.Sid)
}

//go:nosplit
func EpollPWait(req *runtime.OExitRequest) {
	request := (*runtime.OcallReq)(unsafe.Pointer(req.EWReq))
	result := (*runtime.OcallRes)(unsafe.Pointer(req.EWRes))
	runtime.EpollPWait(request, result)
	if enclWrap.isSim {
		return
	}
	sgxEResume(req.Sid)
}

//go:nosplit
func sgxEResume(id uint64) {
	tcs := runtime.Cooprt.Tcss[id]
	xcpt := runtime.Cooprt.ExceptionHandler
	asm_eresume(uint64(tcs.Tcs), xcpt)
}
