package gosecu

import (
	"fmt"
	"gosecommon"
	"reflect"
	"runtime"
	"unsafe"
)

// Slice of gosecure targets.
var (
	secureMap map[string]func(size int32, argp *uint8)
)

func freeServer() {
	for {
		addr := <-runtime.Cooprt.Uach
		runtime.UnsafeAllocator.FreeTracker(addr)
	}
}

// We cannot use reflect to get the value of the arguments. Instead, we give
// a pointer to a buffer allocated inside the ecall attribute and use it to pass
// the arguments from the stack frame.
func privateServer(c chan runtime.EcallReq) {
	success := 0
	for {
		call := <-c
		if fn := secureMap[call.Name]; fn != nil {
			success++
			go fn(call.Siz, call.Argp)
		} else {
			panic("gosecu: illegal gosecure call.")
		}
	}
	fmt.Println("Closing the privateServer ", success)
	panic("Closing the shit")
}

// EcallServer keeps polling the Cooprt.Ecall queue for incoming private ecall
// server requests.
func EcallServer() {
	// Init the cross domain ref pointer for crossed routines.
	//runtime.InitAllcg()
	go freeServer()
	for {
		req := <-runtime.Cooprt.EcallSrv
		if req == nil || req.PrivChan == nil {
			panic("[EcallServer] nil value received, probably stack shrink")
			continue
		}

		go privateServer(req.PrivChan)
	}
}

// RegisterSecureFunction is called automatically at the begining of the enclave
// execution, and registers all the functions that are a target of the gosecure
// keyword.
func RegisterSecureFunction(f interface{}) {
	if secureMap == nil {
		secureMap = make(map[string]func(size int32, argp *uint8))
		runtime.SetCopiers(gosecommon.DeepCopier, gosecommon.DeepCopierSend, gosecommon.CanShallowCopy)
	}

	ptr := reflect.ValueOf(f).Pointer()
	pc := runtime.FuncForPC(ptr)
	if pc == nil {
		//log.Fatalln("Unable to register secure function.")
		panic("Unable to register secure function.")
	}

	//TODO @aghosn that will not be enough probably. Should have a pointer instead?
	// or copy memory in a buffer inside the anonymous function?
	secureMap[pc.Name()] = func(size int32, argp *uint8) {
		// TODO deep copy the stack frame
		if size == 0 {
			runtime.Newproc(ptr, argp, size)
			return
		}
		sl := gosecommon.DeepCopyStackFrame(size, argp, reflect.ValueOf(f).Type())
		argpcpy := (*uint8)(unsafe.Pointer(&sl[0]))
		runtime.Newproc(ptr, argpcpy, size)
	}
}
