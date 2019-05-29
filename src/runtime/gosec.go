package runtime

import (
	"runtime/internal/atomic"
	"unsafe"
)

type SysType int

const (
	S3  SysType = 0
	S6  SysType = 1
	RS3 SysType = 2
	RS6 SysType = 3
	MAL SysType = 4
	FRE SysType = 5
)

// For epoll from the enclave.
const (
	ENCL_POLLING  = 0
	ENCL_NPOLLING = 1
)

//EcallServerRequest type is used to send a request for the enclave to spawn
//a new dedicated ecall server listening on the provided private PC channel.
type EcallServerReq struct {
	PrivChan chan EcallReq
}

//EcallReq contains the arguments for an ecall. Mimics the newproc interface.
//Name is the target routine's name.
//Siz is the size of the argument buffer.
//Argp all the arguments.
//Buf an extra slice buffer.
type EcallReq struct {
	Name string
	Siz  int32
	Argp *uint8 //TODO @aghosn not sure about this one.
	Buf  []uint8
}

type OcallReq struct {
	Big  SysType
	Trap uintptr
	A1   uintptr
	A2   uintptr
	A3   uintptr
	A4   uintptr
	A5   uintptr
	A6   uintptr
	Id   int
}

type OcallRes struct {
	R1  uintptr
	R2  uintptr
	Err uintptr
}

type poolSysChan struct {
	id        int
	available uint32
	c         chan OcallRes
}

// Request types for OExitRequest.
const (
	SpawnRequest       = uint64(1)
	FutexSleepRequest  = uint64(2)
	FutexWakeupRequest = uint64(3)
	EPollWaitRequest   = uint64(4)
)

//OExitRequest pass when doing an sgx_ocall.
//It is supposed to have a size of 64bytes, which is the granularity of our
//unsafe allocator.
type OExitRequest struct {
	Cid   uint64  //OExit id
	Sid   uint64  //tcs source id of requester
	Did   uint64  // tcs dest id for new thread
	Gp    uintptr // the g that will be used for the new thread
	Mp    uintptr // the m that will be used for the new thread
	Addr  uintptr // pointer to futex target
	Val   uint32  // value that needs to be written with futex
	Ns    int64   // nano sleep timeout
	EWReq uintptr // address of the epoll request
	EWRes uintptr // address of the epoll result
}

//SgxTCSInfo describes a tcs related information, such as tls.
type SgxTCSInfo struct {
	Stack uintptr
	Ssiz  uintptr
	Tcs   uintptr // tcs size 0x1000.
	Ssa   uintptr
	Msgx  uintptr // size 0x1000, for the mglobal otherwise doesn't work
	Tls   uintptr // size 0x1000
	Rdi   uint64
	Rsi   uint64
	Entry uintptr // entry point for this tcs.
	Used  bool
}

//CooperativeRuntime information and channels for runtime cooperation.
type CooperativeRuntime struct {
	EcallSrv chan *EcallServerReq
	Ocall    chan OcallReq

	argc int32
	argv **byte

	readyE slqueue //Ready to be rescheduled in the enclave
	readyO slqueue //Ready to be rescheduled outside of the enclave

	//pool of answer channels.
	sysPool []*poolSysChan

	membuf_head uintptr

	StartUnsafe uintptr
	SizeUnsafe  uintptr

	// The enclave heap region.
	// This is the equivalent of my previous preallocated regions.
	// TODO secure it somehow.
	eHeap            uintptr
	Tcss             []SgxTCSInfo // array of tcs infos used in spawnThread
	Notes            [10]note     // notes for futex calls.
	OEntry           uintptr
	ExceptionHandler uint64

	Uach chan uintptr
}

const (
	//TODO @aghosn this must be exactly the same as in amd64/obj.go
	PSIZE       = 0x1000
	ENCLMASK    = 0x040000000000
	ENCLSIZE    = 0x001000000000
	MMMASK      = 0x050000000000
	MEMBUF_SIZE = uintptr(PSIZE * 1400)

	SG_BUF_SIZE = 100 // size in bytes

	POOL_INIT_SIZE = 5000 //Default size for the pools.

	// TODO this must be the same as in the gosec package.
	// Later move all of these within a separate package and share it.
	MEMBUF_START = (ENCLMASK + ENCLSIZE - PSIZE - MEMBUF_SIZE)
	_unsafeSize  = PSIZE * 500
)

var (
	UnsafeAllocator uledger // manages unsafe memory from the enclave.
	workEnclave     uintptr // replica for the gc in unsafe memory
	schedEnclave    uintptr // replica for notesleeps on the sched.
)

// entry point for an ocall, defined in asm in runtime/asmsgx_amd64.s
func sgx_ocall(trgt, args, nstk, rbp uintptr)

//InitCooperativeRuntime initializes the global variable Cooprt.
func InitCooperativeRuntime() {
	if Cooprt != nil {
		return
	}

	Cooprt = &CooperativeRuntime{}
	Cooprt.EcallSrv = make(chan *EcallServerReq)
	Cooprt.argc, Cooprt.argv = -1, argv
	Cooprt.Ocall = make(chan OcallReq)
	Cooprt.sysPool = make([]*poolSysChan, POOL_INIT_SIZE)
	for i := range Cooprt.sysPool {
		Cooprt.sysPool[i] = &poolSysChan{i, 1, make(chan OcallRes)}
	}
	Cooprt.membuf_head = uintptr(MEMBUF_START)
	Cooprt.eHeap = 0
	cprtQ = &(Cooprt.readyO)

	//Allocate the unsafe zone for the enclave.
	ptr, err := mmap(nil, _unsafeSize, _PROT_READ|_PROT_WRITE, _MAP_ANON|_MAP_PRIVATE, -1, 0)
	if err != 0 {
		panic("Error allocating the unsafe zone.")
	}
	Cooprt.StartUnsafe = uintptr(ptr)
	Cooprt.SizeUnsafe = _unsafeSize
	Cooprt.Uach = make(chan uintptr)
}

// SetHeapValue allows to let Cooprt register enclave heap value.
func (c *CooperativeRuntime) SetHeapValue(e uintptr) bool {
	if c.eHeap != 0 {
		return false
	}
	c.eHeap = e
	return true
}

// TranslateNote translates enclave note address into unsafe one.
// Required for futexsleepp from the enclave. TODO this is wrong somehow.
//go:nosplit
//go:nowritebarrier
func (c *CooperativeRuntime) TranslateNote(n *note) *note {
	nptr := uintptr(unsafe.Pointer(n))
	//Sometimes nested calls, so already translated
	if nptr >= c.StartUnsafe && nptr <= c.StartUnsafe+c.SizeUnsafe {
		return n
	}

	// Calling futex on something outside of the enclave.
	// Should not happen so throw exception for the moment
	// TODO support this later
	if nptr < ENCLMASK || nptr > ENCLMASK+ENCLSIZE {
		throw("Calling futex from enclave on a non enclave note")
		return n
	}
	// A note from the M
	for i, tcs := range c.Tcss {
		if nptr > tcs.Tls && nptr < tcs.Tls+PSIZE {
			return &c.Notes[i]
		}
	}

	// A note from the work
	wkptr := uintptr(unsafe.Pointer(&work))
	wksize := unsafe.Sizeof(work)
	if nptr > wkptr && nptr < wkptr+wksize {
		res := (*note)(unsafe.Pointer(workEnclave + (nptr - wkptr)))
		return res
	}

	scdptr := uintptr(unsafe.Pointer(&sched))
	scdsize := unsafe.Sizeof(sched)
	if nptr > scdptr && nptr < scdptr+scdsize {
		res := (*note)(unsafe.Pointer(schedEnclave + (nptr - scdptr)))
		return res
	}

	println("nptr: ", nptr)
	for _, tcs := range c.Tcss {
		println("tls: ", tcs.Tls, " Msgx: ", tcs.Msgx)
	}
	throw("Could not find the corresponding note")
	return n
}

//MarkNoFutex sets the g's markednofutex attribute to true.
//This prevents blocking on a channel operation.
func MarkNoFutex() {
	_g_ := getg()
	_g_.markednofutex = true
}

//MarkFutex sets the g's markednofutex to false.
//This allows the routine to futex sleep on a lock.
func MarkFutex() {
	_g_ := getg()
	_g_.markednofutex = false
}

//IsEnclave exposes the runtime.isEnclave value to the outside.
func IsEnclave() bool {
	return isEnclave
}

//IsSimulation exposes the runtime.isSimulation to the outside.
func IsSimulation() bool {
	return isSimulation
}

func checkEnclaveBounds(addr uintptr) {
	if isEnclave {
		// Enclave has access to everything.
		return
	}
	if addr >= ENCLMASK && addr < ENCLMASK+ENCLSIZE {
		print("pre-panic: addr ", hex(addr), "\n")
		panic("runtime: illegal address used outside of the enclave.")
	}
}

func panicGosec(a string) {
	if isEnclave {
		marker := (*uint64)(unsafe.Pointer(uintptr(0x050000000000)))
		*marker = uint64(0x666)
	}
	panic(a)
}

// sysFutex allows to do a wakeup call on a futex while going through the
// interposition mechanism.
func sysFutex(addr *uint32, cnt uint32) {
	syscid, csys := Cooprt.AcquireSysPool()
	sys_futex := uintptr(202)
	req := OcallReq{S6, sys_futex, uintptr(unsafe.Pointer(addr)),
		uintptr(_FUTEX_WAKE), uintptr(cnt), 0, 0, 0, syscid}
	Cooprt.Ocall <- req
	_ = <-csys
	Cooprt.ReleaseSysPool(syscid)
	// TODO aghosn Don't care about the result for now
}

// checkinterdomain detects inter domain crossing and panics if foreign has
// higher protection than local. Returns true if local and foreign belong to
// different domains.
// This function is called when writting to a channel for example.
func checkinterdomain(rlocal, rforeign bool) bool {
	if !rlocal && rforeign {
		panicGosec("An untrusted routine is trying to access a trusted channel")
	}
	return rlocal != rforeign
}

// migrateCrossDomain takes ready routines from the cross domain queue and puts
// them in the local or global run queue.
// the locked argument tells us if sched.lock is locked.
//go:nosplit
//go:nowritebarrier
func migrateCrossDomain(locked bool) {
	_g_ := getg()
	_g_.m.locks++
	if cprtQ == nil {
		throw("migrateCrossdomain called on un-init cprtQ.")
	}

	sgq, tail, size := slqget(cprtQ, locked)
	if size == 0 {
		_g_.m.locks--
		return
	}
	if sgq == nil {
		println("Oh mighty fucks: ", size)
		throw("Crashy crash")
	}
	for i := 0; i < size; i++ {
		sg := sgq
		gp := sg.g
		if sgq.schednext != 0 {
			sgq = sgq.schednext.ptr()
		} else if sgq != tail {
			throw("malformed sgqueue, tail does not match tail(q)")
		}
		sg.schednext = 0
		ready(gp, 3+1, false)
	}
	if size > 0 && _g_.m.spinning {
		resetspinning()
	}
	_g_.m.locks--
}

// crossReleaseSudog calls the appropriate releaseSudog version depending on whether
// the sudog is a crossdomain one or not.
func crossReleaseSudog(sg *sudog, size uint16) {
	sg.needcpy = false
	// Check if this is not from the pool and is same domain (regular path)
	if isReschedulable(sg) {
		releaseSudog(sg)
		return
	}
	UnsafeAllocator.ReleaseUnsafeSudog(sg, size)
}

// isReschedulable checks if a sudog can be directly rescheduled.
// For that, we require the sudog to not belong to the pool and for the unblocking
// routine to belong to the same domain as this sudog.
func isReschedulable(sg *sudog) bool {
	if sg == nil {
		panicGosec("Calling isReschedulable with nil sudog.")
	}
	return (sg.id == -1 && !checkinterdomain(isEnclave, sg.g.isencl))
}

// crossGoready takes a sudog and makes it ready to be rescheduled.
// This method should be called only once the isReschedulable returned false.
func (c *CooperativeRuntime) crossGoready(sg *sudog) {
	// We are about to make ready a sudog that is not from the pool.
	// This can happen only when non-trusted has blocked on a channel.
	target := &c.readyE
	if sg.id == -1 {
		if sg.g.isencl || sg.g.isencl == isEnclave {
			panicGosec("Misspredicted the crossdomain scenario.")
		}
		target = &c.readyO
	}
	// warn that it needs copy
	sg.needcpy = true
	slqput(target, sg)
}

func (c *CooperativeRuntime) AcquireSysPool() (int, chan OcallRes) {
	for i, s := range c.sysPool {
		if s.available == 1 && atomic.Xchg(&c.sysPool[i].available, 0) == 1 {
			c.sysPool[i].id = i
			return i, c.sysPool[i].c
		}
	}
	panicGosec("Ran out of syspool channels.")
	return -1, nil
}

func (c *CooperativeRuntime) ReleaseSysPool(id int) {
	if id < 0 || id >= len(c.sysPool) {
		panicGosec("Trying to release out of range syspool")
	}
	if c.sysPool[id].available != 0 {
		panicGosec("Trying to release an available channel")
	}

	//Do we need atomic here?
	c.sysPool[id].available = 1
}

func (c *CooperativeRuntime) SysSend(id int, r OcallRes) {
	c.sysPool[id].c <- r
}

// Sets up the stack arguments and returns the beginning of the stack address.
func SetupEnclSysStack(stack, eS uintptr) uintptr {
	if isEnclave {
		panicGosec("Should not allocate enclave from the enclave.")
	}

	addrArgc := stack - unsafe.Sizeof(argc)
	addrArgv := addrArgc - unsafe.Sizeof(argv)

	ptrArgc := (*int32)(unsafe.Pointer(addrArgc))
	*ptrArgc = argc

	// Initialize the Cooprt
	Cooprt.SetHeapValue(eS)

	ptrArgv := (***byte)(unsafe.Pointer(addrArgv))
	*ptrArgv = (**byte)(unsafe.Pointer(Cooprt))

	return addrArgv
}

//go:nosplit
func StartEnclaveOSThread(stack uintptr, fn unsafe.Pointer) {
	ret := clone(cloneFlags, unsafe.Pointer(stack), nil, nil, fn)
	if ret < 0 {
		write(2, unsafe.Pointer(&failthreadcreate[0]), int32(len(failthreadcreate)))
		exit(1)
	}
}

//go:nosplit
func Newproc(ptr uintptr, argp *uint8, siz int32) {
	if Cooprt == nil {
		panic("Cooprt must be init before calling gosec.go:Newproc")
	}
	fn := &funcval{ptr}
	pc := getcallerpc()
	systemstack(func() {
		newproc1(fn, argp, siz, pc)
	})
}

//GosecureSend sends an ecall request on the p's private channel.
//TODO @aghosn: Maybe should change to avoid performing several copies!
func GosecureSend(req EcallReq) {
	gp := getg()
	if gp == nil {
		throw("Gosecure: un-init g.")
	}
	if Cooprt == nil {
		throw("Cooprt not initialized.")
	}
	if gp.ecallchan == nil {
		gp.ecallchan = make(chan EcallReq)
		srvreq := &EcallServerReq{gp.ecallchan}
		MarkNoFutex()
		Cooprt.EcallSrv <- srvreq
		MarkFutex()
	}
	MarkNoFutex()
	gp.ecallchan <- req
	MarkFutex()
}

//go:noescape
func sched_setaffinity(pid, len uintptr, buf *uintptr) int32

func enclaveIsMapped(ptr uintptr, n uintptr) bool {
	if ptr >= Cooprt.eHeap && ptr+n <= Cooprt.eHeap+_MaxMemEncl {
		return true
	}
	return false
}

func EnclHeapSizeToAllocate() uintptr {
	return _MaxMemEncl
}

// Futexsleep for the enclave. We interpose so that we can eexit.
//go:nosplit
func futexsleep0(addr *uint32, val uint32, ns int64) {
	gp := getg()
	if gp == nil || gp.m == nil || gp.m.g0 == nil {
		throw("Something is not initialized.")
	}
	ustk := gp.m.g0.sched.usp
	ubp := gp.m.g0.sched.ubp
	aptr := UnsafeAllocator.Malloc(unsafe.Sizeof(OExitRequest{}))
	args := (*OExitRequest)(unsafe.Pointer(aptr))
	args.Cid = FutexSleepRequest
	args.Sid = gp.m.procid
	args.Addr = uintptr(unsafe.Pointer(addr))
	args.Val = val
	args.Ns = ns
	sgx_ocall(Cooprt.OEntry, aptr, ustk, ubp)
	UnsafeAllocator.Free(aptr, unsafe.Sizeof(OExitRequest{}))
}

// Futexwakeup for the enclave.
//go:nosplit
func futexwakeup0(addr *uint32, cnt uint32) {
	gp := getg()
	if gp == nil || gp.m == nil || gp.m.g0 == nil {
		throw("Something is not initialized.")
	}
	ustk := gp.m.g0.sched.usp
	ubp := gp.m.g0.sched.ubp
	aptr := UnsafeAllocator.Malloc(unsafe.Sizeof(OExitRequest{}))
	args := (*OExitRequest)(unsafe.Pointer(aptr))
	args.Cid = FutexWakeupRequest
	args.Sid = gp.m.procid
	args.Addr = uintptr(unsafe.Pointer(addr))
	args.Val = cnt
	sgx_ocall(Cooprt.OEntry, aptr, ustk, ubp)
	UnsafeAllocator.Free(aptr, unsafe.Sizeof(OExitRequest{}))
}

//go:nosplit
//go:nowritebarrier
func FutexsleepE(addr unsafe.Pointer, val uint32) {
	futex(addr, _FUTEX_WAIT, val, nil, nil, 0)
}

//go:nosplit
//go:nowritebarrier
func FutexwakeupE(addr unsafe.Pointer, val uint32) {
	ret := futex(addr, _FUTEX_WAKE, val, nil, nil, 0)
	if ret >= 0 {
		return
	}
	throw("Futex wakeup enclave failed.")
}

//go:nosplit
//go:nowritebarrier
func EpollPWait(req *OcallReq, res *OcallRes) {
	res.R1 = uintptr(eepollwait(int32(req.A1),
		(*epollevent)(unsafe.Pointer(req.A2)), int32(req.A3), int32(req.A4)))
}

func SetChanType(cptr uintptr, tpe *DPTpe) {
	c := (*hchan)(unsafe.Pointer(cptr))
	c.encltpe = tpe
}
