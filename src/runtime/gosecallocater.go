package runtime

import (
	"unsafe"
)

//TODO rewrite to be write barrier compatible.
const (
	_psize          = 0x1000
	_uspgranularity = 64 //allocate by chunks of 64 bytes.
	_uspfree        = uint64(0x0000000000000000)
	_uspfull        = uint64(0xffffffffffffffff)
	_sgfree         = uint32(0x0)
	_sglock         = uint32(0x1)
	_sgcachesize    = uint32(500)
	_spansize       = _psize
)

//uspan is an unsafe span of memory from which we perform the allocation.
//it corresponds to a page size.
type uspan struct {
	id       uint32
	bitmask  uint64  //quick check for available 64 bytes slots, bit 0 is [start;start+64[
	start    uintptr //address of the beginning.
	freesize uintptr //in bytes
	prev     uspanptr
	next     uspanptr
}

type uspanptr uintptr

//go:nosplit
func (u uspanptr) ptr() *uspan {
	return (*uspan)(unsafe.Pointer(u))
}

//go:nosplit
func (u *uspanptr) set(us *uspan) {
	*u = uspanptr(unsafe.Pointer(us))
}

type umentry struct {
	size uint32
	mask uint64
}

type sgentry struct {
	sg       sudog
	isrcv    bool
	orig     unsafe.Pointer
	buff     unsafe.Pointer
	sbuff    uintptr
	elemtype *_type
	tracker  AllocTracker
}

type spanlist struct {
	head uspanptr
	tail uspanptr
}

type uledger struct {
	start     uintptr
	size      uintptr
	allspans  []uspan
	freespans spanlist
	fullspans spanlist

	poolsg  waitq //keep a pool of allocated sgs
	psgsize uint32
	psglock slock

	inited bool
	sl     slock
	toFree map[uintptr]AllocTracker
}

//go:nowritebarrier
func (sl *spanlist) add(u *uspan) {
	if sl.tail == 0 {
		if sl.head != 0 {
			throw("empty head, non-empty tail")
		}
		sl.head.set(u)
		sl.tail.set(u)
		u.prev = 0
		u.next = 0
	}
	sl.tail.ptr().next.set(u)
	u.prev.set(sl.tail.ptr())
	u.next = 0
	sl.tail.set(u)
}

//go:nowritebarrier
func (sl *spanlist) remove(u *uspan) {
	if u.prev != 0 {
		u.prev.ptr().next = u.next
	}
	if sl.tail.ptr() == u {
		sl.tail = u.prev
	}
	if sl.head.ptr() == u {
		sl.head = u.next
	}
	u.next = 0
	u.prev = 0
}

//go:nowritebarrier
func (sl *spanlist) isEmpty() bool {
	return sl.head == 0
}

//initialize takes the start and size (in bytes) of the unsafe memory pool.
func (u *uledger) Initialize(start, size uintptr) {
	if size == 0 || size%_psize != 0 {
		throw("uledger: bad init values")
	}
	u.start = start
	u.size = size
	nbpages := size / _psize
	u.allspans = make([]uspan, nbpages)
	for i := 0; i < int(nbpages); i++ {
		sp := &u.allspans[i]
		sp.id = uint32(i)
		sp.bitmask = _uspfree
		sp.start = start + uintptr(i)*_psize
		sp.freesize = _spansize
		u.freespans.add(sp)
	}
	// Now initialize the workEnclave
	workEnclave = u.Malloc(unsafe.Sizeof(work))
	schedEnclave = u.Malloc(unsafe.Sizeof(sched))
	u.toFree = make(map[uintptr]AllocTracker)
}

//go:nosplit
//go:nowritebarrier
func (u *uledger) Malloc(size uintptr) uintptr {
	//slow path, TODO check that no lock is held
	if size >= _spansize {
		syscid, csys := Cooprt.AcquireSysPool()
		req := OcallReq{MAL, 0, 0, size, 0, 0, 0, 0, syscid}
		Cooprt.Ocall <- req
		res := <-csys
		return res.R1
	}
	u.sl.lock()
	if u.freespans.isEmpty() {
		println("Size of allspans ", len(u.allspans))
		println("Size of a sudog ", unsafe.Sizeof(sudog{}), " - ", u.inited)
		throw("uledger: ran out of memory")
	}
	for sptr := u.freespans.head; sptr != 0; sptr = sptr.ptr().next {
		span := sptr.ptr()
		if span.freesize >= size {
			//We are looking for contiguous space so it might fail
			if ptr, ok := span.allocate(size); ok {
				//If now the span is full, move it
				if span.freesize == 0 {
					u.freespans.remove(span)
					u.fullspans.add(span)
				}
				u.sl.unlock()
				//set to zero
				for i := uintptr(0); i < size; i++ {
					bptr := (*byte)(unsafe.Pointer(ptr + i))
					*bptr = byte(0)
				}
				return ptr
			}
		}
	}
	u.sl.unlock()
	throw("uledger: ran out of contiguous memory")
	return uintptr(0)
}

//go:nosplit
//go:nowritebarrier
func (u *uledger) Free(ptr, size uintptr) {
	// Slow path
	if size >= _spansize {
		// There is no need to get an answer
		req := OcallReq{FRE, 0, ptr, size, 0, 0, 0, 0, 0}
		Cooprt.Ocall <- req
		return
	}
	u.sl.lock()
	index := (ptr - u.start) / _spansize //find the pod
	move, ok := u.allspans[index].deallocate(ptr, size)
	if !ok { //Failed de-allocating
		throw("uledger: error deallocating object!")
	}
	if move { //The span was full
		u.fullspans.remove(&u.allspans[index])
		u.freespans.add(&u.allspans[index])
	}
	u.sl.unlock()
}

func (u *uledger) FreeAll(tracker AllocTracker) {
	for _, v := range tracker {
		u.Free(v.Src, v.Size)
	}
}

// AcquireUnsafeSudog returns an unsafe sudog and an unsafe buffer as
// requested.
//go:nosplit
func (u *uledger) AcquireUnsafeSudog(elem unsafe.Pointer, isrcv bool, size uint16, elemtype *_type) (*sudog, unsafe.Pointer) {
	if !isEnclave {
		throw("Error in AcquireUnsafeSudog")
	}
	var sg *sudog
	//Quick check if the queue is empty
	if u.psgsize > 0 {
		u.psglock.lock()
		sg = u.poolsg.dequeue()
		if sg != nil {
			u.psgsize--
		}
		u.psglock.unlock()
	}

	//Need to allocate a new one.
	if sg == nil {
		sg = (*sudog)(unsafe.Pointer(u.Malloc(unsafe.Sizeof(sgentry{}))))
	}
	sg.id = 1
	buff := unsafe.Pointer(u.Malloc(uintptr(size)))
	if elem != nil {
		typedmemmove(elemtype, buff, elem)
	}
	sg.schednext = 0
	//book-keeping for the release.
	sge := (*sgentry)(unsafe.Pointer(sg))
	sge.isrcv = isrcv
	sge.orig = elem
	sge.buff = buff
	sge.sbuff = uintptr(size)
	sge.elemtype = elemtype
	// register the g
	allcgadd(getg())
	return sg, buff
}

func (u *uledger) AcquireUnsafeSudogSend(elem unsafe.Pointer, size uint16, elemtype *_type) (*sudog, unsafe.Pointer) {
	if !isEnclave {
		throw("Error in AcquireUnsafeSudogSend")
	}
	var sg *sudog
	//Quick check if the queue is empty
	if u.psgsize > 0 {
		u.psglock.lock()
		sg = u.poolsg.dequeue()
		if sg != nil {
			u.psgsize--
		}
		u.psglock.unlock()
	}

	//Need to allocate a new one.
	if sg == nil {
		sg = (*sudog)(unsafe.Pointer(u.Malloc(unsafe.Sizeof(sgentry{}))))
	}
	sg.id = 1
	buff, tracker := DeepCopierSend(elem, elemtype)
	sg.schednext = 0
	//book-keeping for the release.
	sge := (*sgentry)(unsafe.Pointer(sg))
	sge.isrcv = false
	sge.orig = elem
	sge.buff = buff
	sge.sbuff = uintptr(size)
	sge.elemtype = elemtype
	sge.tracker = tracker
	// register the g
	allcgadd(getg())
	return sg, buff
}

//go:nosplit
func (u *uledger) ReleaseUnsafeSudog(sg *sudog, size uint16) {
	if sg.id != -1 && !isEnclave {
		throw("Error in ReleaseUnsafeSudog")
	}

	//release values
	sge := (*sgentry)(unsafe.Pointer(sg))

	if sge.sbuff != uintptr(size) {
		throw("Error wrong size.")
	}

	if sge.isrcv && sge.orig != nil {
		dst := sge.orig
		typeBitsBulkBarrier(sge.elemtype, uintptr(dst), uintptr(sge.buff), sge.elemtype.size)
		memmove(sge.orig, sge.buff, sge.sbuff)
	} else if sge.isrcv == false && sge.tracker != nil {
		u.FreeAll(sge.tracker)
		goto skipfree
	}
	u.Free(uintptr(sge.buff), sge.sbuff)

skipfree:
	//caching size
	if u.psgsize < _sgcachesize {
		u.psglock.lock()
		u.poolsg.enqueue(sg)
		u.psgsize++
		u.psglock.unlock()
	} else {
		u.Free(uintptr(unsafe.Pointer(sge)), unsafe.Sizeof(sgentry{}))
	}
	// unregister the routine
	allcgremove(getg())
}

func (u *uledger) registerTracker(tracker AllocTracker) {
	if len(tracker) < 2 {
		panic("registering invalid tracker")
	}
	u.sl.lock()
	u.toFree[tracker[1].Src] = tracker
	u.sl.unlock()
}

func (u *uledger) FreeTracker(src uintptr) {
	u.sl.lock()
	v, ok := u.toFree[src]
	if !ok {
		if isSimulation {
			println(src)
		}
		panic("Trying to free a tracker that does not exist")
	}
	delete(u.toFree, src)
	u.sl.unlock()
	u.FreeAll(v)
}

//go:nosplit
//go:nowritebarrier
func (u *uspan) allocate(size uintptr) (uintptr, bool) {
	cbits := size / _uspgranularity
	if size%_uspgranularity != 0 {
		cbits++
	}
	fcount := uintptr(0)
	mask := u.bitmask
	idx := -1
	for i := 0; i < 64 && idx == -1; i, mask = i+1, mask>>1 {
		if (mask & 1) == 0 {
			fcount++
			if fcount == cbits { //we can allocate!
				idx = i - int(cbits) + 1
			}
			continue
		}
		fcount = 0
	}
	if idx == -1 { //failure
		return 0, false
	}
	occupied := uint64(0)
	for i := 0; i < int(cbits); i++ {
		occupied |= 1 << uintptr(idx+i)
	}
	u.bitmask |= occupied
	ptr := u.start + uintptr(idx)*_uspgranularity
	u.freesize -= cbits * _uspgranularity
	return ptr, true
}

//go:nosplit
//go:nowritebarrier
func (u *uspan) deallocate(ptr, size uintptr) (bool, bool) {
	cbits := size / _uspgranularity
	if size%_uspgranularity != 0 {
		cbits++
	}
	idx := (ptr - u.start) / _uspgranularity
	if (ptr-u.start)%_uspgranularity != 0 {
		throw("gosecallocator: assumption was wrong")
	}
	occupied := uint64(0)
	for i := 0; i < int(cbits); i++ {
		occupied |= 1 << (idx + uintptr(i))
	}
	move := false
	if u.bitmask == _uspfull {
		move = true
	}
	if (u.bitmask & occupied) != occupied {
		throw("gosecallocator: mistake computing bitmask or freeing.")
	}
	u.bitmask ^= occupied
	u.freesize += uintptr(cbits * _uspgranularity)
	return move, true
}
