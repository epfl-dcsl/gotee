package runtime

import (
	"runtime/internal/atomic"
	"unsafe"
)

const (
	lffailure  = 5
	lfsize     = 256
	lfempty    = 0
	lffull     = 1
	lfreserved = 2
)

type sguintptr uintptr

//go:nosplit
func (l sguintptr) ptr() *sudog {
	return (*sudog)(unsafe.Pointer(l))
}

//go:nosplit
func (l *sguintptr) set(sg *sudog) {
	*l = sguintptr(unsafe.Pointer(sg))
}

//go:nosplit
//go:nowritebarrier
func setSGNoWB(sg **sudog, new *sudog) {
	(*sguintptr)(unsafe.Pointer(sg)).set(new)
}

type lfqueue struct {
	//does not work, need to be only one array.
	avails [lfsize]uint32
	values [lfsize]sguintptr
	size   uint32
}

//lfget drain as much as possible from the queue.
// We need mutual exclusion among the consumers,
// if locked, do not lock the sched.
func lfqget(q *lfqueue, locked bool) (*sudog, *sudog, int) {
	var drainer [lfsize]sguintptr
	index := 0
	if !locked {
		lock(&sched.lock)
	}
	fsize := int(q.size)
	for i := 0; i < lfsize; i++ {
		if q.avails[i] == lffull {
			drainer[index] = q.values[i] //acquire value.
			index++
			q.avails[i] = lfempty //make it available again
			if index >= fsize {
				break
			}
		}
	}
	atomic.Xadd(&q.size, -int32(index))
	if !locked {
		unlock(&sched.lock)
	}
	//unwind results
	var head *sudog
	var prev *sudog
	size := 0
	for i := 0; i < index; i++ {
		sg := drainer[i].ptr()
		if head == nil {
			head = sg
		}
		if prev != nil {
			prev.schednext.set(sg)
		}
		size++
		prev = sg
		for prev.schednext != 0 {
			prev = prev.schednext.ptr()
			size++
		}
	}
	if size > index {
		println("Had to unwind")
	}

	return head, prev, size
}

func lfqput(q *lfqueue, elem *sudog) {
	failures := 0 // bound the failures
	contention := 0
	for {
		for i := 0; i < lfsize; i++ {
			//test, test_and_set
			if q.avails[i] == lfempty {
				if atomic.Cas(&q.avails[i], lfempty, lfreserved) {
					q.values[i].set(elem)
					q.avails[i] = lffull //make it visible to others
					atomic.Xadd(&q.size, 1)
					return
				}
				contention++
			}
		}
		failures++
		if contention == 0 {
			throw("Queue was full, this was not supposed to happen.")
		}
		if failures > lffailure {
			throw("Failed too many times.")
		}
	}
}
