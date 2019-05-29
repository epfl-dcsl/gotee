package runtime

type slqueue struct {
	m    mutex
	head sguintptr
	tail sguintptr
	size uint64
}

//go:nosplit
//go:nowritebarrier
func slqget(q *slqueue, locked bool) (*sudog, *sudog, int) {
	if !locked {
		MarkNoFutex()
		lock(&q.m)
		MarkFutex()
	}
	head, tail, size := q.head, q.tail, q.size
	q.head, q.tail, q.size = 0, 0, 0
	if !locked {
		unlock(&q.m)
	}
	if size == 1 && head != tail {
		throw("slqueue: head != tail for size 1.")
	}
	return head.ptr(), tail.ptr(), int(size)
}

//go:nosplit
//go:nowritebarrier
func slqput(q *slqueue, elem *sudog) {
	var tail *sudog = elem
	var size uint64 = 1
	for tail.schednext != 0 {
		// Just going through the list to find the tail
		size++
		tail = tail.schednext.ptr()
	}
	if tail == nil {
		throw("slqueue tail is nil...")
	}
	MarkNoFutex()
	lock(&q.m)
	MarkFutex()
	if q.tail == 0 {
		if q.head != 0 || q.size != 0 {
			throw("Malformed slqueue: the head is not nil, but tail is")
		}
		q.head.set(elem)
	} else {
		q.tail.ptr().schednext.set(elem)
	}
	q.tail.set(tail)
	q.size += size
	unlock(&q.m)
}
