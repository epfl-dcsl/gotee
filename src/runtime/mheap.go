// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Page heap.
//
// See malloc.go for overview.

package runtime

import (
	"runtime/internal/atomic"
	"runtime/internal/sys"
	"unsafe"
)

// minPhysPageSize is a lower-bound on the physical page size. The
// true physical page size may be larger than this. In contrast,
// sys.PhysPageSize is an upper-bound on the physical page size.
const minPhysPageSize = 4096

// Main malloc heap.
// The heap itself is the "free[]" and "large" arrays,
// but all the other global data is here too.
//
// mheap must not be heap-allocated because it contains mSpanLists,
// which must not be heap-allocated.
//
//go:notinheap
type mheap struct {
	lock      mutex
	free      [_MaxMHeapList]mSpanList // free lists of given length up to _MaxMHeapList
	freelarge mTreap                   // free treap of length >= _MaxMHeapList
	busy      [_MaxMHeapList]mSpanList // busy lists of large spans of given length
	busylarge mSpanList                // busy lists of large spans length >= _MaxMHeapList
	sweepgen  uint32                   // sweep generation, see comment in mspan
	sweepdone uint32                   // all spans are swept
	sweepers  uint32                   // number of active sweepone calls

	// allspans is a slice of all mspans ever created. Each mspan
	// appears exactly once.
	//
	// The memory for allspans is manually managed and can be
	// reallocated and move as the heap grows.
	//
	// In general, allspans is protected by mheap_.lock, which
	// prevents concurrent access as well as freeing the backing
	// store. Accesses during STW might not hold the lock, but
	// must ensure that allocation cannot happen around the
	// access (since that may free the backing store).
	allspans []*mspan // all spans out there

	// spans is a lookup table to map virtual address page IDs to *mspan.
	// For allocated spans, their pages map to the span itself.
	// For free spans, only the lowest and highest pages map to the span itself.
	// Internal pages map to an arbitrary span.
	// For pages that have never been allocated, spans entries are nil.
	//
	// Modifications are protected by mheap.lock. Reads can be
	// performed without locking, but ONLY from indexes that are
	// known to contain in-use or stack spans. This means there
	// must not be a safe-point between establishing that an
	// address is live and looking it up in the spans array.
	//
	// This is backed by a reserved region of the address space so
	// it can grow without moving. The memory up to len(spans) is
	// mapped. cap(spans) indicates the total reserved memory.
	spans []*mspan

	// sweepSpans contains two mspan stacks: one of swept in-use
	// spans, and one of unswept in-use spans. These two trade
	// roles on each GC cycle. Since the sweepgen increases by 2
	// on each cycle, this means the swept spans are in
	// sweepSpans[sweepgen/2%2] and the unswept spans are in
	// sweepSpans[1-sweepgen/2%2]. Sweeping pops spans from the
	// unswept stack and pushes spans that are still in-use on the
	// swept stack. Likewise, allocating an in-use span pushes it
	// on the swept stack.
	sweepSpans [2]gcSweepBuf

	_ uint32 // align uint64 fields on 32-bit for atomics

	// Proportional sweep
	//
	// These parameters represent a linear function from heap_live
	// to page sweep count. The proportional sweep system works to
	// stay in the black by keeping the current page sweep count
	// above this line at the current heap_live.
	//
	// The line has slope sweepPagesPerByte and passes through a
	// basis point at (sweepHeapLiveBasis, pagesSweptBasis). At
	// any given time, the system is at (memstats.heap_live,
	// pagesSwept) in this space.
	//
	// It's important that the line pass through a point we
	// control rather than simply starting at a (0,0) origin
	// because that lets us adjust sweep pacing at any time while
	// accounting for current progress. If we could only adjust
	// the slope, it would create a discontinuity in debt if any
	// progress has already been made.
	pagesInUse         uint64  // pages of spans in stats _MSpanInUse; R/W with mheap.lock
	pagesSwept         uint64  // pages swept this cycle; updated atomically
	pagesSweptBasis    uint64  // pagesSwept to use as the origin of the sweep ratio; updated atomically
	sweepHeapLiveBasis uint64  // value of heap_live to use as the origin of sweep ratio; written with lock, read without
	sweepPagesPerByte  float64 // proportional sweep ratio; written with lock, read without
	// TODO(austin): pagesInUse should be a uintptr, but the 386
	// compiler can't 8-byte align fields.

	// Malloc stats.
	largealloc  uint64                  // bytes allocated for large objects
	nlargealloc uint64                  // number of large object allocations
	largefree   uint64                  // bytes freed for large objects (>maxsmallsize)
	nlargefree  uint64                  // number of frees for large objects (>maxsmallsize)
	nsmallfree  [_NumSizeClasses]uint64 // number of frees for small objects (<=maxsmallsize)

	// range of addresses we might see in the heap
	bitmap        uintptr // Points to one byte past the end of the bitmap
	bitmap_mapped uintptr

	// The arena_* fields indicate the addresses of the Go heap.
	//
	// The maximum range of the Go heap is
	// [arena_start, arena_start+_MaxMem+1).
	//
	// The range of the current Go heap is
	// [arena_start, arena_used). Parts of this range may not be
	// mapped, but the metadata structures are always mapped for
	// the full range.
	arena_start uintptr
	arena_used  uintptr // Set with setArenaUsed.

	// The heap is grown using a linear allocator that allocates
	// from the block [arena_alloc, arena_end). arena_alloc is
	// often, but *not always* equal to arena_used.
	arena_alloc uintptr
	arena_end   uintptr

	// arena_reserved indicates that the memory [arena_alloc,
	// arena_end) is reserved (e.g., mapped PROT_NONE). If this is
	// false, we have to be careful not to clobber existing
	// mappings here. If this is true, then we own the mapping
	// here and *must* clobber it to use it.
	arena_reserved bool

	_ uint32 // ensure 64-bit alignment

	// central free lists for small size classes.
	// the padding makes sure that the MCentrals are
	// spaced CacheLineSize bytes apart, so that each MCentral.lock
	// gets its own cache line.
	// central is indexed by spanClass.
	central [numSpanClasses]struct {
		mcentral mcentral
		pad      [sys.CacheLineSize - unsafe.Sizeof(mcentral{})%sys.CacheLineSize]byte
	}

	spanalloc             fixalloc // allocator for span*
	cachealloc            fixalloc // allocator for mcache*
	treapalloc            fixalloc // allocator for treapNodes* used by large objects
	specialfinalizeralloc fixalloc // allocator for specialfinalizer*
	specialprofilealloc   fixalloc // allocator for specialprofile*
	speciallock           mutex    // lock for special record allocators.

	unused *specialfinalizer // never set, just here to force the specialfinalizer type into DWARF
}

var mheap_ mheap

// An MSpan is a run of pages.
//
// When a MSpan is in the heap free list, state == MSpanFree
// and heapmap(s->start) == span, heapmap(s->start+s->npages-1) == span.
//
// When a MSpan is allocated, state == MSpanInUse or MSpanManual
// and heapmap(i) == span for all s->start <= i < s->start+s->npages.

// Every MSpan is in one doubly-linked list,
// either one of the MHeap's free lists or one of the
// MCentral's span lists.

// An MSpan representing actual memory has state _MSpanInUse,
// _MSpanManual, or _MSpanFree. Transitions between these states are
// constrained as follows:
//
// * A span may transition from free to in-use or manual during any GC
//   phase.
//
// * During sweeping (gcphase == _GCoff), a span may transition from
//   in-use to free (as a result of sweeping) or manual to free (as a
//   result of stacks being freed).
//
// * During GC (gcphase != _GCoff), a span *must not* transition from
//   manual or in-use to free. Because concurrent GC may read a pointer
//   and then look up its span, the span state must be monotonic.
type mSpanState uint8

const (
	_MSpanDead   mSpanState = iota
	_MSpanInUse             // allocated for garbage collected heap
	_MSpanManual            // allocated for manual management (e.g., stack allocator)
	_MSpanFree
)

// mSpanStateNames are the names of the span states, indexed by
// mSpanState.
var mSpanStateNames = []string{
	"_MSpanDead",
	"_MSpanInUse",
	"_MSpanManual",
	"_MSpanFree",
}

// mSpanList heads a linked list of spans.
//
//go:notinheap
type mSpanList struct {
	first *mspan // first span in list, or nil if none
	last  *mspan // last span in list, or nil if none
}

//go:notinheap
type mspan struct {
	next *mspan     // next span in list, or nil if none
	prev *mspan     // previous span in list, or nil if none
	list *mSpanList // For debugging. TODO: Remove.

	startAddr uintptr // address of first byte of span aka s.base()
	npages    uintptr // number of pages in span

	manualFreeList gclinkptr // list of free objects in _MSpanManual spans

	// freeindex is the slot index between 0 and nelems at which to begin scanning
	// for the next free object in this span.
	// Each allocation scans allocBits starting at freeindex until it encounters a 0
	// indicating a free object. freeindex is then adjusted so that subsequent scans begin
	// just past the newly discovered free object.
	//
	// If freeindex == nelem, this span has no free objects.
	//
	// allocBits is a bitmap of objects in this span.
	// If n >= freeindex and allocBits[n/8] & (1<<(n%8)) is 0
	// then object n is free;
	// otherwise, object n is allocated. Bits starting at nelem are
	// undefined and should never be referenced.
	//
	// Object n starts at address n*elemsize + (start << pageShift).
	freeindex uintptr
	// TODO: Look up nelems from sizeclass and remove this field if it
	// helps performance.
	nelems uintptr // number of object in the span.

	// Cache of the allocBits at freeindex. allocCache is shifted
	// such that the lowest bit corresponds to the bit freeindex.
	// allocCache holds the complement of allocBits, thus allowing
	// ctz (count trailing zero) to use it directly.
	// allocCache may contain bits beyond s.nelems; the caller must ignore
	// these.
	allocCache uint64

	// allocBits and gcmarkBits hold pointers to a span's mark and
	// allocation bits. The pointers are 8 byte aligned.
	// There are three arenas where this data is held.
	// free: Dirty arenas that are no longer accessed
	//       and can be reused.
	// next: Holds information to be used in the next GC cycle.
	// current: Information being used during this GC cycle.
	// previous: Information being used during the last GC cycle.
	// A new GC cycle starts with the call to finishsweep_m.
	// finishsweep_m moves the previous arena to the free arena,
	// the current arena to the previous arena, and
	// the next arena to the current arena.
	// The next arena is populated as the spans request
	// memory to hold gcmarkBits for the next GC cycle as well
	// as allocBits for newly allocated spans.
	//
	// The pointer arithmetic is done "by hand" instead of using
	// arrays to avoid bounds checks along critical performance
	// paths.
	// The sweep will free the old allocBits and set allocBits to the
	// gcmarkBits. The gcmarkBits are replaced with a fresh zeroed
	// out memory.
	allocBits  *gcBits
	gcmarkBits *gcBits

	// sweep generation:
	// if sweepgen == h->sweepgen - 2, the span needs sweeping
	// if sweepgen == h->sweepgen - 1, the span is currently being swept
	// if sweepgen == h->sweepgen, the span is swept and ready to use
	// h->sweepgen is incremented by 2 after every GC

	sweepgen    uint32
	divMul      uint16     // for divide by elemsize - divMagic.mul
	baseMask    uint16     // if non-0, elemsize is a power of 2, & this will get object allocation base
	allocCount  uint16     // number of allocated objects
	spanclass   spanClass  // size class and noscan (uint8)
	incache     bool       // being used by an mcache
	state       mSpanState // mspaninuse etc
	needzero    uint8      // needs to be zeroed before allocation
	divShift    uint8      // for divide by elemsize - divMagic.shift
	divShift2   uint8      // for divide by elemsize - divMagic.shift2
	elemsize    uintptr    // computed from sizeclass or from npages
	unusedsince int64      // first time spotted by gc in mspanfree state
	npreleased  uintptr    // number of pages released to the os
	limit       uintptr    // end of data in span
	speciallock mutex      // guards specials list
	specials    *special   // linked list of special records sorted by offset.
}

func (s *mspan) base() uintptr {
	return s.startAddr
}

func (s *mspan) layout() (size, n, total uintptr) {
	total = s.npages << _PageShift
	size = s.elemsize
	if size > 0 {
		n = total / size
	}
	return
}

// recordspan adds a newly allocated span to h.allspans.
//
// This only happens the first time a span is allocated from
// mheap.spanalloc (it is not called when a span is reused).
//
// Write barriers are disallowed here because it can be called from
// gcWork when allocating new workbufs. However, because it's an
// indirect call from the fixalloc initializer, the compiler can't see
// this.
//
//go:nowritebarrierrec
func recordspan(vh unsafe.Pointer, p unsafe.Pointer) {
	h := (*mheap)(vh)
	s := (*mspan)(p)
	if len(h.allspans) >= cap(h.allspans) {
		n := 64 * 1024 / sys.PtrSize
		if n < cap(h.allspans)*3/2 {
			n = cap(h.allspans) * 3 / 2
		}
		var new []*mspan
		sp := (*slice)(unsafe.Pointer(&new))
		sp.array = sysAlloc(uintptr(n)*sys.PtrSize, &memstats.other_sys)
		if sp.array == nil {
			throw("runtime: cannot allocate memory")
		}
		sp.len = len(h.allspans)
		sp.cap = n
		if len(h.allspans) > 0 {
			copy(new, h.allspans)
		}
		oldAllspans := h.allspans
		*(*notInHeapSlice)(unsafe.Pointer(&h.allspans)) = *(*notInHeapSlice)(unsafe.Pointer(&new))
		if len(oldAllspans) != 0 {
			//TODO aghosn handle that better.
			sysFree(unsafe.Pointer(&oldAllspans[0]), uintptr(cap(oldAllspans))*unsafe.Sizeof(oldAllspans[0]), &memstats.other_sys)
		}
	}
	h.allspans = h.allspans[:len(h.allspans)+1]
	h.allspans[len(h.allspans)-1] = s
}

// A spanClass represents the size class and noscan-ness of a span.
//
// Each size class has a noscan spanClass and a scan spanClass. The
// noscan spanClass contains only noscan objects, which do not contain
// pointers and thus do not need to be scanned by the garbage
// collector.
type spanClass uint8

const (
	numSpanClasses = _NumSizeClasses << 1
	tinySpanClass  = spanClass(tinySizeClass<<1 | 1)
)

func makeSpanClass(sizeclass uint8, noscan bool) spanClass {
	return spanClass(sizeclass<<1) | spanClass(bool2int(noscan))
}

func (sc spanClass) sizeclass() int8 {
	return int8(sc >> 1)
}

func (sc spanClass) noscan() bool {
	return sc&1 != 0
}

// inheap reports whether b is a pointer into a (potentially dead) heap object.
// It returns false for pointers into _MSpanManual spans.
// Non-preemptible because it is used by write barriers.
//go:nowritebarrier
//go:nosplit
func inheap(b uintptr) bool {
	if b == 0 || b < mheap_.arena_start || b >= mheap_.arena_used {
		return false
	}
	// Not a beginning of a block, consult span table to find the block beginning.
	s := mheap_.spans[(b-mheap_.arena_start)>>_PageShift]
	if s == nil || b < s.base() || b >= s.limit || s.state != mSpanInUse {
		return false
	}
	return true
}

// inHeapOrStack is a variant of inheap that returns true for pointers
// into any allocated heap span.
//
//go:nowritebarrier
//go:nosplit
func inHeapOrStack(b uintptr) bool {
	if b == 0 || b < mheap_.arena_start || b >= mheap_.arena_used {
		return false
	}
	// Not a beginning of a block, consult span table to find the block beginning.
	s := mheap_.spans[(b-mheap_.arena_start)>>_PageShift]
	if s == nil || b < s.base() {
		return false
	}
	switch s.state {
	case mSpanInUse, _MSpanManual:
		return b < s.limit
	default:
		return false
	}
}

// TODO: spanOf and spanOfUnchecked are open-coded in a lot of places.
// Use the functions instead.

// spanOf returns the span of p. If p does not point into the heap or
// no span contains p, spanOf returns nil.
func spanOf(p uintptr) *mspan {
	if p == 0 || p < mheap_.arena_start || p >= mheap_.arena_used {
		return nil
	}
	return spanOfUnchecked(p)
}

// spanOfUnchecked is equivalent to spanOf, but the caller must ensure
// that p points into the heap (that is, mheap_.arena_start <= p <
// mheap_.arena_used).
func spanOfUnchecked(p uintptr) *mspan {
	return mheap_.spans[(p-mheap_.arena_start)>>_PageShift]
}

func mlookup(v uintptr, base *uintptr, size *uintptr, sp **mspan) int32 {
	_g_ := getg()

	_g_.m.mcache.local_nlookup++
	if sys.PtrSize == 4 && _g_.m.mcache.local_nlookup >= 1<<30 {
		// purge cache stats to prevent overflow
		lock(&mheap_.lock)
		purgecachedstats(_g_.m.mcache)
		unlock(&mheap_.lock)
	}

	s := mheap_.lookupMaybe(unsafe.Pointer(v))
	if sp != nil {
		*sp = s
	}
	if s == nil {
		if base != nil {
			*base = 0
		}
		if size != nil {
			*size = 0
		}
		return 0
	}

	p := s.base()
	if s.spanclass.sizeclass() == 0 {
		// Large object.
		if base != nil {
			*base = p
		}
		if size != nil {
			*size = s.npages << _PageShift
		}
		return 1
	}

	n := s.elemsize
	if base != nil {
		i := (v - p) / n
		*base = p + i*n
	}
	if size != nil {
		*size = n
	}

	return 1
}

// Initialize the heap. (TODO(aghosn) here I had a problem with the unlocked)
func (h *mheap) init(spansStart, spansBytes uintptr) {
	h.treapalloc.init(unsafe.Sizeof(treapNode{}), nil, nil, &memstats.other_sys)
	h.spanalloc.init(unsafe.Sizeof(mspan{}), recordspan, unsafe.Pointer(h), &memstats.mspan_sys)
	h.cachealloc.init(unsafe.Sizeof(mcache{}), nil, nil, &memstats.mcache_sys)
	h.specialfinalizeralloc.init(unsafe.Sizeof(specialfinalizer{}), nil, nil, &memstats.other_sys)
	h.specialprofilealloc.init(unsafe.Sizeof(specialprofile{}), nil, nil, &memstats.other_sys)

	// Don't zero mspan allocations. Background sweeping can
	// inspect a span concurrently with allocating it, so it's
	// important that the span's sweepgen survive across freeing
	// and re-allocating a span to prevent background sweeping
	// from improperly cas'ing it from 0.
	//
	// This is safe because mspan contains no heap pointers.
	h.spanalloc.zero = false

	// h->mapcache needs no init
	for i := range h.free {
		h.free[i].init()
		h.busy[i].init()
	}

	h.busylarge.init()
	for i := range h.central {
		h.central[i].mcentral.init(spanClass(i))
	}

	sp := (*slice)(unsafe.Pointer(&h.spans))
	sp.array = unsafe.Pointer(spansStart)
	sp.len = 0
	sp.cap = int(spansBytes / sys.PtrSize)

	// Map metadata structures. But don't map race detector memory
	// since we're not actually growing the arena here (and TSAN
	// gets mad if you map 0 bytes).
	h.setArenaUsed(h.arena_used, false)
}

// setArenaUsed extends the usable arena to address arena_used and
// maps auxiliary VM regions for any newly usable arena space.
//
// racemap indicates that this memory should be managed by the race
// detector. racemap should be true unless this is covering a VM hole.
func (h *mheap) setArenaUsed(arena_used uintptr, racemap bool) {
	// Map auxiliary structures *before* h.arena_used is updated.
	// Waiting to update arena_used until after the memory has been mapped
	// avoids faults when other threads try access these regions immediately
	// after observing the change to arena_used.

	// Map the bitmap.
	h.mapBits(arena_used)

	// Map spans array.
	h.mapSpans(arena_used)

	// Tell the race detector about the new heap memory.
	if racemap && raceenabled {
		racemapshadow(unsafe.Pointer(h.arena_used), arena_used-h.arena_used)
	}

	h.arena_used = arena_used
}

// mapSpans makes sure that the spans are mapped
// up to the new value of arena_used.
//
// Don't call this directly. Call mheap.setArenaUsed.
func (h *mheap) mapSpans(arena_used uintptr) {
	// Map spans array, PageSize at a time.
	n := arena_used
	n -= h.arena_start
	n = n / _PageSize * sys.PtrSize
	n = round(n, physPageSize)
	need := n / unsafe.Sizeof(h.spans[0])
	have := uintptr(len(h.spans))
	if have >= need {
		return
	}
	h.spans = h.spans[:need]
	sysMap(unsafe.Pointer(&h.spans[have]), (need-have)*unsafe.Sizeof(h.spans[0]), h.arena_reserved, &memstats.other_sys)
}

// Sweeps spans in list until reclaims at least npages into heap.
// Returns the actual number of pages reclaimed.
func (h *mheap) reclaimList(list *mSpanList, npages uintptr) uintptr {
	n := uintptr(0)
	sg := mheap_.sweepgen
retry:
	for s := list.first; s != nil; s = s.next {
		if s.sweepgen == sg-2 && atomic.Cas(&s.sweepgen, sg-2, sg-1) {
			list.remove(s)
			// swept spans are at the end of the list
			list.insertBack(s) // Puts it back on a busy list. s is not in the treap at this point.
			unlock(&h.lock)
			snpages := s.npages
			if s.sweep(false) {
				n += snpages
			}
			lock(&h.lock)
			if n >= npages {
				return n
			}
			// the span could have been moved elsewhere
			goto retry
		}
		if s.sweepgen == sg-1 {
			// the span is being sweept by background sweeper, skip
			continue
		}
		// already swept empty span,
		// all subsequent ones must also be either swept or in process of sweeping
		break
	}
	return n
}

// Sweeps and reclaims at least npage pages into heap.
// Called before allocating npage pages.
func (h *mheap) reclaim(npage uintptr) {
	// First try to sweep busy spans with large objects of size >= npage,
	// this has good chances of reclaiming the necessary space.
	for i := int(npage); i < len(h.busy); i++ {
		if h.reclaimList(&h.busy[i], npage) != 0 {
			return // Bingo!
		}
	}

	// Then -- even larger objects.
	if h.reclaimList(&h.busylarge, npage) != 0 {
		return // Bingo!
	}

	// Now try smaller objects.
	// One such object is not enough, so we need to reclaim several of them.
	reclaimed := uintptr(0)
	for i := 0; i < int(npage) && i < len(h.busy); i++ {
		reclaimed += h.reclaimList(&h.busy[i], npage-reclaimed)
		if reclaimed >= npage {
			return
		}
	}

	// Now sweep everything that is not yet swept.
	unlock(&h.lock)
	for {
		n := sweepone()
		if n == ^uintptr(0) { // all spans are swept
			break
		}
		reclaimed += n
		if reclaimed >= npage {
			break
		}
	}
	lock(&h.lock)
}

// Allocate a new span of npage pages from the heap for GC'd memory
// and record its size class in the HeapMap and HeapMapCache.
func (h *mheap) alloc_m(npage uintptr, spanclass spanClass, large bool) *mspan {
	_g_ := getg()
	if _g_ != _g_.m.g0 {
		throw("_mheap_alloc not on g0 stack")
	}
	lock(&h.lock)

	// To prevent excessive heap growth, before allocating n pages
	// we need to sweep and reclaim at least n pages.
	if h.sweepdone == 0 {
		// TODO(austin): This tends to sweep a large number of
		// spans in order to find a few completely free spans
		// (for example, in the garbage benchmark, this sweeps
		// ~30x the number of pages its trying to allocate).
		// If GC kept a bit for whether there were any marks
		// in a span, we could release these free spans
		// at the end of GC and eliminate this entirely.
		if trace.enabled {
			traceGCSweepStart()
		}
		h.reclaim(npage)
		if trace.enabled {
			traceGCSweepDone()
		}
	}

	// transfer stats from cache to global
	memstats.heap_scan += uint64(_g_.m.mcache.local_scan)
	_g_.m.mcache.local_scan = 0
	memstats.tinyallocs += uint64(_g_.m.mcache.local_tinyallocs)
	_g_.m.mcache.local_tinyallocs = 0

	s := h.allocSpanLocked(npage, &memstats.heap_inuse)
	if s != nil {
		// Record span info, because gc needs to be
		// able to map interior pointer to containing span.
		atomic.Store(&s.sweepgen, h.sweepgen)
		h.sweepSpans[h.sweepgen/2%2].push(s) // Add to swept in-use list.
		s.state = _MSpanInUse
		s.allocCount = 0
		s.spanclass = spanclass
		if sizeclass := spanclass.sizeclass(); sizeclass == 0 {
			s.elemsize = s.npages << _PageShift
			s.divShift = 0
			s.divMul = 0
			s.divShift2 = 0
			s.baseMask = 0
		} else {
			s.elemsize = uintptr(class_to_size[sizeclass])
			m := &class_to_divmagic[sizeclass]
			s.divShift = m.shift
			s.divMul = m.mul
			s.divShift2 = m.shift2
			s.baseMask = m.baseMask
		}

		// update stats, sweep lists
		h.pagesInUse += uint64(npage)
		if large {
			memstats.heap_objects++
			mheap_.largealloc += uint64(s.elemsize)
			mheap_.nlargealloc++
			atomic.Xadd64(&memstats.heap_live, int64(npage<<_PageShift))
			// Swept spans are at the end of lists.
			if s.npages < uintptr(len(h.busy)) {
				h.busy[s.npages].insertBack(s)
			} else {
				h.busylarge.insertBack(s)
			}
		}
	}
	// heap_scan and heap_live were updated.
	if gcBlackenEnabled != 0 {
		gcController.revise()
	}

	if trace.enabled {
		traceHeapAlloc()
	}

	// h.spans is accessed concurrently without synchronization
	// from other threads. Hence, there must be a store/store
	// barrier here to ensure the writes to h.spans above happen
	// before the caller can publish a pointer p to an object
	// allocated from s. As soon as this happens, the garbage
	// collector running on another processor could read p and
	// look up s in h.spans. The unlock acts as the barrier to
	// order these writes. On the read side, the data dependency
	// between p and the index in h.spans orders the reads.
	unlock(&h.lock)
	return s
}

func (h *mheap) alloc(npage uintptr, spanclass spanClass, large bool, needzero bool) *mspan {
	// Don't do any operations that lock the heap on the G stack.
	// It might trigger stack growth, and the stack growth code needs
	// to be able to allocate heap.
	var s *mspan
	systemstack(func() {
		s = h.alloc_m(npage, spanclass, large)
	})

	if s != nil {
		if needzero && s.needzero != 0 {
			memclrNoHeapPointers(unsafe.Pointer(s.base()), s.npages<<_PageShift)
		}
		s.needzero = 0
	}
	return s
}

// allocManual allocates a manually-managed span of npage pages.
// allocManual returns nil if allocation fails.
//
// allocManual adds the bytes used to *stat, which should be a
// memstats in-use field. Unlike allocations in the GC'd heap, the
// allocation does *not* count toward heap_inuse or heap_sys.
//
// The memory backing the returned span may not be zeroed if
// span.needzero is set.
//
// allocManual must be called on the system stack to prevent stack
// growth. Since this is used by the stack allocator, stack growth
// during allocManual would self-deadlock.
//
//go:systemstack
func (h *mheap) allocManual(npage uintptr, stat *uint64) *mspan {
	lock(&h.lock)
	s := h.allocSpanLocked(npage, stat)
	if s != nil {
		s.state = _MSpanManual
		s.manualFreeList = 0
		s.allocCount = 0
		s.spanclass = 0
		s.nelems = 0
		s.elemsize = 0
		s.limit = s.base() + s.npages<<_PageShift
		// Manually manged memory doesn't count toward heap_sys.
		memstats.heap_sys -= uint64(s.npages << _PageShift)
	}

	// This unlock acts as a release barrier. See mheap.alloc_m.
	unlock(&h.lock)

	return s
}

// Allocates a span of the given size.  h must be locked.
// The returned span has been removed from the
// free list, but its state is still MSpanFree.
func (h *mheap) allocSpanLocked(npage uintptr, stat *uint64) *mspan {
	var list *mSpanList
	var s *mspan

	// Try in fixed-size lists up to max.
	for i := int(npage); i < len(h.free); i++ {
		list = &h.free[i]
		if !list.isEmpty() {
			s = list.first
			list.remove(s)
			goto HaveSpan
		}
	}
	// Best fit in list of large spans.
	s = h.allocLarge(npage) // allocLarge removed s from h.freelarge for us
	if s == nil {
		if !h.grow(npage) {
			return nil
		}
		s = h.allocLarge(npage)
		if s == nil {
			return nil
		}
	}

HaveSpan:
	// Mark span in use.
	if s.state != _MSpanFree {
		throw("MHeap_AllocLocked - MSpan not free")
	}
	if s.npages < npage {
		throw("MHeap_AllocLocked - bad npages")
	}
	if s.npreleased > 0 {
		sysUsed(unsafe.Pointer(s.base()), s.npages<<_PageShift)
		memstats.heap_released -= uint64(s.npreleased << _PageShift)
		s.npreleased = 0
	}

	if s.npages > npage {
		// Trim extra and put it back in the heap.
		t := (*mspan)(h.spanalloc.alloc())
		t.init(s.base()+npage<<_PageShift, s.npages-npage)
		s.npages = npage
		p := (t.base() - h.arena_start) >> _PageShift
		if p > 0 {
			h.spans[p-1] = s
		}
		h.spans[p] = t
		h.spans[p+t.npages-1] = t
		t.needzero = s.needzero
		s.state = _MSpanManual // prevent coalescing with s
		t.state = _MSpanManual
		h.freeSpanLocked(t, false, false, s.unusedsince)
		s.state = _MSpanFree
	}
	s.unusedsince = 0

	p := (s.base() - h.arena_start) >> _PageShift
	for n := uintptr(0); n < npage; n++ {
		h.spans[p+n] = s
	}

	*stat += uint64(npage << _PageShift)
	memstats.heap_idle -= uint64(npage << _PageShift)

	//println("spanalloc", hex(s.start<<_PageShift))
	if s.inList() {
		throw("still in list")
	}
	return s
}

// Large spans have a minimum size of 1MByte. The maximum number of large spans to support
// 1TBytes is 1 million, experimentation using random sizes indicates that the depth of
// the tree is less that 2x that of a perfectly balanced tree. For 1TByte can be referenced
// by a perfectly balanced tree with a depth of 20. Twice that is an acceptable 40.
func (h *mheap) isLargeSpan(npages uintptr) bool {
	return npages >= uintptr(len(h.free))
}

// allocLarge allocates a span of at least npage pages from the treap of large spans.
// Returns nil if no such span currently exists.
func (h *mheap) allocLarge(npage uintptr) *mspan {
	// Search treap for smallest span with >= npage pages.
	return h.freelarge.remove(npage)
}

// Try to add at least npage pages of memory to the heap,
// returning whether it worked.
//
// h must be locked.
func (h *mheap) grow(npage uintptr) bool {
	// Ask for a big chunk, to reduce the number of mappings
	// the operating system needs to track; also amortizes
	// the overhead of an operating system mapping.
	// Allocate a multiple of 64kB.
	npage = round(npage, (64<<10)/_PageSize)
	ask := npage << _PageShift
	if ask < _HeapAllocChunk {
		ask = _HeapAllocChunk
	}

	v := h.sysAlloc(ask)
	if v == nil {
		if ask > npage<<_PageShift {
			ask = npage << _PageShift
			v = h.sysAlloc(ask)
		}
		if v == nil {
			print("runtime: out of memory: cannot allocate ", ask, "-byte block (", memstats.heap_sys, " in use)\n")
			return false
		}
	}

	// Create a fake "in use" span and free it, so that the
	// right coalescing happens.
	s := (*mspan)(h.spanalloc.alloc())
	s.init(uintptr(v), ask>>_PageShift)
	p := (s.base() - h.arena_start) >> _PageShift
	for i := p; i < p+s.npages; i++ {
		h.spans[i] = s
	}
	atomic.Store(&s.sweepgen, h.sweepgen)
	s.state = _MSpanInUse
	h.pagesInUse += uint64(s.npages)
	h.freeSpanLocked(s, false, true, 0)
	return true
}

// Look up the span at the given address.
// Address is guaranteed to be in map
// and is guaranteed to be start or end of span.
func (h *mheap) lookup(v unsafe.Pointer) *mspan {
	p := uintptr(v)
	p -= h.arena_start
	return h.spans[p>>_PageShift]
}

// Look up the span at the given address.
// Address is *not* guaranteed to be in map
// and may be anywhere in the span.
// Map entries for the middle of a span are only
// valid for allocated spans. Free spans may have
// other garbage in their middles, so we have to
// check for that.
func (h *mheap) lookupMaybe(v unsafe.Pointer) *mspan {
	if uintptr(v) < h.arena_start || uintptr(v) >= h.arena_used {
		return nil
	}
	s := h.spans[(uintptr(v)-h.arena_start)>>_PageShift]
	if s == nil || uintptr(v) < s.base() || uintptr(v) >= uintptr(unsafe.Pointer(s.limit)) || s.state != _MSpanInUse {
		return nil
	}
	return s
}

// Free the span back into the heap.
func (h *mheap) freeSpan(s *mspan, acct int32) {
	systemstack(func() {
		mp := getg().m
		lock(&h.lock)
		memstats.heap_scan += uint64(mp.mcache.local_scan)
		mp.mcache.local_scan = 0
		memstats.tinyallocs += uint64(mp.mcache.local_tinyallocs)
		mp.mcache.local_tinyallocs = 0
		if msanenabled {
			// Tell msan that this entire span is no longer in use.
			base := unsafe.Pointer(s.base())
			bytes := s.npages << _PageShift
			msanfree(base, bytes)
		}
		if acct != 0 {
			memstats.heap_objects--
		}
		if gcBlackenEnabled != 0 {
			// heap_scan changed.
			gcController.revise()
		}
		h.freeSpanLocked(s, true, true, 0)
		unlock(&h.lock)
	})
}

// freeManual frees a manually-managed span returned by allocManual.
// stat must be the same as the stat passed to the allocManual that
// allocated s.
//
// This must only be called when gcphase == _GCoff. See mSpanState for
// an explanation.
//
// freeManual must be called on the system stack to prevent stack
// growth, just like allocManual.
//
//go:systemstack
func (h *mheap) freeManual(s *mspan, stat *uint64) {
	s.needzero = 1
	lock(&h.lock)
	*stat -= uint64(s.npages << _PageShift)
	memstats.heap_sys += uint64(s.npages << _PageShift)
	h.freeSpanLocked(s, false, true, 0)
	unlock(&h.lock)
}

// s must be on a busy list (h.busy or h.busylarge) or unlinked.
func (h *mheap) freeSpanLocked(s *mspan, acctinuse, acctidle bool, unusedsince int64) {
	switch s.state {
	case _MSpanManual:
		if s.allocCount != 0 {
			throw("MHeap_FreeSpanLocked - invalid stack free")
		}
	case _MSpanInUse:
		if s.allocCount != 0 || s.sweepgen != h.sweepgen {
			print("MHeap_FreeSpanLocked - span ", s, " ptr ", hex(s.base()), " allocCount ", s.allocCount, " sweepgen ", s.sweepgen, "/", h.sweepgen, "\n")
			throw("MHeap_FreeSpanLocked - invalid free")
		}
		h.pagesInUse -= uint64(s.npages)
	default:
		throw("MHeap_FreeSpanLocked - invalid span state")
	}

	if acctinuse {
		memstats.heap_inuse -= uint64(s.npages << _PageShift)
	}
	if acctidle {
		memstats.heap_idle += uint64(s.npages << _PageShift)
	}
	s.state = _MSpanFree
	if s.inList() {
		h.busyList(s.npages).remove(s)
	}

	// Stamp newly unused spans. The scavenger will use that
	// info to potentially give back some pages to the OS.
	s.unusedsince = unusedsince
	if unusedsince == 0 {
		s.unusedsince = nanotime()
	}
	s.npreleased = 0

	// Coalesce with earlier, later spans.
	p := (s.base() - h.arena_start) >> _PageShift
	if p > 0 {
		before := h.spans[p-1]
		if before != nil && before.state == _MSpanFree {
			// Now adjust s.
			s.startAddr = before.startAddr
			s.npages += before.npages
			s.npreleased = before.npreleased // absorb released pages
			s.needzero |= before.needzero
			p -= before.npages
			h.spans[p] = s
			// The size is potentially changing so the treap needs to delete adjacent nodes and
			// insert back as a combined node.
			if h.isLargeSpan(before.npages) {
				// We have a t, it is large so it has to be in the treap so we can remove it.
				h.freelarge.removeSpan(before)
			} else {
				h.freeList(before.npages).remove(before)
			}
			before.state = _MSpanDead
			h.spanalloc.free(unsafe.Pointer(before))
		}
	}

	// Now check to see if next (greater addresses) span is free and can be coalesced.
	if (p + s.npages) < uintptr(len(h.spans)) {
		after := h.spans[p+s.npages]
		if after != nil && after.state == _MSpanFree {
			s.npages += after.npages
			s.npreleased += after.npreleased
			s.needzero |= after.needzero
			h.spans[p+s.npages-1] = s
			if h.isLargeSpan(after.npages) {
				h.freelarge.removeSpan(after)
			} else {
				h.freeList(after.npages).remove(after)
			}
			after.state = _MSpanDead
			h.spanalloc.free(unsafe.Pointer(after))
		}
	}

	// Insert s into appropriate list or treap.
	if h.isLargeSpan(s.npages) {
		h.freelarge.insert(s)
	} else {
		h.freeList(s.npages).insert(s)
	}
}

func (h *mheap) freeList(npages uintptr) *mSpanList {
	return &h.free[npages]
}

func (h *mheap) busyList(npages uintptr) *mSpanList {
	if npages < uintptr(len(h.busy)) {
		return &h.busy[npages]
	}
	return &h.busylarge
}

func scavengeTreapNode(t *treapNode, now, limit uint64) uintptr {
	s := t.spanKey
	var sumreleased uintptr
	if (now-uint64(s.unusedsince)) > limit && s.npreleased != s.npages {
		start := s.base()
		end := start + s.npages<<_PageShift
		if physPageSize > _PageSize {
			// We can only release pages in
			// physPageSize blocks, so round start
			// and end in. (Otherwise, madvise
			// will round them *out* and release
			// more memory than we want.)
			start = (start + physPageSize - 1) &^ (physPageSize - 1)
			end &^= physPageSize - 1
			if end <= start {
				// start and end don't span a
				// whole physical page.
				return sumreleased
			}
		}
		len := end - start
		released := len - (s.npreleased << _PageShift)
		if physPageSize > _PageSize && released == 0 {
			return sumreleased
		}
		memstats.heap_released += uint64(released)
		sumreleased += released
		s.npreleased = len >> _PageShift
		sysUnused(unsafe.Pointer(start), len)
	}
	return sumreleased
}

func scavengelist(list *mSpanList, now, limit uint64) uintptr {
	if list.isEmpty() {
		return 0
	}

	var sumreleased uintptr
	for s := list.first; s != nil; s = s.next {
		if (now-uint64(s.unusedsince)) <= limit || s.npreleased == s.npages {
			continue
		}
		start := s.base()
		end := start + s.npages<<_PageShift
		if physPageSize > _PageSize {
			// We can only release pages in
			// physPageSize blocks, so round start
			// and end in. (Otherwise, madvise
			// will round them *out* and release
			// more memory than we want.)
			start = (start + physPageSize - 1) &^ (physPageSize - 1)
			end &^= physPageSize - 1
			if end <= start {
				// start and end don't span a
				// whole physical page.
				continue
			}
		}
		len := end - start

		released := len - (s.npreleased << _PageShift)
		if physPageSize > _PageSize && released == 0 {
			continue
		}
		memstats.heap_released += uint64(released)
		sumreleased += released
		s.npreleased = len >> _PageShift
		sysUnused(unsafe.Pointer(start), len)
	}
	return sumreleased
}

func (h *mheap) scavenge(k int32, now, limit uint64) {
	// Disallow malloc or panic while holding the heap lock. We do
	// this here because this is an non-mallocgc entry-point to
	// the mheap API.
	gp := getg()
	gp.m.mallocing++
	lock(&h.lock)
	var sumreleased uintptr
	for i := 0; i < len(h.free); i++ {
		sumreleased += scavengelist(&h.free[i], now, limit)
	}
	sumreleased += scavengetreap(h.freelarge.treap, now, limit)
	unlock(&h.lock)
	gp.m.mallocing--

	if debug.gctrace > 0 {
		if sumreleased > 0 {
			print("scvg", k, ": ", sumreleased>>20, " MB released\n")
		}
		print("scvg", k, ": inuse: ", memstats.heap_inuse>>20, ", idle: ", memstats.heap_idle>>20, ", sys: ", memstats.heap_sys>>20, ", released: ", memstats.heap_released>>20, ", consumed: ", (memstats.heap_sys-memstats.heap_released)>>20, " (MB)\n")
	}
}

//go:linkname runtime_debug_freeOSMemory runtime/debug.freeOSMemory
func runtime_debug_freeOSMemory() {
	GC()
	systemstack(func() { mheap_.scavenge(-1, ^uint64(0), 0) })
}

// Initialize a new span with the given start and npages.
func (span *mspan) init(base uintptr, npages uintptr) {
	// span is *not* zeroed.
	span.next = nil
	span.prev = nil
	span.list = nil
	span.startAddr = base
	span.npages = npages
	span.allocCount = 0
	span.spanclass = 0
	span.incache = false
	span.elemsize = 0
	span.state = _MSpanDead
	span.unusedsince = 0
	span.npreleased = 0
	span.speciallock.key = 0
	span.specials = nil
	span.needzero = 0
	span.freeindex = 0
	span.allocBits = nil
	span.gcmarkBits = nil
}

func (span *mspan) inList() bool {
	return span.list != nil
}

// Initialize an empty doubly-linked list.
func (list *mSpanList) init() {
	list.first = nil
	list.last = nil
}

func (list *mSpanList) remove(span *mspan) {
	if span.list != list {
		print("runtime: failed MSpanList_Remove span.npages=", span.npages,
			" span=", span, " prev=", span.prev, " span.list=", span.list, " list=", list, "\n")
		throw("MSpanList_Remove")
	}
	if list.first == span {
		list.first = span.next
	} else {
		span.prev.next = span.next
	}
	if list.last == span {
		list.last = span.prev
	} else {
		span.next.prev = span.prev
	}
	span.next = nil
	span.prev = nil
	span.list = nil
}

func (list *mSpanList) isEmpty() bool {
	return list.first == nil
}

func (list *mSpanList) insert(span *mspan) {
	if span.next != nil || span.prev != nil || span.list != nil {
		println("runtime: failed MSpanList_Insert", span, span.next, span.prev, span.list)
		throw("MSpanList_Insert")
	}
	span.next = list.first
	if list.first != nil {
		// The list contains at least one span; link it in.
		// The last span in the list doesn't change.
		list.first.prev = span
	} else {
		// The list contains no spans, so this is also the last span.
		list.last = span
	}
	list.first = span
	span.list = list
}

func (list *mSpanList) insertBack(span *mspan) {
	if span.next != nil || span.prev != nil || span.list != nil {
		println("runtime: failed MSpanList_InsertBack", span, span.next, span.prev, span.list)
		throw("MSpanList_InsertBack")
	}
	span.prev = list.last
	if list.last != nil {
		// The list contains at least one span.
		list.last.next = span
	} else {
		// The list contains no spans, so this is also the first span.
		list.first = span
	}
	list.last = span
	span.list = list
}

// takeAll removes all spans from other and inserts them at the front
// of list.
func (list *mSpanList) takeAll(other *mSpanList) {
	if other.isEmpty() {
		return
	}

	// Reparent everything in other to list.
	for s := other.first; s != nil; s = s.next {
		s.list = list
	}

	// Concatenate the lists.
	if list.isEmpty() {
		*list = *other
	} else {
		// Neither list is empty. Put other before list.
		other.last.next = list.first
		list.first.prev = other.last
		list.first = other.first
	}

	other.first, other.last = nil, nil
}

const (
	_KindSpecialFinalizer = 1
	_KindSpecialProfile   = 2
	// Note: The finalizer special must be first because if we're freeing
	// an object, a finalizer special will cause the freeing operation
	// to abort, and we want to keep the other special records around
	// if that happens.
)

//go:notinheap
type special struct {
	next   *special // linked list in span
	offset uint16   // span offset of object
	kind   byte     // kind of special
}

// Adds the special record s to the list of special records for
// the object p. All fields of s should be filled in except for
// offset & next, which this routine will fill in.
// Returns true if the special was successfully added, false otherwise.
// (The add will fail only if a record with the same p and s->kind
//  already exists.)
func addspecial(p unsafe.Pointer, s *special) bool {
	span := mheap_.lookupMaybe(p)
	if span == nil {
		throw("addspecial on invalid pointer")
	}

	// Ensure that the span is swept.
	// Sweeping accesses the specials list w/o locks, so we have
	// to synchronize with it. And it's just much safer.
	mp := acquirem()
	span.ensureSwept()

	offset := uintptr(p) - span.base()
	kind := s.kind

	lock(&span.speciallock)

	// Find splice point, check for existing record.
	t := &span.specials
	for {
		x := *t
		if x == nil {
			break
		}
		if offset == uintptr(x.offset) && kind == x.kind {
			unlock(&span.speciallock)
			releasem(mp)
			return false // already exists
		}
		if offset < uintptr(x.offset) || (offset == uintptr(x.offset) && kind < x.kind) {
			break
		}
		t = &x.next
	}

	// Splice in record, fill in offset.
	s.offset = uint16(offset)
	s.next = *t
	*t = s
	unlock(&span.speciallock)
	releasem(mp)

	return true
}

// Removes the Special record of the given kind for the object p.
// Returns the record if the record existed, nil otherwise.
// The caller must FixAlloc_Free the result.
func removespecial(p unsafe.Pointer, kind uint8) *special {
	span := mheap_.lookupMaybe(p)
	if span == nil {
		throw("removespecial on invalid pointer")
	}

	// Ensure that the span is swept.
	// Sweeping accesses the specials list w/o locks, so we have
	// to synchronize with it. And it's just much safer.
	mp := acquirem()
	span.ensureSwept()

	offset := uintptr(p) - span.base()

	lock(&span.speciallock)
	t := &span.specials
	for {
		s := *t
		if s == nil {
			break
		}
		// This function is used for finalizers only, so we don't check for
		// "interior" specials (p must be exactly equal to s->offset).
		if offset == uintptr(s.offset) && kind == s.kind {
			*t = s.next
			unlock(&span.speciallock)
			releasem(mp)
			return s
		}
		t = &s.next
	}
	unlock(&span.speciallock)
	releasem(mp)
	return nil
}

// The described object has a finalizer set for it.
//
// specialfinalizer is allocated from non-GC'd memory, so any heap
// pointers must be specially handled.
//
//go:notinheap
type specialfinalizer struct {
	special special
	fn      *funcval // May be a heap pointer.
	nret    uintptr
	fint    *_type   // May be a heap pointer, but always live.
	ot      *ptrtype // May be a heap pointer, but always live.
}

// Adds a finalizer to the object p. Returns true if it succeeded.
func addfinalizer(p unsafe.Pointer, f *funcval, nret uintptr, fint *_type, ot *ptrtype) bool {
	lock(&mheap_.speciallock)
	s := (*specialfinalizer)(mheap_.specialfinalizeralloc.alloc())
	unlock(&mheap_.speciallock)
	s.special.kind = _KindSpecialFinalizer
	s.fn = f
	s.nret = nret
	s.fint = fint
	s.ot = ot
	if addspecial(p, &s.special) {
		// This is responsible for maintaining the same
		// GC-related invariants as markrootSpans in any
		// situation where it's possible that markrootSpans
		// has already run but mark termination hasn't yet.
		if gcphase != _GCoff {
			_, base, _ := findObject(p)
			mp := acquirem()
			gcw := &mp.p.ptr().gcw
			// Mark everything reachable from the object
			// so it's retained for the finalizer.
			scanobject(uintptr(base), gcw)
			// Mark the finalizer itself, since the
			// special isn't part of the GC'd heap.
			scanblock(uintptr(unsafe.Pointer(&s.fn)), sys.PtrSize, &oneptrmask[0], gcw)
			if gcBlackenPromptly {
				gcw.dispose()
			}
			releasem(mp)
		}
		return true
	}

	// There was an old finalizer
	lock(&mheap_.speciallock)
	mheap_.specialfinalizeralloc.free(unsafe.Pointer(s))
	unlock(&mheap_.speciallock)
	return false
}

// Removes the finalizer (if any) from the object p.
func removefinalizer(p unsafe.Pointer) {
	s := (*specialfinalizer)(unsafe.Pointer(removespecial(p, _KindSpecialFinalizer)))
	if s == nil {
		return // there wasn't a finalizer to remove
	}
	lock(&mheap_.speciallock)
	mheap_.specialfinalizeralloc.free(unsafe.Pointer(s))
	unlock(&mheap_.speciallock)
}

// The described object is being heap profiled.
//
//go:notinheap
type specialprofile struct {
	special special
	b       *bucket
}

// Set the heap profile bucket associated with addr to b.
func setprofilebucket(p unsafe.Pointer, b *bucket) {
	lock(&mheap_.speciallock)
	s := (*specialprofile)(mheap_.specialprofilealloc.alloc())
	unlock(&mheap_.speciallock)
	s.special.kind = _KindSpecialProfile
	s.b = b
	if !addspecial(p, &s.special) {
		throw("setprofilebucket: profile already set")
	}
}

// Do whatever cleanup needs to be done to deallocate s. It has
// already been unlinked from the MSpan specials list.
func freespecial(s *special, p unsafe.Pointer, size uintptr) {
	switch s.kind {
	case _KindSpecialFinalizer:
		sf := (*specialfinalizer)(unsafe.Pointer(s))
		queuefinalizer(p, sf.fn, sf.nret, sf.fint, sf.ot)
		lock(&mheap_.speciallock)
		mheap_.specialfinalizeralloc.free(unsafe.Pointer(sf))
		unlock(&mheap_.speciallock)
	case _KindSpecialProfile:
		sp := (*specialprofile)(unsafe.Pointer(s))
		mProf_Free(sp.b, size)
		lock(&mheap_.speciallock)
		mheap_.specialprofilealloc.free(unsafe.Pointer(sp))
		unlock(&mheap_.speciallock)
	default:
		throw("bad special kind")
		panic("not reached")
	}
}

// gcBits is an alloc/mark bitmap. This is always used as *gcBits.
//
//go:notinheap
type gcBits uint8

// bytep returns a pointer to the n'th byte of b.
func (b *gcBits) bytep(n uintptr) *uint8 {
	return addb((*uint8)(b), n)
}

// bitp returns a pointer to the byte containing bit n and a mask for
// selecting that bit from *bytep.
func (b *gcBits) bitp(n uintptr) (bytep *uint8, mask uint8) {
	return b.bytep(n / 8), 1 << (n % 8)
}

const gcBitsChunkBytes = uintptr(64 << 10)
const gcBitsHeaderBytes = unsafe.Sizeof(gcBitsHeader{})

type gcBitsHeader struct {
	free uintptr // free is the index into bits of the next free byte.
	next uintptr // *gcBits triggers recursive type bug. (issue 14620)
}

//go:notinheap
type gcBitsArena struct {
	// gcBitsHeader // side step recursive type bug (issue 14620) by including fields by hand.
	free uintptr // free is the index into bits of the next free byte; read/write atomically
	next *gcBitsArena
	bits [gcBitsChunkBytes - gcBitsHeaderBytes]gcBits
}

var gcBitsArenas struct {
	lock     mutex
	free     *gcBitsArena
	next     *gcBitsArena // Read atomically. Write atomically under lock.
	current  *gcBitsArena
	previous *gcBitsArena
}

// tryAlloc allocates from b or returns nil if b does not have enough room.
// This is safe to call concurrently.
func (b *gcBitsArena) tryAlloc(bytes uintptr) *gcBits {
	if b == nil || atomic.Loaduintptr(&b.free)+bytes > uintptr(len(b.bits)) {
		return nil
	}
	// Try to allocate from this block.
	end := atomic.Xadduintptr(&b.free, bytes)
	if end > uintptr(len(b.bits)) {
		return nil
	}
	// There was enough room.
	start := end - bytes
	return &b.bits[start]
}

// newMarkBits returns a pointer to 8 byte aligned bytes
// to be used for a span's mark bits.
func newMarkBits(nelems uintptr) *gcBits {
	blocksNeeded := uintptr((nelems + 63) / 64)
	bytesNeeded := blocksNeeded * 8

	// Try directly allocating from the current head arena.
	head := (*gcBitsArena)(atomic.Loadp(unsafe.Pointer(&gcBitsArenas.next)))
	if p := head.tryAlloc(bytesNeeded); p != nil {
		return p
	}

	// There's not enough room in the head arena. We may need to
	// allocate a new arena.
	lock(&gcBitsArenas.lock)
	// Try the head arena again, since it may have changed. Now
	// that we hold the lock, the list head can't change, but its
	// free position still can.
	if p := gcBitsArenas.next.tryAlloc(bytesNeeded); p != nil {
		unlock(&gcBitsArenas.lock)
		return p
	}

	// Allocate a new arena. This may temporarily drop the lock.
	fresh := newArenaMayUnlock()
	// If newArenaMayUnlock dropped the lock, another thread may
	// have put a fresh arena on the "next" list. Try allocating
	// from next again.
	if p := gcBitsArenas.next.tryAlloc(bytesNeeded); p != nil {
		// Put fresh back on the free list.
		// TODO: Mark it "already zeroed"
		fresh.next = gcBitsArenas.free
		gcBitsArenas.free = fresh
		unlock(&gcBitsArenas.lock)
		return p
	}

	// Allocate from the fresh arena. We haven't linked it in yet, so
	// this cannot race and is guaranteed to succeed.
	p := fresh.tryAlloc(bytesNeeded)
	if p == nil {
		throw("markBits overflow")
	}

	// Add the fresh arena to the "next" list.
	fresh.next = gcBitsArenas.next
	atomic.StorepNoWB(unsafe.Pointer(&gcBitsArenas.next), unsafe.Pointer(fresh))

	unlock(&gcBitsArenas.lock)
	return p
}

// newAllocBits returns a pointer to 8 byte aligned bytes
// to be used for this span's alloc bits.
// newAllocBits is used to provide newly initialized spans
// allocation bits. For spans not being initialized the
// the mark bits are repurposed as allocation bits when
// the span is swept.
func newAllocBits(nelems uintptr) *gcBits {
	return newMarkBits(nelems)
}

// nextMarkBitArenaEpoch establishes a new epoch for the arenas
// holding the mark bits. The arenas are named relative to the
// current GC cycle which is demarcated by the call to finishweep_m.
//
// All current spans have been swept.
// During that sweep each span allocated room for its gcmarkBits in
// gcBitsArenas.next block. gcBitsArenas.next becomes the gcBitsArenas.current
// where the GC will mark objects and after each span is swept these bits
// will be used to allocate objects.
// gcBitsArenas.current becomes gcBitsArenas.previous where the span's
// gcAllocBits live until all the spans have been swept during this GC cycle.
// The span's sweep extinguishes all the references to gcBitsArenas.previous
// by pointing gcAllocBits into the gcBitsArenas.current.
// The gcBitsArenas.previous is released to the gcBitsArenas.free list.
func nextMarkBitArenaEpoch() {
	lock(&gcBitsArenas.lock)
	if gcBitsArenas.previous != nil {
		if gcBitsArenas.free == nil {
			gcBitsArenas.free = gcBitsArenas.previous
		} else {
			// Find end of previous arenas.
			last := gcBitsArenas.previous
			for last = gcBitsArenas.previous; last.next != nil; last = last.next {
			}
			last.next = gcBitsArenas.free
			gcBitsArenas.free = gcBitsArenas.previous
		}
	}
	gcBitsArenas.previous = gcBitsArenas.current
	gcBitsArenas.current = gcBitsArenas.next
	atomic.StorepNoWB(unsafe.Pointer(&gcBitsArenas.next), nil) // newMarkBits calls newArena when needed
	unlock(&gcBitsArenas.lock)
}

// newArenaMayUnlock allocates and zeroes a gcBits arena.
// The caller must hold gcBitsArena.lock. This may temporarily release it.
func newArenaMayUnlock() *gcBitsArena {
	var result *gcBitsArena
	if gcBitsArenas.free == nil {
		unlock(&gcBitsArenas.lock)
		result = (*gcBitsArena)(sysAlloc(gcBitsChunkBytes, &memstats.gc_sys))
		if result == nil {
			throw("runtime: cannot allocate memory")
		}
		lock(&gcBitsArenas.lock)
	} else {
		result = gcBitsArenas.free
		gcBitsArenas.free = gcBitsArenas.free.next
		memclrNoHeapPointers(unsafe.Pointer(result), gcBitsChunkBytes)
	}
	result.next = nil
	// If result.bits is not 8 byte aligned adjust index so
	// that &result.bits[result.free] is 8 byte aligned.
	if uintptr(unsafe.Offsetof(gcBitsArena{}.bits))&7 == 0 {
		result.free = 0
	} else {
		result.free = 8 - (uintptr(unsafe.Pointer(&result.bits[0])) & 7)
	}
	return result
}
