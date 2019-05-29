package runtime

import (
//	"runtime/internal/atomic"
//	"unsafe"
)

func gosecassert(b bool) {
	if !b {
		print("[enclave: ", isEnclave, "]")
		throw("Assertion failure")
	}
}

const DEBUGMASK = 0x060000000000

const DBG_MASK_RT = 0xdead000

const (
	DBG_BLCK_RC = int64(0x11)
	DBG_BLCK_WC = int64(0x22)
	DBG_UNBL_RC = int64(0x33)
	DBG_UNBL_WC = int64(0x44)
	DBG_NBLC_RC = int64(0x55)
	DBG_NBLC_WC = int64(0x66)
	DBG_NOBL_RC = int64(0x77)
	DBG_NOBL_WC = int64(0x88)
	DBG_SEL_WAK = int64(0x99)
)

type DbgInfo struct {
	id        int64
	index     int64
	markers   [15]int64
	separator int64
	addresses [15]uintptr
}

type DbgRoutineInfo = [10]DbgInfo

type DbgRtThree = uintptr

//var dumper = (*DbgRoutineInfo)(unsafe.Pointer(uintptr(DEBUGMASK)))
//
//var threeDumper = (*DbgRtThree)(unsafe.Pointer((uintptr(unsafe.Pointer(dumper)) + unsafe.Sizeof(*dumper))))
//
//func dbgEnter() {
//	ptr := (*uint32)(unsafe.Pointer(uintptr(DEBUGMASK)))
//	atomic.Xadd(ptr, 1)
//}
//
//func dbgLeave() {
//	ptr := (*uint32)(unsafe.Pointer(uintptr(DEBUGMASK)))
//	if *ptr > 1 {
//		panic("Too many people, that I'll never meet")
//	}
//	atomic.Xadd(ptr, -1)
//}
//
//func dbgOutputNbAllg() {
//	gp := getg()
//	if gp == nil {
//		panic("This should not be nil")
//	}
//	p := gp.m.p.ptr()
//	if p == nil {
//		panic("This should not be nil")
//	}
//	addr := uintptr(p.id*4) + uintptr(DEBUGMASK) + unsafe.Sizeof(uintptr(1))
//	ptr := (*uint32)(unsafe.Pointer(addr))
//	atomic.Store(ptr, uint32(len(allgs)))
//}
//
//func DbgMarkRoutine(id uint32) {
//	if gp := getg(); gp != nil {
//		gp.dbgmarker = id
//		dumper[gp.dbgmarker].id = int64(uintptr(unsafe.Pointer(gp))) //int64(gp.dbgmarker) + DBG_MASK_RT
//		dumper[gp.dbgmarker].separator = 0xFFFFFFFFFFF
//		return
//	}
//	panic("The current routine is nil")
//}
//
//func DbgIsMarked() bool {
//	gp := getg()
//	if gp == nil {
//		panic("nil goroutine")
//	}
//	return gp.dbgmarker != 0
//}
//
//func DbgMarkThree(trap uintptr) {
//	gp := getg()
//	if gp == nil {
//		panic("nil goroutine")
//	}
//	if gp.dbgmarker != 3 {
//		return
//	}
//	*threeDumper = trap
//	threeDumper = (*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(threeDumper)) + unsafe.Sizeof(uintptr(0))))
//}
//
//func DbgMarkThreePost(trap uintptr) {
//	gp := getg()
//	if gp == nil {
//		panic("nil goroutine")
//	}
//	if gp.dbgmarker != 3 || trap != 0x1 {
//		return
//	}
//	*threeDumper = 0x666
//	threeDumper = (*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(threeDumper)) + unsafe.Sizeof(uintptr(0))))
//}
//
//func DbgMarkThreeGet() uintptr {
//	gp := getg()
//	if gp == nil || gp.dbgmarker == 0 {
//		return 0
//	}
//	return uintptr(gp.dbgmarker)
//}
//
//func DbgGetDiff() uintptr {
//	gp := getg()
//	if gp == nil {
//		return 0
//	}
//
//	return (uintptr(unsafe.Pointer(&gp.atomicstatus))) - (uintptr(unsafe.Pointer(gp)))
//}
//
//func DbgTakePoint(value int64, c *hchan) {
//	if !DbgIsMarked() {
//		return
//	}
//	gp := getg()
//	entry := &dumper[gp.dbgmarker]
//	if int(entry.index) >= len(entry.markers) {
//		entry.index = entry.index % int64(len(entry.markers))
//		//panic("ran out of space for markers")
//	}
//	entry.markers[entry.index] = value
//	entry.addresses[entry.index] = uintptr(unsafe.Pointer(c))
//	entry.index++
//}
//
//func dbgRegisterStatus(read bool) {
//	gp := getg()
//	if gp == nil {
//		panic("The routine is nil")
//	}
//
//	addr := uintptr(gp.dbgmarker*8) + uintptr(DEBUGMASK)
//	ptr := (*int64)(unsafe.Pointer(addr))
//	if read {
//		*ptr = gp.goid
//	} else {
//		*ptr = gp.goid * -1
//	}
//}
