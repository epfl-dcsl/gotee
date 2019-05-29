package runtime

import (
	"unsafe"
)

type DPTpe = _type

type TrackerEntry struct {
	Src  uintptr
	Size uintptr
}

type AllocTracker = []TrackerEntry

type CopyTpe func(unsafe.Pointer, *DPTpe) unsafe.Pointer
type CopyTpe2 func(unsafe.Pointer, *DPTpe) (unsafe.Pointer, AllocTracker)

var (
	DeepCopier     CopyTpe
	DeepCopierSend CopyTpe2
	CanShallowCopy func(*DPTpe) bool
)

func SetCopier(cp CopyTpe, csc func(*DPTpe) bool) {
	DeepCopier = cp
	CanShallowCopy = csc
}

func SetCopiers(cp CopyTpe, cp2 CopyTpe2, csc func(*DPTpe) bool) {
	DeepCopier = cp
	DeepCopierSend = cp2
	CanShallowCopy = csc
}

func storeCopy(dst unsafe.Pointer, val unsafe.Pointer, size uint16) {
	panic("bitch")
}

func copyIn(size uintptr) uintptr {
	src := make([]byte, int(size))
	return uintptr(unsafe.Pointer(&src[0]))
}

func doCopy(sg *sudog, dest unsafe.Pointer, c *hchan) {
	notInit := (DeepCopier == nil || dest == nil)
	missingInfo := isEnclave && c.encltpe == nil
	rcvDirect := (isEnclave && sg.id == -1) || (!isEnclave && sg.id != -1)
	if notInit || missingInfo {
		return
	}
	if !sg.needcpy && !rcvDirect {
		return
	}
	// now you need to do a copy
	tpe := c.elemtype
	if isEnclave {
		tpe = c.encltpe
	}

	// by default that's handled
	if CanShallowCopy(tpe) {
		return
	}
	//extract address
	orig := *(*uintptr)(unsafe.Pointer(uintptr(dest)))

	typedmemmove(tpe, dest, DeepCopier(dest, tpe))
	// non-enclave does a non-direct recv
	if !isEnclave && sg.id == -1 {
		go func() {
			Cooprt.Uach <- uintptr(orig)
		}()
	}
}

func sendCopy(dest *sudog, src unsafe.Pointer, c *hchan) bool {
	doesNotApply := !isEnclave || c.isencl || dest.elem == nil
	if doesNotApply {
		return false
	}
	nocpy := c.encltpe == nil || CanShallowCopy(c.encltpe)
	if nocpy {
		return false
	}
	r, tracker := DeepCopierSend(src, c.encltpe)
	UnsafeAllocator.registerTracker(tracker)
	typedmemmove(c.encltpe, dest.elem, r)
	return true
}
