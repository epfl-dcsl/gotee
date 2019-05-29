package gosecommon

import (
	"reflect"
	r "runtime"
	"unsafe"
)

type rslice struct {
	array unsafe.Pointer
	l     int
	c     int
}

type CA func(size uintptr) uintptr

type Copy struct {
	start uintptr
	size  uintptr
}

type Store = map[uintptr]Copy

func memcpy(dest, source, l uintptr) {
	if dest == 0 || source == 0 {
		panic("nil argument to copy")
	}
	for i := uintptr(0); i < l; i++ {
		d := (*byte)(unsafe.Pointer(dest + i))
		s := (*byte)(unsafe.Pointer(source + i))
		*d = *s
	}
}

func CanShallowCopy(rtpe *r.DPTpe) bool {
	tpe := reflect.ConvDPTpeToType(rtpe)
	switch tpe.Kind() {
	case reflect.Map:
		panic("Trying to deep copy a map...")
	case reflect.Array:
		return CanShallowCopy(reflect.ConvTypeToDPTpe(tpe.Elem()))
	case reflect.Struct:
		needed := false
		for i := 0; i < tpe.NumField(); i++ {
			if !CanShallowCopy(reflect.ConvTypeToDPTpe(tpe.Field(i).Type)) {
				needed = true
				break
			}
		}
		return !needed
	case reflect.UnsafePointer:
		fallthrough
	case reflect.Ptr:
		return false
	case reflect.Slice:
		return false
	}
	return true
}

// needsCopy checks the given type against the supported once and returns
// true if the type requires recursive exploring for copy.
func needsCopy(tpe reflect.Type) (bool, reflect.Kind) {
	switch tpe.Kind() {
	case reflect.Map:
		panic("Trying to deep copy a map...")
	case reflect.UnsafePointer:
		fallthrough
	case reflect.Ptr:
		fallthrough
	case reflect.Struct:
		// we force the inspection from deepcopy
		fallthrough
	case reflect.Array:
		fallthrough
	case reflect.Slice:
		return true, tpe.Kind()
	}
	return false, tpe.Kind()
}

func ignoreCopy(tpe reflect.Type) bool {
	return tpe == reflect.TypeOf(r.EcallReq{}) ||
		tpe == reflect.TypeOf(r.EcallServerReq{}) ||
		tpe == reflect.TypeOf(&r.EcallServerReq{})
}

func setPtrValue(ptr uintptr, val uintptr) {
	pptr := (*uintptr)(unsafe.Pointer(ptr))
	*pptr = val
}

func extractValue(ptr uintptr) uintptr {
	val := *(*uintptr)(unsafe.Pointer(ptr))
	return val
}

func copyIn(size uintptr) uintptr {
	v := make([]uint8, size)
	return uintptr(unsafe.Pointer(&v[0]))
}

func DeepCopierSend(src unsafe.Pointer, tpe *r.DPTpe) (unsafe.Pointer, r.AllocTracker) {
	store := make(Store)
	gtpe := reflect.ConvTypePtr(tpe)
	var tracker r.AllocTracker
	allocater := func(size uintptr) uintptr {
		res := r.UnsafeAllocator.Malloc(size)
		tracker = append(tracker, r.TrackerEntry{res, size})
		return res
	}
	cpy := unsafe.Pointer(DeepCopy(uintptr(src), gtpe, store, allocater))
	return cpy, tracker
}

func DeepCopier(src unsafe.Pointer, tpe *r.DPTpe) unsafe.Pointer {
	store := make(Store)
	gtpe := reflect.ConvTypePtr(tpe)
	return unsafe.Pointer(DeepCopy(uintptr(src), gtpe, store, copyIn))
}

// deepCopy entry point for deepCopy.
// Takes a pointer type as element, returns pointer to the same type.
func DeepCopy(src uintptr, tpe reflect.Type, store Store, alloc CA) uintptr {
	if tpe.Kind() != reflect.Ptr {
		panic("Call to deepCopy does not respect calling convention.")
	}
	if v, ok := store[src]; ok {
		return v.start
	}
	// Initial shallow copy.
	dest := alloc(tpe.Elem().Size()) //make([]uint8, tpe.Elem().Size())
	memcpy(dest, src, tpe.Elem().Size())
	store[src] = Copy{dest, tpe.Elem().Size()}

	// Go into the type's deep copy
	deepCopy1(dest, src, tpe.Elem(), store, alloc)
	return dest
}

// deepCopy1 dest and src are pointers to type tpe.
func deepCopy1(dest, src uintptr, tpe reflect.Type, store Store, alloc CA) {
	b, k := needsCopy(tpe)
	if !b {
		// flat type, not interesting.
		return
	}
	switch k {
	case reflect.Ptr:
		// at that point dest and ptr should be ptrs to ptrs
		val := DeepCopy(extractValue(src), tpe, store, alloc)
		setPtrValue(dest, val)
	case reflect.Struct:
		offset := uintptr(0)
		for i := 0; i < tpe.NumField(); i++ {
			f := tpe.Field(i)
			if b, _ := needsCopy(f.Type); b {
				deepCopy1(dest+offset, src+offset, f.Type, store, alloc)
			}
			offset += f.Type.Size()
		}
	case reflect.Array:
		if b, _ := needsCopy(tpe.Elem()); !b {
			return
		}
		offset := uintptr(0)
		for i := 0; i < tpe.Len(); i++ {
			deepCopy1(dest+offset, src+offset, tpe.Elem(), store, alloc)
			offset += tpe.Elem().Size()
		}
	// TODO handle slices.
	case reflect.Slice:
		rs := (*rslice)(unsafe.Pointer(src))
		//now allocate the new array
		ndest := alloc(uintptr(rs.c))
		memcpy(ndest, uintptr(rs.array), uintptr(rs.l))
		cs := (*rslice)(unsafe.Pointer(dest))
		cs.array = unsafe.Pointer(ndest)
		cs.l = rs.l
		cs.c = rs.c
		if b, _ := needsCopy(tpe.Elem()); b {
			deepCopy1(ndest, uintptr(rs.array), reflect.ArrayOf(rs.c, tpe.Elem()), store, alloc)
		}
	case reflect.UnsafePointer:
		panic("Unsafe pointers are not allowed!")
	case reflect.Chan:
		panic("Must implement the channel registration")
	default:
		panic("Unhandled type")
	}
}

func DeepCopyStackFrame(size int32, argp *uint8, ftpe reflect.Type) []byte {
	if ftpe.Kind() != reflect.Func {
		panic("Wrong call to DeepCopyStackFrame")
	}
	if size == 0 {
		return nil
	}
	store := make(Store)
	nframe := make([]byte, int(size))
	fptr := uintptr(unsafe.Pointer(&nframe[0]))
	srcptr := uintptr(unsafe.Pointer(argp))
	memcpy(fptr, srcptr, uintptr(size))
	for i := 0; i < ftpe.NumIn(); i++ {
		// handle cross-domain channels
		if ftpe.In(i).Kind() == reflect.Chan {
			extendUnsafeChanType(fptr, ftpe.In(i))
			goto endloop
		}
		if ok, _ := needsCopy(ftpe.In(i)); !ok {
			goto endloop
		}
		deepCopy1(fptr, srcptr, ftpe.In(i), store, copyIn)
	endloop:
		fptr += ftpe.In(i).Size()
		srcptr += ftpe.In(i).Size()
	}
	return nframe
}

func extendUnsafeChanType(cptr uintptr, ctype reflect.Type) {
	rdpte := reflect.ConvTypeToDPTpe(ctype.Elem())
	r.SetChanType(extractValue(cptr), rdpte)
}
