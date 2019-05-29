package runtime

import "unsafe"

//TODO(aghosn) added this for the moment to expose these to the outside.
//go:nosplit
func RMmap(addr unsafe.Pointer, n uintptr, prot, flags, fd int32, off uint32) (p unsafe.Pointer, err int) {
	return mmap(addr, n, prot, flags, fd, off)
}

func RMunmap(addr unsafe.Pointer, n uintptr) {
	munmap(addr, n)
}
