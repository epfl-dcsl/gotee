// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

package runtime

import "unsafe"

const (
	_sys_epoll_create  = 213
	_sys_epoll_create1 = 291
	_sys_epoll_ctl     = 233
	_sys_epoll_wait    = 281
	_sys_closeonexec   = 72
)

func eepollcreate(size int32) int32
func eepollcreate1(flags int32) int32
func ccloseonexec(fd int32)

//go:noescape
func eepollctl(epfd, op, fd int32, ev *epollevent) int32

//go:noescape
func eepollwait(epfd int32, ev *epollevent, nev, timeout int32) int32

func epollcreate(size int32) int32 {
	if !isEnclave {
		return eepollcreate(size)
	}
	return gosecinterpose(_sys_epoll_create, uintptr(size), 0, 0, 0, 0, 0)
}
func epollcreate1(flags int32) int32 {
	if !isEnclave {
		return eepollcreate1(flags)
	}
	return gosecinterpose(_sys_epoll_create1, uintptr(flags), 0, 0, 0, 0, 0)
}

func epollctl(epfd, op, fd int32, ev *epollevent) int32 {
	if !isEnclave {
		return eepollctl(epfd, op, fd, ev)
	}
	return gosecinterpose(_sys_epoll_ctl, uintptr(epfd), uintptr(op), uintptr(fd), uintptr(unsafe.Pointer(ev)), 0, 0)
}

func epollwait(epfd int32, ev *epollevent, nev, timeout int32) int32 {
	if !isEnclave {
		return eepollwait(epfd, ev, nev, timeout)
	}
	return gosecinterpose(_sys_epoll_wait, uintptr(epfd), uintptr(unsafe.Pointer(ev)), uintptr(nev), uintptr(timeout), 0, 0)
}

func closeonexec(fd int32) {
	if !isEnclave {
		ccloseonexec(fd)
		return
	}
	gosecinterpose(_sys_closeonexec, uintptr(fd), 2, 1, 0, 0, 0)
}

var (
	epfd int32 = -1 // epoll descriptor
)

func netpollinit() {
	epfd = epollcreate1(_EPOLL_CLOEXEC)
	if epfd >= 0 {
		return
	}
	epfd = epollcreate(1024)
	if epfd >= 0 {
		closeonexec(epfd)
		return
	}
	println("runtime: epollcreate failed with", -epfd)
	throw("runtime: netpollinit failed")
}

func netpolldescriptor() uintptr {
	return uintptr(epfd)
}

func netpollopen(fd uintptr, pd *pollDesc) int32 {
	var ev epollevent
	ev.events = _EPOLLIN | _EPOLLOUT | _EPOLLRDHUP | _EPOLLET
	*(**pollDesc)(unsafe.Pointer(&ev.data)) = pd
	return -epollctl(epfd, _EPOLL_CTL_ADD, int32(fd), &ev)
}

func netpollclose(fd uintptr) int32 {
	var ev epollevent
	return -epollctl(epfd, _EPOLL_CTL_DEL, int32(fd), &ev)
}

func netpollarm(pd *pollDesc, mode int) {
	throw("runtime: unused")
}

// polls for ready network connections
// returns list of goroutines that become runnable
func netpoll(block bool) *g {
	if epfd == -1 {
		return nil
	}
	waitms := int32(-1)
	if !block {
		waitms = 0
	}
	var events [128]epollevent
retry:
	n := epollwait(epfd, &events[0], int32(len(events)), waitms)
	if n < 0 {
		if n != -_EINTR {
			println("runtime: epollwait on fd", epfd, "failed with", -n)
			throw("runtime: netpoll failed")
		}
		goto retry
	}
	var gp guintptr
	for i := int32(0); i < n; i++ {
		ev := &events[i]
		if ev.events == 0 {
			continue
		}
		var mode int32
		if ev.events&(_EPOLLIN|_EPOLLRDHUP|_EPOLLHUP|_EPOLLERR) != 0 {
			mode += 'r'
		}
		if ev.events&(_EPOLLOUT|_EPOLLHUP|_EPOLLERR) != 0 {
			mode += 'w'
		}
		if mode != 0 {
			pd := *(**pollDesc)(unsafe.Pointer(&ev.data))

			netpollready(&gp, pd, mode)
		}
	}
	if block && gp == 0 {
		goto retry
	}
	return gp.ptr()
}

func gosecinterpose(trap, a1, a2, a3, a4, a5, a6 uintptr) int32 {
	if Cooprt == nil || !isEnclave {
		panic("Going through interpose with nil Cooprt or outside of enclave.")
	}
	//TODO check the curg not nil before doing these things
	gp := getg()
	if gp == nil || gp.m.g0 == nil {
		panic("oh shit")
	}
	var r1 uintptr
	syscid, csys := Cooprt.AcquireSysPool()
	switch trap {
	case _sys_closeonexec:
		fallthrough
	case _sys_epoll_create:
		fallthrough
	case _sys_epoll_create1:
		req := OcallReq{S3, trap, a1, a2, a3, 0, 0, 0, syscid}
		Cooprt.Ocall <- req
		res := <-csys
		r1 = res.R1
	case _sys_epoll_ctl:
		sev := unsafe.Sizeof(epollevent{})
		ev := UnsafeAllocator.Malloc(sev)
		memcpy(ev, a4, sev)
		req := OcallReq{S6, trap, a1, a2, a3, ev, 0, 0, syscid}
		Cooprt.Ocall <- req
		res := <-csys
		//copy back the results and free.
		memcpy(a4, ev, sev)
		UnsafeAllocator.Free(ev, sev)
		r1 = res.R1
	case _sys_epoll_wait:
		// We need to do an exit here, so lets give up the channel.
		Cooprt.ReleaseSysPool(syscid)
		sev := unsafe.Sizeof(epollevent{})
		ev := UnsafeAllocator.Malloc(sev)
		req := (*OcallReq)(unsafe.Pointer(UnsafeAllocator.Malloc(unsafe.Sizeof(OcallReq{}))))
		res := (*OcallRes)(unsafe.Pointer(UnsafeAllocator.Malloc(unsafe.Sizeof(OcallRes{}))))
		memcpy(ev, a2, sev)
		*req = OcallReq{S6, trap, a1, ev, a3, a4, a5, a6, syscid}
		sgx_ocall_epoll_pwait(req, res)
		r1 = res.R1
		UnsafeAllocator.Free(uintptr(unsafe.Pointer(req)), unsafe.Sizeof(*req))
		UnsafeAllocator.Free(uintptr(unsafe.Pointer(res)), unsafe.Sizeof(*res))
		memcpy(a2, ev, sev)
		UnsafeAllocator.Free(ev, sev)
		return int32(r1)
	default:
		panic("Unsupported gosecinterpose syscall")
	}
	Cooprt.ReleaseSysPool(syscid)
	return int32(r1)
}

func sgx_ocall_epoll_pwait(req *OcallReq, res *OcallRes) {
	if !isEnclave || Cooprt == nil {
		throw("Wrong call to sgx ocall epoll pwait")
	}
	gp := getg()
	if gp == nil || gp.m == nil || gp.m.g0 == nil {
		throw("Something is not inited in g struct.")
	}
	ustk := gp.m.g0.sched.usp
	ubp := gp.m.g0.sched.ubp
	aptr := UnsafeAllocator.Malloc(unsafe.Sizeof(OExitRequest{}))
	args := (*OExitRequest)(unsafe.Pointer(aptr))
	args.Cid = EPollWaitRequest
	args.Sid = gp.m.procid
	args.EWReq = uintptr(unsafe.Pointer(req))
	args.EWRes = uintptr(unsafe.Pointer(res))
	sgx_ocall(Cooprt.OEntry, aptr, ustk, ubp)
	UnsafeAllocator.Free(aptr, unsafe.Sizeof(OExitRequest{}))
}

//TODO remove, avoid duplicated code.
func memcpy(dest, source, l uintptr) {
	for i := uintptr(0); i < l; i++ {
		d := (*byte)(unsafe.Pointer(dest + i))
		s := (*byte)(unsafe.Pointer(source + i))
		*d = *s
	}
}
