package gnet

import (
	"unsafe"
)

const (
	NI_NAMEREQD  = 8
	AI_CANONNAME = 0x0002
	AI_V4MAPPED  = 0x0008
	AI_ALL       = 0x0010

	EAI_AGAIN    = -3
	EAI_SYSTEM   = -11
	EAI_NONAME   = -2
	EAI_OVERFLOW = -12
	SOCK_STREAM  = 1
	SOCK_DGRAM   = 2
	IPPROTO_TCP  = 6
	IPPROTO_UDP  = 17

	AF_INET  = 2
	AF_INET6 = 12
)

type struct_in_addr struct {
	s_addr uint64
}

type struct_sockaddr struct {
	sin_family int16
	sin_port   uint16
	sin_addr   struct_in_addr
	sin_zero   [8]uint8
}

type socklen_t = int
type char_t = byte

type struct_addrinfo struct {
	ai_flags     int
	ai_family    int
	ai_socktype  int
	ai_protocol  int
	ai_addrlen   socklen_t
	ai_addr      *struct_sockaddr
	ai_canonname *char_t
	ai_next      *struct_addrinfo
}

func getnameinfo(sa *struct_sockaddr, addrlen socklen_t, host unsafe.Pointer, hostlen socklen_t, srv unsafe.Pointer, servlen socklen_t, flags int) (int, error) {
	// TODO implement correctly, for the moment we assume that sa is localhost.
	panic("TODO implement")
	return 0, nil
}

func getaddrinfo(node, service unsafe.Pointer, hints *struct_addrinfo, res **struct_addrinfo) (int, error) {
	(*res) = new(struct_addrinfo)
	addr := &struct_sockaddr{sin_family: AF_INET, sin_port: 0, sin_addr: toIp(127, 0, 0, 1)}
	canonname := []byte(" ")
	(*res).ai_flags = 26 //TODO find why
	(*res).ai_family = AF_INET
	(*res).ai_socktype = SOCK_STREAM
	(*res).ai_protocol = IPPROTO_TCP
	(*res).ai_addrlen = 16
	(*res).ai_addr = addr
	(*res).ai_canonname = &canonname[0]
	(*res).ai_next = nil
	return 0, nil
}

func freeaddrinfo(res *struct_addrinfo) {
	//panic("TODO implement")
	// TODO nothing to do I guess
}

func size_t(l int) socklen_t {
	panic("TODO implement")
	return 0
}

func toIp(h, m, m1, l uint16) struct_in_addr {
	var res uint64
	res = uint64(h)<<48 + uint64(m)<<32 + uint64(m1)<<16 + uint64(l)
	return struct_in_addr{res}
}
