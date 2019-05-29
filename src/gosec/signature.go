package gosec

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"io/ioutil"
	"os"
	"os/exec"
	"time"
	"unsafe"
)

const (
	target           = "/tmp/gobdump.dat"
	_enclaveCssSize  = uintptr(1808)
	_miscselectSize  = uintptr(4)
	_attribSize      = uintptr(16)
	_measurementSize = uintptr(SGX_HASH_SIZE)
	_tcs_t_size      = uintptr(0x1000)
)

var data2hash []byte = nil
var meta *metadata_t

func checkStructSize() {
	if unsafe.Sizeof(enclave_css_t{}) != _enclaveCssSize {
		panic("Wrong size for the enclave css.")
	}

	if unsafe.Sizeof(miscselect_t{}) != _miscselectSize {
		panic("Wrong size for the miscseclect")
	}

	if unsafe.Sizeof(sgx_attributes_t{}) != _attribSize {
		panic("Wrong size for the sgx_attributes.")
	}

	if unsafe.Sizeof(sgx_measurement_t{}) != _measurementSize {
		panic("Wrong size for the sgx_measurement")
	}

	if unsafe.Sizeof(tcs_t{}) != _tcs_t_size {
		panic("Wrong size for the tcs_t")
	}
}

func sgxHashInit() {
	checkStructSize()
	data2hash = make([]byte, 0)
	meta = &metadata_t{}
	setHeader(&meta.Enclave_css)
	setBody(&meta.Enclave_css)
	meta.Magic_num = METADATA_MAGIC
	meta.Version = METADATA_VERSION
	meta.Tcs_policy = 1
	meta.Max_save_buffer_size = 2632
	meta.Desired_misc_select = 0
	meta.Tcs_min_pool = 1

}

func setHeader(e *enclave_css_t) {
	e.Header = [12]uint8{6, 0, 0, 0, 0xE1, 0, 0, 0, 0, 0, 1, 0}
	e.Header2 = [16]uint8{1, 1, 0, 0, 0x60, 0, 0, 0, 0x60, 0, 0, 0, 1, 0, 0, 0}
	//TODO trying to see if dbg works.
	e.Tpe = 0 //uint32(TPE_DBG)
	e.Module_vendor = 0
	year, month, day := time.Now().Date()
	e.Date = uint32(day + (int(month) << 8) + (year % 100 << 16) + (year / 100 << 24))
	e.Hw_version = 0
	for i := range e.Reserved {
		e.Reserved[i] = 0
	}
}

func setBody(e *enclave_css_t) {
	e.Misc_mask.Value = 0xff
	for i := range e.Misc_mask.Reversed2 {
		e.Misc_mask.Reversed2[i] = 0xff
	}
	e.Isv_prod_id = 0
	e.Isv_svn = 42
}

func sgxHashEcreate(secs *secs_t) {
	meta.Enclave_size = secs.size
	meta.Attributes.Flags = secs.attributes
	meta.Attributes.Xfrm = secs.xfrm

	tmp := make([]byte, 64)
	offset := 0

	eheader := []byte("ECREATE\000")
	if len(eheader) != 8 {
		panic("header has incorrect size.")
	}
	memcpy_s(tmp, eheader, offset, 8)
	offset += 8

	//ssaFS := make([]byte, 8)
	//binary.LittleEndian.PutUint64(ssaFS, uint64(secs.ssaFrameSize))
	//memcpy_s(tmp, ssaFS, offset, 8)
	//offset += 8
	ssaFS := make([]byte, 4)
	binary.LittleEndian.PutUint32(ssaFS, secs.ssaFrameSize)
	memcpy_s(tmp, ssaFS, offset, 4)
	offset += 4

	secSize := make([]byte, 8)
	binary.LittleEndian.PutUint64(secSize, secs.size)
	memcpy_s(tmp, secSize, offset, 8)
	offset += 8
	for i := offset; i < len(tmp); i++ {
		tmp[i] = byte(0)
	}

	// Append it to the hash.
	data2hash = append(data2hash, tmp...)
}

func sgxHashEadd(secs *secs_t, secinfo *isgx_secinfo, daddr uintptr) {
	if daddr < uintptr(secs.baseAddr) {
		panic("gosec: invalid daddr out of range.")
	}
	tmp := make([]byte, 64)
	offset := 0

	eheader := []byte("EADD\000\000\000\000")
	if len(eheader) != 8 {
		panic("EADD hash has not the correct size.")
	}
	memcpy_s(tmp, eheader, offset, 8)
	offset += 8

	off := uint64(daddr) - secs.baseAddr
	encloff := make([]byte, 8)
	binary.LittleEndian.PutUint64(encloff, off)
	memcpy_s(tmp, encloff, offset, 8)
	offset += 8

	flags := make([]byte, 8)
	binary.LittleEndian.PutUint64(flags, secinfo.flags)
	memcpy_s(tmp, flags, offset, 8)
	offset += 8

	base := unsafe.Pointer(&secinfo.reserved)
	for i := offset; i < len(tmp); i++ {
		val := (*byte)(unsafe.Pointer(uintptr(base) + uintptr(i-offset)))
		tmp[i] = *val
	}
	// Add it to the signature.
	data2hash = append(data2hash, tmp...)

	if secinfo.flags&SGX_SECINFO_W == 0 || secinfo.flags&SGX_SECINFO_TCS != 0 {
		sgxHashEExtendRegion(secs, daddr)
	}

}

func sgxHashEExtend(secs *secs_t, daddr uintptr) {
	if daddr < uintptr(secs.baseAddr) || daddr > uintptr(secs.baseAddr)+uintptr(secs.size) {
		panic("gosec: invalid daddr out of range.")
	}
	tmp := make([]byte, 320)
	offset := 0

	eheader := []byte("EEXTEND\000")
	if len(eheader) != 8 {
		panic("EEXTEND has not the correct size.")
	}
	memcpy_s(tmp, eheader, offset, 8)
	offset += 8

	off := uint64(uint64(daddr) - secs.baseAddr)
	encloff := make([]byte, 8)
	binary.LittleEndian.PutUint64(encloff, off)
	memcpy_s(tmp, encloff, offset, 8)
	offset += 8

	// TODO 48 0 bytes.
	offset += 48
	base := transposeOut(daddr)
	for i := uintptr(0); i < uintptr(256); i++ {
		val := (*byte)(unsafe.Pointer(base + i))
		tmp[int(i)+offset] = *val
	}
	data2hash = append(data2hash, tmp...)
}

// Adds a full page to the eextend
func sgxHashEExtendRegion(secs *secs_t, daddr uintptr) {
	for i := uintptr(0); i < PSIZE; i += uintptr(256) {
		sgxHashEExtend(secs, daddr+i)
	}
}

func sgxHashFinalize() {
	sig := sha256.Sum256(data2hash)
	for i := 0; i < SGX_HASH_SIZE; i++ {
		meta.Enclave_css.Enclave_hash.M[i] = sig[i]
	}

	//Do a dump of the measurement here.
	err := ioutil.WriteFile("/tmp/gosec_measurement.dat", data2hash, 0644)
	check(err)
}

func sgxTokenGetRequest(secs *secs_t) *LaunchTokenRequest {
	tokenreq := &LaunchTokenRequest{}
	tokenreq.MrSigner = []byte("trying") // key modulus.
	tokenreq.MrEnclave = meta.Enclave_css.Enclave_hash.M[:]

	seattrib := make([]byte, 0)

	attrib := make([]byte, 8)
	binary.LittleEndian.PutUint64(attrib, secs.attributes)
	seattrib = append(seattrib, attrib...)

	xflags := make([]byte, 8)
	binary.LittleEndian.PutUint64(xflags, secs.xfrm)
	seattrib = append(seattrib, xflags...)

	tokenreq.SeAttributes = seattrib
	return tokenreq
}

func sgxTokenGetAesm(secs *secs_t) TokenGob {
	request := sgxTokenGetRequest(secs)

	f, err := os.Create("/tmp/gobdump_meta.dat")
	check(err)

	enc := gob.NewEncoder(f)
	err = enc.Encode(meta)
	check(err)

	f2, err := os.Create("/tmp/gobdump_req.dat")
	check(err)
	enc = gob.NewEncoder(f2)
	err = enc.Encode(request)
	check(err)

	cmd := exec.Command("serializer", "")
	err = cmd.Run()
	check(err)

	// Read the token.
	b, err := ioutil.ReadFile("/tmp/go_enclave.token")
	check(err)

	dec := gob.NewDecoder(bytes.NewReader(b))
	var token TokenGob
	err = dec.Decode(&token)
	check(err)
	return token
}

func memcpy_s(dst, src []byte, off, s int) {
	for i := 0; i < s; i++ {
		dst[off+i] = src[i]
	}
}
