package gosec

const (
	_PROT_NONE     = 0x0
	_PROT_READ     = 0x1
	_PROT_WRITE    = 0x2
	_PROT_EXEC     = 0x4
	_MAP_SHARED    = 0x01
	_MAP_PRIVATE   = 0x02
	_MAP_FIXED     = 0x10
	_MAP_ANON      = 0x20
	_MAP_NORESERVE = 0x4000
	SGX_MAGIC      = 0xA4

	ERR_SGX_INVALID_EINIT_TOKEN = 16
	ERR_SGX_INVALID_CPUSVN      = 32
	ERR_SGX_INVALID_ISVSVN      = 64
	//TODO(aghosn) for the moment I hardcode it, but should be more resilient.
	SGX_IOC_ENCLAVE_CREATE   = ((1 << 30) | (SGX_MAGIC << 8) | (0) | (8 << 16))
	SGX_IOC_ENCLAVE_ADD_PAGE = ((1 << 30) | (SGX_MAGIC << 8) | (0x01) | (26 << 16))
	SGX_IOC_ENCLAVE_INIT     = ((1 << 30) | (SGX_MAGIC << 8) | (0x02) | (24 << 16))

	SGX_ATTR_MODE64BIT = 0x04
	TCS_DBGOPTION      = 1
)

type einittoken_t struct {
	valid              uint32
	reserved           [44]uint8
	attributes         attributes_t
	mrEnclave          [32]uint8
	reserved2          [32]uint8
	mrSigner           [32]uint8
	reserved3          [32]uint8
	cpuSvnLE           [16]uint8
	isvprodIDLE        uint16
	isvsvnLE           uint16
	reserved4          [24]uint8
	maskedmiscSelectLE miscselect_t
	maskedAttributesLE attributes_t
	keyid              [32]uint8
	mac                [16]uint8
}

type sigstruct_t struct {
	header        [16]uint8
	vendor        uint32
	date          uint32
	header2       [16]uint8
	swdefined     uint32
	reserved1     [84]uint8
	modulus       [384]uint8
	exponent      uint32
	signature     [384]uint8
	miscselect    miscselect_t
	miscmask      miscselect_t
	reserved2     [20]uint8
	attributes    attributes_t
	attributeMask attributes_t
	enclaveHash   [32]uint8
	reserved3     [32]uint8
	isvProdID     uint16
	isvSvn        uint16
	reserved4     [12]uint8
	q1            [384]uint8
	q2            [384]uint8
}

type tcs_t struct {
	reserved1 uint64 // 0
	flags     uint64 /* (8)bit 0: DBGOPTION */
	ossa      uint64 /* (16)State Save Area */
	cssa      uint32 /* (24)Current SSA slot */
	nssa      uint32 /* (28)Number of SSA slots */
	oentry    uint64 /* (32)Offset in enclave to which control is transferred on EENTER if enclave INACTIVE state */
	reserved2 uint64 /* (40) */
	ofsbasgx  uint64 /* (48)When added to the base address of the enclave, produces the base address FS segment inside the enclave */
	ogsbasgx  uint64 /* (56)When added to the base address of the enclave, produces the base address GS segment inside the enclave */
	fslimit   uint32 /* (64)Size to become the new FS limit in 32-bit mode */
	gslimit   uint32 /* (68)Size to become the new GS limit in 32-bit mode */
	reserved3 [503]uint64
}

type secs_t struct {
	size                   uint64 //!< Size of enclave in bytes; must be power of 2
	baseAddr               uint64 //!< Enclave base linear address must be naturally aligned to size
	ssaFrameSize           uint32 //!< Size of 1 SSA frame in pages(incl. XSAVE)
	miscselect             miscselect_t
	reserved1              [24]uint8
	attributes             uint64 //!< Attributes of Enclave: (pg 2-4)
	xfrm                   uint64
	mrEnclave              [32]uint8 //!< Measurement Reg of encl. build process
	reserved2              [32]uint8
	mrSigner               [32]uint8 //!< Measurement Reg extended with pub key that verified the enclave
	reserved3              [96]uint8
	isvprodID              uint16 //!< Product ID of enclave
	isvsvn                 uint16 //!< Security Version Number (SVN) of enclave
	mrEnclaveUpdateCounter uint64 //!< Hack: place update counter here
	eid_reserved           secs_eid_reserved_t
}

type miscselect_t struct {
	Value     uint8
	Reversed2 [3]uint8
}

type attributes_t struct {
	value     uint8
	reserved4 [7]uint8
	xfrm      uint64
}

// TODO(aghosn) fix this: reserved and eid/pad should overlap according to the sgx reference
type secs_eid_reserved_t struct {
	eid_pad  secs_eid_pad_t
	reserved [3836]uint8 //!< Reserve 8 bytes for update counter.
}

// (ref 2.7, table 2-2)
type secs_eid_pad_t struct {
	eid     uint64     //!< Enclave Identifier
	padding [352]uint8 //!< Padding pattern from Signature
}
