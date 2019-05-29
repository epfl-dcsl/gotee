package gosec

const (
	SGX_HASH_SIZE = 32
	SGX_MAC_SIZE  = 16

	METADATA_MAGIC   = uint64(0x86A80294635D0E4C)
	METADATA_VERSION = uint64(0x200000003)

	SE_KEY_SIZE      = 384 /* in bytes */
	SE_EXPONENT_SIZE = 4   /* RSA public key exponent size in bytes */

	TPE_DBG = (1 << 31)
)

type TokenGob struct {
	Token []byte
	Meta  metadata_t
}

type sgx_measurement_t struct {
	M [SGX_HASH_SIZE]uint8
}
type sgx_attributes_t struct {
	Flags uint64
	Xfrm  uint64
}

type enclave_css_t struct { /* 1808 bytes */
	Header         [12]uint8               /* (0) must be (06000000E100000000000100H) */
	Tpe            uint32                  /* (12) bit 31: 0 = prod, 1 = debug; Bit 30-0: Must be zero */
	Module_vendor  uint32                  /* (16) Intel=0x8086, ISV=0x0000 */
	Date           uint32                  /* (20) build date as yyyymmdd */
	Header2        [16]uint8               /* (24) must be (01010000600000006000000001000000H) */
	Hw_version     uint32                  /* (40) For Launch Enclaves: HWVERSION != 0. Others, HWVERSION = 0 */
	Reserved       [84]uint8               /* (44) Must be 0 */
	Modulus        [SE_KEY_SIZE]uint8      /* (128) Module Public Key (keylength=3072 bits) */
	Exponent       [SE_EXPONENT_SIZE]uint8 /* (512) RSA Exponent = 3 */
	Signature      [SE_KEY_SIZE]uint8      /* (516) Signature over Header and Body */
	Misc_select    miscselect_t            /* (900) The MISCSELECT that must be set */
	Misc_mask      miscselect_t            /* (904) Mask of MISCSELECT to enforce */
	Reserved2      [20]uint8               /* (908) Reserved. Must be 0. */
	Attributes     sgx_attributes_t        /* (928) Enclave Attributes that must be set */
	Attribute_mask sgx_attributes_t        /* (944) Mask of Attributes to Enforce */
	Enclave_hash   sgx_measurement_t       /* (960) MRENCLAVE - (32 bytes) */
	Reserved3      [32]uint8               /* (992) Must be 0 */
	Isv_prod_id    uint16                  /* (1024) ISV assigned Product ID */
	Isv_svn        uint16                  /* (1026) ISV assigned SVN */
	Reserved4      [12]uint8               /* (1028) Must be 0 */
	Q1             [SE_KEY_SIZE]uint8      /* (1040) Q1 value for RSA Signature Verification */
	Q2             [SE_KEY_SIZE]uint8      /* (1424) Q2 value for RSA Signature Verification */
}

type metadata_t struct {
	Magic_num            uint64 /* The magic number identifying the file as a signed enclave image */
	Version              uint64 /* The metadata version */
	Size                 uint32 /* The size of this structure */
	Tcs_policy           uint32 /* TCS management policy */
	Ssa_frame_size       uint32 /* The size of SSA frame in page */
	Max_save_buffer_size uint32 /* Max buffer size is 2632 */
	Desired_misc_select  uint32
	Tcs_min_pool         uint32           /* TCS min pool*/
	Enclave_size         uint64           /* enclave virtual size */
	Attributes           sgx_attributes_t /*XFeatureMask to be set in SECS. */
	Enclave_css          enclave_css_t    /* The enclave signature */
	//dirs                 [DIR_NUM]data_directory_t
	Data [18592]uint8
}

type LaunchTokenRequest struct {
	MrEnclave        []byte  `protobuf:"bytes,1,req,name=mr_enclave,json=mrEnclave" json:"mr_enclave,omitempty"`
	MrSigner         []byte  `protobuf:"bytes,2,req,name=mr_signer,json=mrSigner" json:"mr_signer,omitempty"`
	SeAttributes     []byte  `protobuf:"bytes,3,req,name=se_attributes,json=seAttributes" json:"se_attributes,omitempty"`
	Timeout          *uint32 `protobuf:"varint,9,opt,name=timeout" json:"timeout,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

type AESM_message struct {
	size uint32
	data []byte
}
