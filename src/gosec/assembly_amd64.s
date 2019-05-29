#include "textflag.h"

// func asm_eenter(tcs, xcpt, rdi, rsi uint64)
TEXT gosec·asm_eenter(SB),$0-40
    MOVQ $2, AX				//EENTER
    MOVQ tcs+0(FP),BX
    MOVQ xcpt+8(FP), CX
    BYTE $0x0f; BYTE $0x01; BYTE $0xd7 //ENCLU EENTER
    MOVQ rdi+16(FP), AX
    MOVQ DI, (AX)
    MOVQ rdi+24(FP), AX
    MOVQ SI, (AX)
    RET

// func asm_exception()
TEXT gosec·asm_exception(SB),$0
    BYTE $0x0f; BYTE $0x01; BYTE $0xd7

// func asm_eresume(tcs, xcpt uint64)
TEXT gosec·asm_eresume(SB),$0-40
    MOVQ $2, AX				//EENTER
    MOVQ tcs+0(FP),BX
    MOVQ xcpt+8(FP), CX
		MOVQ $0xdead, R10
    BYTE $0x0f; BYTE $0x01; BYTE $0xd7 //ENCLU EENTER
    // Should never return
		MOVQ $123, 123
		RET

// The goals is to push req *runtime.OExitRequest on the stack before the call
// According to our current implementation, req is in SI
// This function does the dispatch for the enclave
// func asm_oentry() 
TEXT gosec·asm_oentry(SB),NOSPLIT,$8-8
	PUSHQ SI
	MOVQ (SI), R9
	CMPQ R9, $1 // SpawnRequest (runtime/gosec.go)
	JNE futsleep
	CALL gosec·spawnEnclaveThread(SB)
	JMP end
futsleep:
	CMPQ R9, $2 // FutexSleepRequest (runtime/gosec.go)
	JNE futwake
	CALL gosec·FutexSleep(SB)
	JMP end
futwake:
	CMPQ R9, $3
	JNE epoll
	CALL gosec·FutexWakeup(SB)
	JMP end
epoll:
	CALL gosec·EpollPWait(SB)
end:
	POPQ SI
	RET
