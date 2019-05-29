#include "go_asm.h"
#include "go_tls.h"
#include "funcdata.h"
#include "textflag.h"

//Maybe we don't even need to allocate pstack in the end.
// This is the entry point for enclave threads.
// sgxtramp_encl(tcs, xcpt, rdi, rsi, msgx, isSim, pstack, m, g, id)
TEXT runtime·sgxtramp_encl(SB),NOSPLIT,$0
	// set the tls if is simulation
	MOVB runtime·isSimulation(SB), R8
	CMPB R8, $1
	JNE nonsim
		
	MOVQ msgx+32(FP), R9
	LEAQ m_tls(R9), DI
	CALL runtime·sgxsettls(SB)
	JMP setup

//TODO to fakely balance push pop
fakebalance:
	PUSHQ $0xdead
	PUSHQ $0xdead

nonsim:
	// check if we are reentering
	// TODO check the value of gm instead
	CMPQ R10, $0xdead
	JNE setup

	get_tls(CX)
	MOVQ g(CX), AX // AX = g
	MOVQ g_m(AX), BX // BX = m
	MOVQ m_g0(BX), DX // DX = m.g0

	//Get previous values for the stack
	MOVQ g_sched+gobuf_bp+8(DX), DI
	MOVQ g_sched+gobuf_bp+16(DX), SI	

	//Save the unsafe stack current location TODO will be able to remove it
	MOVQ SP, g_sched+gobuf_bp+8(DX)
	MOVQ BP, g_sched+gobuf_bp+16(DX)

	//switch stacks
	MOVQ DI, SP
	MOVQ SI, BP

	//now fix the unsafe stack
	POPQ R8 // bp
	POPQ R9 //stk

	MOVQ R8, g_sched+gobuf_bp+16(DX)
	MOVQ R9, g_sched+gobuf_bp+8(DX)

	RET

setup:
	// set the m and g
	MOVQ mp+56(FP), R8
	MOVQ gp+64(FP), R9

	get_tls(CX)
	MOVQ R8, g_m(R9)
	MOVQ R9, g(CX)

	MOVQ id+72(FP), R9
	MOVQ R9, m_procid(R8)
	
	// save unprotected stack
	get_tls(CX)
	MOVQ g(CX), AX // AX = g
	MOVQ g_m(AX), BX // BX = m
	MOVQ m_g0(BX), DX // DX = m.g0
	MOVQ SP, g_sched+gobuf_bp+8(DX)
	MOVQ BP, g_sched+gobuf_bp+16(DX)

	// Switch stacks now that we used all the values
	// Protected stack is mp.g0.stack.hi
	get_tls(CX)
	MOVQ g(CX), AX
	MOVQ (g_stack+stack_hi)(AX), SP
	CALL runtime·stackcheck(SB)	

	CALL runtime·mstart(SB)
	
	// It should never return. If it does, segfault that thread
	MOVL $0xdead, 0xdead
	JMP -1(PC) // keep exiting

// Implements the logic for the enclave runtime init.
TEXT runtime·sgx_rt0_go(SB),NOSPLIT,$0
	// copy arguments forward on an even stack
	MOVQ	DI, AX		// argc
	MOVQ	SI, BX		// argv
	SUBQ	$(4*8+7), SP		// 2args 2auto
	ANDQ	$~15, SP
	MOVQ	AX, 16(SP)
	MOVQ	BX, 24(SP)

	// create istack out of the given (operating system) stack.
	// _cgo_init may update stackguard.
	MOVQ	$runtime·g0(SB), DI
	LEAQ	(-64*1024+104)(SP), BX
	MOVQ	BX, g_stackguard0(DI)
	MOVQ	BX, g_stackguard1(DI)
	MOVQ	BX, (g_stack+stack_lo)(DI)
	MOVQ	SP, (g_stack+stack_hi)(DI)

	// find out information about the processor we're on
	MOVL	$0, AX
    // TODO Not allowed within the enclave; find a solution.
    //CPUID
    MOVL    $22, AX
    MOVL    $0x756E6547, BX
    MOVL    $0x6C65746E, CX
    MOVL    $0x49656E69, DX

	MOVL	AX, SI
	CMPL	AX, $0
	JE	nocpuinfo

	// Figure out how to serialize RDTSC.
	// On Intel processors LFENCE is enough. AMD requires MFENCE.
	// Don't know about the rest, so let's do MFENCE.
	CMPL	BX, $0x756E6547  // "Genu"
	JNE	notintel

	CMPL	DX, $0x49656E69  // "ineI"
	JNE	notintel

	CMPL	CX, $0x6C65746E  // "ntel"
	JNE	notintel

	MOVB	$1, runtime·isIntel(SB)
	MOVB	$1, runtime·lfenceBeforeRdtsc(SB)

notintel:
	// Load EAX=1 cpuid flags
	MOVL	$1, AX

    //TODO modified this because CPUID is not allowed
    //CPUID
    MOVL    $0x000806e9, AX
    MOVL    $0x01100800, BX
    MOVL    $0x7ffafbff, CX

    MOVL	AX, runtime·processorVersionInfo(SB)

	TESTL	$(1<<26), DX // SSE2
	SETNE	runtime·support_sse2(SB)

	TESTL	$(1<<9), CX // SSSE3
	SETNE	runtime·support_ssse3(SB)

	TESTL	$(1<<19), CX // SSE4.1
	SETNE	runtime·support_sse41(SB)

	TESTL	$(1<<20), CX // SSE4.2
	SETNE	runtime·support_sse42(SB)

	TESTL	$(1<<23), CX // POPCNT
	SETNE	runtime·support_popcnt(SB)

	TESTL	$(1<<25), CX // AES
	SETNE	runtime·support_aes(SB)

	TESTL	$(1<<27), CX // OSXSAVE
	SETNE	runtime·support_osxsave(SB)

	// If OS support for XMM and YMM is not present
	// support_avx will be set back to false later.
	TESTL	$(1<<28), CX // AVX
	SETNE	runtime·support_avx(SB)

eax7:
	// Load EAX=7/ECX=0 cpuid flags
	CMPL	SI, $7
	JLT	osavx
	MOVL	$7, AX
	MOVL	$0, CX

    // BX 0x029c6fbf
    // TODO not supported inside the enclave.
    //CPUID
    MOVL    $0x029c6fbf, BX

	TESTL	$(1<<3), BX // BMI1
	SETNE	runtime·support_bmi1(SB)

	// If OS support for XMM and YMM is not present
	// support_avx2 will be set back to false later.
	TESTL	$(1<<5), BX
	SETNE	runtime·support_avx2(SB)

	TESTL	$(1<<8), BX // BMI2
	SETNE	runtime·support_bmi2(SB)

	TESTL	$(1<<9), BX // ERMS
	SETNE	runtime·support_erms(SB)

osavx:
	CMPB	runtime·support_osxsave(SB), $1
	JNE	noavx

	MOVL	$0, CX
	// For XGETBV, OSXSAVE bit is required and sufficient
	XGETBV


	ANDL	$6, AX
	CMPL	AX, $6 // Check for OS support of XMM and YMM registers.
	JE nocpuinfo
noavx:
	MOVB $0, runtime·support_avx(SB)
	MOVB $0, runtime·support_avx2(SB)

nocpuinfo:
	// if there is an _cgo_init, call it.
	MOVQ	_cgo_init(SB), AX
	TESTQ	AX, AX
	JZ	needtls
	// g0 already in DI
	MOVQ	DI, CX	// Win64 uses CX for first parameter
	MOVQ	$setg_gcc<>(SB), SI
	CALL	AX

	// update stackguard after _cgo_init
	MOVQ	$runtime·g0(SB), CX
	MOVQ	(g_stack+stack_lo)(CX), AX
	ADDQ	$const__StackGuard, AX
	MOVQ	AX, g_stackguard0(CX)
	MOVQ	AX, g_stackguard1(CX)

#ifndef GOOS_windows
	JMP nonsim
#endif
needtls:
#ifdef GOOS_plan9
	// skip TLS setup on Plan 9
	JMP nonsim
#endif
#ifdef GOOS_solaris
	// skip TLS setup on Solaris
	JMP nonsim
#endif

	//Set up the isEnclave variable.
	MOVB $1, runtime·isEnclave(SB)

// SGX already has the TCS set.
nonsim:
	// store through it, to make sure it works
	get_tls(BX)
	MOVQ	$0x123, g(BX)
	MOVQ	runtime·mglobal(SB), R9

	MOVQ	m_tls(R9), AX
	CMPQ	AX, $0x123
	JEQ 2(PC)
	MOVL	AX, 0	// abort

// set the per-goroutine and per-mach "registers"
	get_tls(BX)
	LEAQ	runtime·g0(SB), CX
	MOVQ	CX, g(BX)
	MOVQ 	runtime·mglobal(SB), AX
	//LEAQ	runtime·mglobal(SB), AX // replaced by the simple movq of pointer.

	// save m->g0 = g0
	MOVQ	CX, m_g0(AX)
	// save m0 to g0->m
	MOVQ	AX, g_m(CX)

	CLD				// convention is D is always left cleared
	CALL	runtime·check(SB)
	MOVL	16(SP), AX		// copy argc
	MOVL	AX, 0(SP)
	MOVQ	24(SP), AX		// copy argv
	MOVQ	AX, 8(SP)
	CALL	runtime·args(SB)

	CALL	runtime·osinit(SB)

	CALL	runtime·schedinit(SB)

	// create a new goroutine to start program
	MOVQ	$runtime·mainPC(SB), AX		// entry
	PUSHQ	AX
	PUSHQ	$0			// arg size
	CALL	runtime·newproc(SB)
	POPQ	AX
	POPQ	AX

	// start this M
	CALL	runtime·mstart(SB)

	MOVL	$0xf1, 0xf1  // crash
	RET

// void setg_gcc(G*); set g called from gcc.
TEXT setg_gcc<>(SB),NOSPLIT,$0
	get_tls(AX)
	MOVQ	DI, g(AX)
	RET

// Allows to do an ocall:
// 1. [~]set RBX to the target RIP (trgt)
// 2. [\](opt) rdi holds ocall index (idx) -> gave this one up
// 3. [~] rsi pointer to marshalling arguments to call (args)
// 4. [~]switch to unprotected stack (nstak)
// 5. [~]set rbp too (rbp)
// void sgx_ocall(void* trgt, void* args, void* nstk, void* rbp)
TEXT runtime·sgx_ocall(SB),NOSPLIT,$0
	//save current stack and bp in unprotected
	get_tls(CX)
	MOVQ g(CX), AX // AX = g
	MOVQ g_m(AX), BX // BX = m
	MOVQ m_g0(BX), DX // DX = m.g0
	//MOVQ SP, g_sched+gobuf_bp+8(DX)
	//MOVQ BP, g_sched+gobuf_bp+16(DX)

	//Arguments for the ocall
	MOVQ trgt+0(FP), BX
	MOVQ args+8(FP), SI

	//restore the rbp and rsp
	MOVQ nstk+16(FP), R8
	MOVQ rbp+24(FP), R9

	//TODO debugging
	MOVB runtime·isSimulation(SB), R10
	CMPB R10, $1
	JE stackswitch

	// Trying to save the unsafe stack and bp
	PUSHQ R8 //stk
	PUSHQ R9 //bp

stackswitch:
	//save the current stack
	MOVQ SP, g_sched+gobuf_bp+8(DX)
	MOVQ BP, g_sched+gobuf_bp+16(DX)

	MOVQ R9, BP
	MOVQ R8, SP

	// we're not gonna do sgx stuff if we are in simulation
	MOVB runtime·isSimulation(SB), R8
	CMPB R8, $1
	JNE sgxcall
	CALL BX
	JMP cleanup

sgxcall:
	//Do the ocall
	MOVQ $4, AX
	BYTE $0x0f; BYTE $0x01; BYTE $0xd7 //ENCLU EEXIT

	// see if we can come back here.
	MOVQ $124, 124
	POPQ R8 // for the balance analyzer
	POPQ R9 

cleanup: 
	get_tls(CX)
	MOVQ g(CX), AX // AX = g
	MOVQ g_m(AX), BX // BX = m
	MOVQ m_g0(BX), DX // DX = m.g0

	//Get previous values for the stack
	MOVQ g_sched+gobuf_bp+8(DX), DI
	MOVQ g_sched+gobuf_bp+16(DX), SI

	//Save the unsafe stack current location
	MOVQ SP, g_sched+gobuf_bp+8(DX)
	MOVQ BP, g_sched+gobuf_bp+16(DX)
	
	//switch stacks
	MOVQ DI, SP
	MOVQ SI, BP

	RET
	
