#include "go_asm.h"
#include "go_tls.h"
#include "textflag.h"


#define SYS_arch_prctl		158
#define SIM_FLAG            0x050000000008

// set tls base to DI
TEXT runtime·sgxsettls(SB),NOSPLIT,$32

  // See if we are in simulation mode or not.
  MOVB runtime·isSimulation(SB), R8
  CMPB R8, $1
  JE 2(PC)
  MOVL $0xf1, 0xf1  // crash

	ADDQ	$8, DI	// ELF wants to use -8(FS)
	MOVQ	DI, SI
	MOVQ	$0x1002, DI	// ARCH_SET_FS
	MOVQ	$SYS_arch_prctl, AX
	SYSCALL
	CMPQ	AX, $0xfffffffffffff001
	JLS	2(PC)
	MOVL	$0xf1, 0xf1  // crash
	RET
