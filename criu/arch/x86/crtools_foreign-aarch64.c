
/* Antonio Barbalace, Stevens 2019 */

//TODO TODO TODO we should integrate this in a better way ... such as trick used in musl to redefine and include another source (this is the original criu/arch/aarch64/crtools.c modified)



#include <string.h>
#include <unistd.h>

#include <linux/elf.h>

#include "types.h"
#include <compel/asm/processor-flags.h>

#include <compel/asm/infect-types.h>
#include "common/compiler.h"
#include <compel/ptrace.h>
#include "asm/dump.h"
#include "protobuf.h"
#include "images/core.pb-c.h"
#include "images/creds.pb-c.h"
#include "parasite-syscall.h"
#include "log.h"
#include "util.h"
#include "cpu.h"
#include "restorer.h"
#include <compel/compel.h>

#include "asm/foreign.h"

unsigned __page_size = 0;
unsigned __page_shift = 0;


#define POPCORN_REGS_aarch64 ((34+64) * sizeof(long))
	
int get_task_regs_size_aarch64() {
	return POPCORN_REGS_aarch64;
}


// the way Popcorn saves them
int save_task_regs_aarch64(void *x, unsigned long *values)
{
	int i;
	CoreEntry *core = x;
	ThreadInfoAarch64 *ti =0;
	
	if (core)
		ti = core->ti_aarch64;
	else
		return -1;
	
	// first value is the magic number;
	values++;
	
	// Save the Aarch64 CPU state
	ti->gpregs->sp = *values++;
	ti->gpregs->pc = *values++;
	for (i = 0; i < 31; ++i)
		ti->gpregs->regs[i] = *values++;
	ti->gpregs->pstate = 0x60000000;

	// Save the FP/SIMD state
	for (i = 0; i < 32; ++i)
	{
		ti->fpsimd->vregs[2*i]    = *values++;
		ti->fpsimd->vregs[2*i +1] = *values++;
	}
	ti->fpsimd->fpsr = 0;
	ti->fpsimd->fpcr = 0;

	return 0;
}

int arch_alloc_thread_info_aarch64(CoreEntry *core)
{
	ThreadInfoAarch64 *ti_aarch64;
	UserAarch64RegsEntry *gpregs;
	UserAarch64FpsimdContextEntry *fpsimd;

	ti_aarch64 = xmalloc(sizeof(*ti_aarch64));
	if (!ti_aarch64)
		goto err;
	thread_info_aarch64__init(ti_aarch64);
	core->ti_aarch64 = ti_aarch64;

	gpregs = xmalloc(sizeof(*gpregs));
	if (!gpregs)
		goto err;
	user_aarch64_regs_entry__init(gpregs);

	gpregs->regs = xmalloc(31*sizeof(uint64_t));
	if (!gpregs->regs)
		goto err;
	gpregs->n_regs = 31;

	ti_aarch64->gpregs = gpregs;

	fpsimd = xmalloc(sizeof(*fpsimd));
	if (!fpsimd)
		goto err;
	user_aarch64_fpsimd_context_entry__init(fpsimd);
	ti_aarch64->fpsimd = fpsimd;
	fpsimd->vregs = xmalloc(64*sizeof(fpsimd->vregs[0]));
	fpsimd->n_vregs = 64;
	if (!fpsimd->vregs)
		goto err;

	return 0;
err:
	return -1;
}

#undef CORE_THREAD_ARCH_INFO
#define CORE_THREAD_ARCH_INFO(core) core->ti_aarch64
void arch_free_thread_info_aarch64(CoreEntry *core)
{
	if (CORE_THREAD_ARCH_INFO(core)) {
		if (CORE_THREAD_ARCH_INFO(core)->fpsimd) {
			xfree(CORE_THREAD_ARCH_INFO(core)->fpsimd->vregs);
			xfree(CORE_THREAD_ARCH_INFO(core)->fpsimd);
		}
		xfree(CORE_THREAD_ARCH_INFO(core)->gpregs->regs);
		xfree(CORE_THREAD_ARCH_INFO(core)->gpregs);
		xfree(CORE_THREAD_ARCH_INFO(core));
		CORE_THREAD_ARCH_INFO(core) = NULL;
	}
}

