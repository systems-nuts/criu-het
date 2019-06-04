
/* Antonio Barbalace, Stevens 2019 */

//TODO TODO TODO we should integrate this in a better way ... such as trick used in musl to redefine and include another source (this is the original criu/arch/x86_64/crtools.c modified)


#include "compel/asm/fpu.h"
#include "compel/compel.h"
#include "compel/plugins/std/syscall-codes.h"
#include "cpu.h"
#include "cr_options.h"
#include "images/core.pb-c.h"
#include "log.h"
#include "protobuf.h"
#include "types.h"

#include "asm/compat.h"

#include "asm/foreign.h"

#define XSAVE_PB_NELEMS(__s, __obj, __member)		\
	(sizeof(__s) / sizeof(*(__obj)->__member))

int save_task_regs_x86_64(void *x, unsigned long * values)
{
	CoreEntry *core = x;
	UserX86RegsEntry *gpregs;

	if (core)
		gpregs = core->thread_info->gpregs;
	else
		return -1;
	
	// first value is the magic number;
	values++;
	
	gpregs->rip = *values++;
	gpregs->rax = *values++;
	gpregs->rdx = *values++;
	gpregs->rcx = *values++;
	gpregs->rbx = *values++;
	gpregs->rsi = *values++;
	gpregs->rdi = *values++;
	gpregs->rbp = *values++;
	gpregs->rsp = *values++;
	gpregs->r8 = *values++;
	gpregs->r9 = *values++;
	gpregs->r10 = *values++;
	gpregs->r11 = *values++;
	gpregs->r12 = *values++;
	gpregs->r13 = *values++;
	gpregs->r14 = *values++;
	gpregs->r15 = *values++;

	gpregs->mode = USER_X86_REGS_MODE__NATIVE;
	gpregs->has_mode = true;

	// copied from /lib/py/het.py
	core->thread_info->fpregs->cwd = 895;
	core->thread_info->fpregs->swd = 0x00;
	core->thread_info->fpregs->twd = 0x00;
	core->thread_info->fpregs->fop = 0x00;
	core->thread_info->fpregs->rip = 5248671;
	core->thread_info->fpregs->rdp = 140735536563788;
	core->thread_info->fpregs->mxcsr = 8064;
	core->thread_info->fpregs->mxcsr_mask = 65535;
		
	/* Make sure we have enough space */
	BUG_ON(core->thread_info->fpregs->n_st_space != (8*sizeof(double)));
	BUG_ON(core->thread_info->fpregs->n_xmm_space != (16 * 2 * sizeof(long)));

	values += 8;
	memcpy(core->thread_info->fpregs->xmm_space, values, 16 * 2 * sizeof(long));
	values += (16*2);
	memcpy(core->thread_info->fpregs->st_space, values, 8 * sizeof(double));
	values += (8*2);

	int * ivalues = (int*) values;
	gpregs->cs = *ivalues++;
	gpregs->ss = *ivalues++;
	gpregs->ds = *ivalues++;
	gpregs->es = *ivalues++;
	gpregs->fs = *ivalues++;
	gpregs->gs = *ivalues++;
	values = (long*) ivalues;
	gpregs->flags = *values++;
	
	return 0;
}

static void alloc_tls(ThreadInfoX86 *ti, void **mempool)
{
	int i;

	ti->tls = xptr_pull_s(mempool, GDT_ENTRY_TLS_NUM*sizeof(UserDescT*));
	ti->n_tls = GDT_ENTRY_TLS_NUM;
	for (i = 0; i < GDT_ENTRY_TLS_NUM; i++) {
		ti->tls[i] = xptr_pull(mempool, UserDescT);
		user_desc_t__init(ti->tls[i]);
	}
}

static int alloc_xsave_extends(UserX86XsaveEntry *xsave)
{
//	if (compel_fpu_has_feature(XFEATURE_YMM)) {
		xsave->n_ymmh_space	= XSAVE_PB_NELEMS(struct ymmh_struct, xsave, ymmh_space);
		xsave->ymmh_space	= xzalloc(pb_repeated_size(xsave, ymmh_space));
		if (!xsave->ymmh_space)
			goto err;
//	}

//	if (compel_fpu_has_feature(XFEATURE_BNDREGS)) {
		xsave->n_bndreg_state	= XSAVE_PB_NELEMS(struct mpx_bndreg_state, xsave, bndreg_state);
		xsave->bndreg_state	= xzalloc(pb_repeated_size(xsave, bndreg_state));
		if (!xsave->bndreg_state)
			goto err;
//	}

//	if (compel_fpu_has_feature(XFEATURE_BNDCSR)) {
		xsave->n_bndcsr_state	= XSAVE_PB_NELEMS(struct mpx_bndcsr_state, xsave, bndcsr_state);
		xsave->bndcsr_state	= xzalloc(pb_repeated_size(xsave, bndcsr_state));
		if (!xsave->bndcsr_state)
			goto err;
//	}

//	if (compel_fpu_has_feature(XFEATURE_OPMASK)) {
		xsave->n_opmask_reg	= XSAVE_PB_NELEMS(struct avx_512_opmask_state, xsave, opmask_reg);
		xsave->opmask_reg	= xzalloc(pb_repeated_size(xsave, opmask_reg));
		if (!xsave->opmask_reg)
			goto err;
//	}

//	if (compel_fpu_has_feature(XFEATURE_ZMM_Hi256)) {
		xsave->n_zmm_upper	= XSAVE_PB_NELEMS(struct avx_512_zmm_uppers_state, xsave, zmm_upper);
		xsave->zmm_upper	= xzalloc(pb_repeated_size(xsave, zmm_upper));
		if (!xsave->zmm_upper)
			goto err;
//	}

/	if (compel_fpu_has_feature(XFEATURE_Hi16_ZMM)) {
		xsave->n_hi16_zmm	= XSAVE_PB_NELEMS(struct avx_512_hi16_state, xsave, hi16_zmm);
		xsave->hi16_zmm		= xzalloc(pb_repeated_size(xsave, hi16_zmm));
		if (!xsave->hi16_zmm)
			goto err;
//	}

//	if (compel_fpu_has_feature(XFEATURE_PKRU)) {
		xsave->n_pkru		= XSAVE_PB_NELEMS(struct pkru_state, xsave, pkru);
		xsave->pkru		= xzalloc(pb_repeated_size(xsave, pkru));
		if (!xsave->pkru)
			goto err;
//	}

	return 0;
err:
	return -1;
}

int arch_alloc_thread_info_x86_64(CoreEntry *core)
{
	size_t sz;
	bool with_fpu, with_xsave = false;
	void *m;
	ThreadInfoX86 *ti = NULL;


	with_fpu = true;

	sz = sizeof(ThreadInfoX86) + sizeof(UserX86RegsEntry) +
		GDT_ENTRY_TLS_NUM*sizeof(UserDescT) +
		GDT_ENTRY_TLS_NUM*sizeof(UserDescT*);
	if (with_fpu) {
		sz += sizeof(UserX86FpregsEntry);
		with_xsave = true;
		if (with_xsave)
			sz += sizeof(UserX86XsaveEntry);
	}

	m = xmalloc(sz);
	if (!m)
		return -1;

	ti = core->thread_info = xptr_pull(&m, ThreadInfoX86);
	thread_info_x86__init(ti);
	ti->gpregs = xptr_pull(&m, UserX86RegsEntry);
	user_x86_regs_entry__init(ti->gpregs);
	alloc_tls(ti, &m);

	if (with_fpu) {
		UserX86FpregsEntry *fpregs;

		fpregs = ti->fpregs = xptr_pull(&m, UserX86FpregsEntry);
		user_x86_fpregs_entry__init(fpregs);

		/* These are numbers from kernel */
		fpregs->n_st_space	= 32;
		fpregs->n_xmm_space	= 64;

		fpregs->st_space	= xzalloc(pb_repeated_size(fpregs, st_space));
		fpregs->xmm_space	= xzalloc(pb_repeated_size(fpregs, xmm_space));

		if (!fpregs->st_space || !fpregs->xmm_space)
			goto err;

		if (with_xsave) {
			UserX86XsaveEntry *xsave;

			xsave = fpregs->xsave = xptr_pull(&m, UserX86XsaveEntry);
			user_x86_xsave_entry__init(xsave);

			if (alloc_xsave_extends(xsave))
				goto err;
		}
	}

	return 0;
err:
	return -1;
}

void arch_free_thread_info_x86_64(CoreEntry *core)
{
	if (!core->thread_info)
		return;

	if (core->thread_info->fpregs->xsave) {
		xfree(core->thread_info->fpregs->xsave->ymmh_space);
		xfree(core->thread_info->fpregs->xsave->pkru);
		xfree(core->thread_info->fpregs->xsave->hi16_zmm);
		xfree(core->thread_info->fpregs->xsave->zmm_upper);
		xfree(core->thread_info->fpregs->xsave->opmask_reg);
		xfree(core->thread_info->fpregs->xsave->bndcsr_state);
		xfree(core->thread_info->fpregs->xsave->bndreg_state);
	}

	xfree(core->thread_info->fpregs->st_space);
	xfree(core->thread_info->fpregs->xmm_space);
	xfree(core->thread_info);
}
