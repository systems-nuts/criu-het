
// Antonio Barbalace, Stevens 2019

// to support multiple conversion into a foreign architecture, x86_64 version



// identity mapping :-)
static inline int save_task_regs_x86_64(void *x, unsigned long *values) {
	return 0;
}
static inline int arch_alloc_thread_info_x86_64(CoreEntry *core) {
	return 0;
}
	
static inline void arch_free_thread_info_x86_64(CoreEntry *core){}



int save_task_regs_aarch64(void *x, unsigned long *values);
int arch_alloc_thread_info_aarch64(CoreEntry *core);
void arch_free_thread_info_aarch64(CoreEntry *core);
