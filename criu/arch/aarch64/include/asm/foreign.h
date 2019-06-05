
// Antonio Barbalace, Stevens 2019

// to support multiple conversion into a foreign architecture, aarch64 version



// identity mapping :-)
int get_task_regs_size_aarch64() {
	return 0;
}
static inline int save_task_regs_aarch64(void *x, unsigned long *values) {
	return 0;
}
static inline int arch_alloc_thread_info_aarch64(CoreEntry *core) {
	return 0;
}
	
static inline void arch_free_thread_info_aarch64(CoreEntry *core){}



int get_task_regs_size_x86_64();
int save_task_regs_x86_64(void *x, unsigned long *values);
int arch_alloc_thread_info_x86_64(CoreEntry *core);
void arch_free_thread_info_x86_64(CoreEntry *core);
