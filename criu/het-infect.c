#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>
#include <fcntl.h>
#include "util.h"
#include <compel/compel.h>

const int long_size = sizeof(int);
long getdata(pid_t pid, long addr)
{   
	pr_info("%s: pid %d addr %ld\n", __func__, pid, addr);
	return ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
}

int putdata(pid_t pid, long addr, long data)
{
	pr_info("%s: pid %d addr %ld data %ld\n", __func__, pid, addr, data);
	return ptrace(PTRACE_POKEDATA, pid, addr, (void*) data);
}

int cfileexists(const char* filename){
    struct stat buffer;
    int exist = stat(filename,&buffer);
    if(exist == 0)
        return 0;
    else // -1
        return 0;
}

/*****************************************************************/
long get_symbol_address(const char* path_to_bin, const char* searched_symbol);

static char* get_binary_path(int pid)
{
	ssize_t ret;
	#define MAXPATH 2048
	static char binary_path[MAXPATH];
	static char exe_path[64];

	sprintf(exe_path, "/proc/%d/exe", pid);
	//pr_info("%s: proc exec path is %s\n", __func__, exe_path);
	printf("%s: proc exec path is %s\n", __func__, exe_path);
	ret = readlink(exe_path, binary_path, MAXPATH);
	if(ret<=0)
		return NULL;
	binary_path[ret]='\0';
	return binary_path;
}

#if 0
static int __popcorn_interrrupt_task(int pid)
{
	long ret;


	ret = ptrace(PTRACE_ATTACH, pid, NULL, 0);
	if (ret) {
		/*
		 * ptrace API doesn't allow to distinguish
		 * attaching to zombie from other errors.
		 * All errors will be handled in compel_wait_task().
		 */
		pr_warn("Unable to interrupt task: %d (%s)\n", pid, strerror(errno));
		return ret;
	}

	 wait(NULL);
	 pr_info("The process stopped a first time %d, %lx\n", pid, addr);

	 /* Put one in the variable */
	 putdata(pid, addr, 1);
	 ret_data = getdata(pid, addr);
	 pr_info("ret data %ld\n", ret_data);

	 /* Cont. for the process to do stack transformation */
	 ptrace(PTRACE_CONT, pid, NULL, NULL);
	 /* Wait stack transformation: alarm */
	 wait(NULL);
	 pr_info("The process stopped a second time\n");
	 ret_data = getdata(pid, addr);
	 pr_info("ret data %ld\n", ret_data);

	 ret=ptrace(PTRACE_CONT, pid, NULL, NULL);
	 ret|=ptrace(PTRACE_DETACH, pid,
			  NULL, NULL);
	return ret;
}
#else

static int __popcorn_interrrupt_task(int pid)
{
	long ret;


	ret = ptrace(PTRACE_SEIZE, pid, NULL, 0);
	if (ret) {
		/*
		 * ptrace API doesn't allow to distinguish
		 * attaching to zombie from other errors.
		 * All errors will be handled in compel_wait_task().
		 */
		pr_warn("Unable to interrupt task: %d (%s)\n", pid, strerror(errno));
		return ret;
	}

	ret = ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
	if (ret < 0) {
		pr_warn("SEIZE %d: can't interrupt task: %s\n", pid, strerror(errno));
		if (ptrace(PTRACE_DETACH, pid, NULL, NULL))
			pr_perror("Unable to detach from %d", pid);
	}

	return ret;
}


#endif

int parse_pid_status(pid_t pid, struct seize_task_status *ss, void *data);
static int __popcorn_wait_task(int pid, long addr, int target_id)
{
	int ret;
	int status;
	//struct seize_task_status ss;

	//first wait we assume SIGTRAP: todo check!
    	pr_info("Wating for the process to stop a first time %d; addr %lx; target arch %d\n", pid, addr, target_id);
	//ret = compel_wait_task(pid, -1, parse_pid_status, NULL, &ss, NULL); //wait4(pid, &status, __WALL, NULL);
	ret = wait4(pid, &status, __WALL, NULL);
	if (ret < 0) {
		/*
		 * wait4() can expectedly fail only in a first time
		 * if a task is zombie. If we are here from try_again,
		 * this means that we are tracing this task.
		 *
		 * So here we can be only once in this function.
		 */
		pr_err("error in %s\n", __func__);
	}
    	pr_info("The process stopped a first time pid %d; addr %lx; target arch %d (ret %d)\n", pid, addr, target_id, ret);

	/* Put one in the variable */
	ret=putdata(pid, addr, target_id);
	if(ret) perror("putdata");

	//cont. interrupt
	if (ptrace(PTRACE_CONT, pid, NULL, NULL)) {
		pr_info("Can't continue");
	}
	
	status=0;
	do{
		printf("waiting stack transformation...\n");
		//second wait: wait for the cond below otherwise continue
		ret=waitpid(pid, &status, __WALL);
		if (ret < 0){
			pr_err("%s:%s:%d error waitpid", __FILE__, __func__, __LINE__);
			goto err;
		}
		if (WIFEXITED(status))
		{
			pr_err("Task exited with %d\n", WEXITSTATUS(status));
			goto err;
		}
		else if(WIFSTOPPED(status))
		{
			int sig=WSTOPSIG(status);
			if(sig == SIGALRM && (getdata(pid, addr))==-1) {
				printf("Stack transformation done\n");
				break;
			}else{ 
				printf("Putting signal %d\n", sig);
				if (ptrace(PTRACE_CONT, pid, NULL, (void*)(long)sig)) {
					pr_info("Can't continue");
				}
			}
		}else if (WIFSIGNALED(status))
		{
			pr_err("Task signaled with %d: %s\n",
				WTERMSIG(status), strsignal(WTERMSIG(status)));
		}
	}while(1);

	//cont. interrupt
	if (ptrace(PTRACE_CONT, pid, NULL, NULL)) {
		pr_info("Can't continue");
	}
	ret = ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
	if (ret < 0) {
		pr_warn("SEIZE %d: can't interrupt task: %s\n", pid, strerror(errno));
		if (ptrace(PTRACE_DETACH, pid, NULL, NULL))
			pr_perror("Unable to detach from %d", pid);
	}

	return ret;
err:
	return -1;
}

int get_target_id(char* target_str)
{
	if(!strcmp(target_str, "aarch64"))
		return 0;
	if(!strcmp(target_str, "x86_64"))
		return 1;
	pr_info("WARN: Unknown architecture %s. defaulting to aarch64\n", target_str);
	return 0;
}


#define MIGRATION_GBL_VARIABLE "__migrate_gb_variable"
int popcorn_interrrupt_task(int pid, char* target_str)
{
	int ret = 0;
	long addr;
	char* bin_file;

	bin_file=get_binary_path(pid);
	if(!bin_file)
	{
		pr_warn("Unable to read bin path\n");
		return -1;
	}
	
	pr_info("binary path of process %d is %s\n", pid, bin_file);
	if(cfileexists(bin_file))
	{
		pr_warn("Binary file not found");
		return -1;
	}else
		pr_info("Binary file exist! %s\n", bin_file);

	int target_id = get_target_id(target_str);
	addr = get_symbol_address(bin_file, MIGRATION_GBL_VARIABLE);
	ret = __popcorn_interrrupt_task(pid);
	ret |= __popcorn_wait_task(pid, addr, target_id);
	return ret;
}

/*****************************************************************/
int popcorn_signal_stack_transform_pid(pid_t pid, char* target_arch)
{
	int ret = 0;
	long addr;
	char* bin_file;

	bin_file=get_binary_path(pid);
	if(!bin_file)
	{
		pr_warn("Unable to read bin path\n");
		return -1;
	}
	
	pr_info("binary path of process %d is %s\n", pid, bin_file);
	if(cfileexists(bin_file))
	{
		pr_warn("Binary file not found");
		return -1;
	}else
		pr_info("Binary file exist! %s\n", bin_file);

	int target_id = get_target_id(target_arch);
	addr = get_symbol_address(bin_file, MIGRATION_GBL_VARIABLE);
	ret=putdata(pid, addr, target_id);
	if(ret) 
		perror("putdata");

	return 0;
}
