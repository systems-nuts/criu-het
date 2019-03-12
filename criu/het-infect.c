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
long get_sym_addr(char* bin_file, char* sym)
{
	FILE *fp;
	char buff[256];
	char cmd[128];
	char nm_path[]="/usr/bin/nm";

	if(cfileexists(nm_path))
	{
		pr_warn("NM Binary not found");
		return -1;
	}else
		pr_info("NM Binary exist %s\n", nm_path);

	/* Open the command for reading. */
	sprintf(cmd, "%s %s", nm_path, bin_file);
	fp = popen(cmd, "r");
	if (fp == NULL) {
		pr_info("Failed to run command\n" );
		return -1;
	}

	char* addr_str=NULL;
	char* name;
	/* Read the output a line at a time - output it. */
	while (fgets(buff, sizeof(buff)-1, fp) != NULL) {
		pr_info("current symbol %s", buff);
		addr_str = strtok(buff, " ");
		strtok(NULL, " ");//skip type
		name = strtok(NULL, " ");
		if(name && strncmp(sym, name, strlen(sym))==0)
			break;
	}

	/* close */
	pclose(fp);

	if(addr_str)
		return strtol(addr_str, NULL, 16);
	return -1;
}


static char* get_binary_path(int pid)
{
	ssize_t ret;
	#define MAXPATH 2048
	static char binary_path[MAXPATH];
	static char exe_path[64];

	sprintf(exe_path, "/proc/%d/exe", pid);
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

static int __popcorn_wait_task(int pid, long addr, int target_id)
{
	int ret;

	//first wait we assume SIGTRAP: todo check!
    	wait(NULL);
    	pr_info("The process stopped a first time pid %d; addr %lx; target arch %d\n", pid, addr, target_id);

	/* Put one in the variable */
	ret=putdata(pid, addr, target_id);
	if(ret) perror("putdata");

	//cont. interrupt
	if (ptrace(PTRACE_CONT, pid, NULL, NULL)) {
		pr_info("Can't continue");
	}
	
	int status=0;
	do{
		//second wait: wait for the cond below otherwise continue
		ret=waitpid(pid, &status, __WALL);
		if (ret < 0){
			perror("error waitpid\n");
			goto err;
		}
		if(WIFSTOPPED(status))
		{
			int sig=WSTOPSIG(status);
			if(sig == SIGALRM && (getdata(pid, addr))==-1) {
				break;
			}else 
				if (ptrace(PTRACE_CONT, pid, NULL, (void*)(long)sig)) {
					pr_info("Can't continue");
				}
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
		pr_warn("Unable to read bin path");
		return -1;
	}
	
	pr_info("binary path of process %d is %s\n", pid, bin_file);
	if(cfileexists(bin_file))
	{
		pr_warn("Binary file not found");
		return -1;
	}else
		pr_info("Binary file exist %s\n", bin_file);
	int target_id = get_target_id(target_str);
	ret = __popcorn_interrrupt_task(pid);
	addr = get_sym_addr(bin_file, MIGRATION_GBL_VARIABLE);
	ret |= __popcorn_wait_task(pid, addr, target_id);
	return ret;
}

/*****************************************************************/
