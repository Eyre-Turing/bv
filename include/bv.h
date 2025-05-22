#ifndef __BV_H__
#define __BV_H__

#include <unistd.h>

#define BV_SYSCALL_LIST_SIZE	1024
extern int *bv_syscall_list;

/*
 * bv_syscall_list like:
 * {4, 1, 0, 2}, means to ptrace: SYS_stat, SYS_write, SYS_read, SYS_open
 */

extern int bv_syscall_list_len;

void _init_var();

#define BV_SYSCALL(SYS_NUM)								\
void __attribute__((constructor)) _set_bv_syscall_##SYS_NUM()			\
{												\
	if (bv_syscall_list == NULL) {							\
		_init_var();								\
	}											\
	bv_syscall_list[bv_syscall_list_len++] = SYS_NUM;				\
}												\
void bv_syscall_##SYS_NUM(pid_t target_pid)


#endif
