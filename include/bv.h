#ifndef __BV_H__
#define __BV_H__

#define BV_SYSCALL_LIST_SIZE	1024
extern int bv_syscall_list[BV_SYSCALL_LIST_SIZE];

/*
 * bv_syscall_list like:
 * {4, 1, 0, 2}, means to ptrace: SYS_stat, SYS_write, SYS_read, SYS_open
 */

extern int bv_syscall_list_len;

#define BV_SYSCALL(SYS_NUM)								\
static void __attribute__((constructor)) _set_bv_syscall_##SYS_NUM()	\
{												\
	bv_syscall_list[bv_syscall_list_len++] = SYS_NUM;				\
}												\
void bv_syscall_##SYS_NUM(pid_t target_pid)


#endif
