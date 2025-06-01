// 这个例子里将表演如何将读取到的任何信息都作大写转小写的操作

#include <bv.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <stdint.h>
#include <errno.h>

BV_SYSCALL(0)	// 0 means SYS_read
{
	struct user_regs_struct regs;
	char buf[9];
	long i, j;
	long data;
	int buf_len;

	// target_pid

	if (ptrace(PTRACE_GETREGS, target_pid, NULL, &regs) == -1) {
		perror("ptrace PTRACE_GETREGS");
		return ;
	}

	// regs.rdi, regs.rsi, regs.rdx
	if (regs.rax == -ENOSYS) {
		fprintf(stderr, "target_pid: %d\n", target_pid);
		fprintf(stderr, "read(%d, \"", regs.rdi);
	}
	else {
		for (i = 0; i < (int64_t) regs.rax; i += 8) {
			data = ptrace(PTRACE_PEEKDATA, target_pid, regs.rsi + i, NULL);
			if (regs.rax -i >= 8) {
				buf_len = 8;
			}
			else {
				buf_len = regs.rax - i;
				
			}
			memcpy(buf, &data, buf_len);
			buf[buf_len] = 0;
			fprintf(stderr, "%s", buf);
			for (j = 0; j < buf_len; ++j) {
				if (buf[j] >= 'A' && buf[j] <= 'Z') {
					buf[j] = buf[j] - 'A' + 'a';
				}
			}
			memcpy(&data, buf, buf_len);
			if (ptrace(PTRACE_POKEDATA, target_pid, regs.rsi + i, data) == -1) {
				perror("ptrace PTRACE_POKEDATA");
			}
		}
		fprintf(stderr, "\", %d) = %ld\n", regs.rdx, (int64_t) regs.rax);
	}
}
