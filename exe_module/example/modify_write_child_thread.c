#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

int main(int argc, char *argv[])
{
	char *pid_str = NULL;
	pid_t pid = -1;
	pid_t child = -1;
	char child_str[16];
	int pipe_to_script[2], pipe_to_me[2];
	int status = 0;
	char *script = NULL;
	char backup_buf[65536];
	long backup_size = 0;
	struct user_regs_struct regs;

	long fd, buf_addr, buf_size, buf_new_size;
	char buf_size_str[16];

	long n, i, data;
	char data_str[sizeof(long)];
	long write_size;

	DIR *dir;
	struct dirent *entry;
	char dir_str[128];

	if (argc < 3) {
		fprintf(stderr, "Usage: %s <pid> <script> [all_thread]\n", argv[0]);
		return 1;
	}

	pid_str = argv[1];
	if (sscanf(argv[1], "%d", &pid) != 1) {
		fprintf(stderr, "pid format error\n");
		return 1;
	}

	script = argv[2];

	if (argc >= 4) {
		// attach all thread
		snprintf(dir_str, sizeof(dir_str), "/proc/%d/task", pid);
		dir = opendir(dir_str);
		if (dir == NULL) {
			perror("opendir");
			return 1;
		}

		i = 0;
		while ( (entry = readdir(dir)) != NULL ) {
			if (entry->d_name[0] != '.') {
				fprintf(stderr, "add thread: %s\n", entry->d_name);
				++i;
				child = fork();
				if (child == 0) {
					execl(argv[0], argv[0], entry->d_name, argv[2], NULL);
					_exit(127);
				}
			}
		}

		closedir(dir);

		while (i > 0) {
			wait(&status);
			if (WIFEXITED(status)) {
				--i;
			}
		}

		return 0;
	}

	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
		perror("ptrace PTRACE_ATTACH");
		return 1;
	}

	if (waitpid(pid, &status, 0) != pid) {
		perror("waitpid");
		return 1;
	}
	if (WIFEXITED(status)) {
		return 0;
	}
	if (! WIFSTOPPED(status)) {
		return 1;
	}

	ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

	while (1) {
		if (wait(&status) != pid) {
			continue;
		}
		if (WIFEXITED(status)) {
			break;
		}

		if (! WIFSTOPPED(status)) {
			continue;
		}

		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		if (regs.orig_rax == SYS_clone || regs.orig_rax == SYS_vfork || regs.orig_rax == SYS_fork) {
			fprintf(stderr, "orig_rax: %ld, rax: %ld\n", regs.orig_rax, regs.rax);
			if (regs.rax != -ENOSYS) {
				child = regs.rax;
				snprintf(child_str, sizeof(child_str), "%ld", child);
				child = fork();
				if (child == 0) {
					execl(argv[0], argv[0], child_str, argv[2], NULL);
					_exit(127);
				}
			}
		}
		else if (regs.orig_rax == SYS_write) {
			if (regs.rax == -ENOSYS) {
				fd = regs.rdi;
				buf_addr = regs.rsi;
				buf_size = regs.rdx;

				if (buf_size > sizeof(backup_buf)) {
					fprintf(stderr, "buf_size too long (%ld), skip\n", buf_size);
					ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
					continue;
				}

				snprintf(buf_size_str, sizeof(buf_size_str), "%ld", buf_size);

				pipe(pipe_to_script);
				pipe(pipe_to_me);

				child = fork();
				if (child == 0) {
					close(pipe_to_script[1]);
					close(pipe_to_me[0]);
					dup2(pipe_to_script[0], 0);
					dup2(pipe_to_me[1], 1);
					close(pipe_to_script[0]);
					close(pipe_to_me[1]);
					execl(script, script, pid_str, buf_size_str, NULL);
					_exit(127);
				}

				close(pipe_to_script[0]);
				close(pipe_to_me[1]);

				fprintf(stderr, "write(%ld, \"", fd);

				for (i = 0; i < buf_size; i += sizeof(long)) {
					data = ptrace(PTRACE_PEEKDATA, pid, buf_addr + i, NULL);
					memcpy(data_str, &data, sizeof(long));
					write_size = sizeof(long);
					if (buf_size - i < write_size) {
						write_size = buf_size - i;
					}
					write(pipe_to_script[1], data_str, write_size);
					write(2, data_str, write_size);
				}

				fprintf(stderr, "\", %ld)", buf_size);

				close(pipe_to_script[1]);

				backup_size = 0;
				buf_new_size = 0;
				while ( (n = read(pipe_to_me[0], data_str, sizeof(long))) > 0 ) {
					data = ptrace(PTRACE_PEEKDATA, pid, buf_addr + backup_size, NULL);
					memcpy(backup_buf + backup_size, &data, sizeof(long));
					memcpy(&data, data_str, sizeof(long));
					ptrace(PTRACE_POKEDATA, pid, buf_addr + backup_size, data);
					backup_size += sizeof(long);
					buf_new_size += n;
				}

				close(pipe_to_me[0]);

				waitpid(child, NULL, 0);

				regs.rdx = buf_new_size;
				ptrace(PTRACE_SETREGS, pid, NULL, &regs);
			}
			else {
				if (buf_size > sizeof(backup_buf)) {
					ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
					continue;
				}
				for (i = 0; i < backup_size; i += sizeof(long)) {
					memcpy(&data, backup_buf + i, sizeof(long));
					ptrace(PTRACE_POKEDATA, pid, buf_addr + i, data);
				}
				regs.rax = buf_size;
				ptrace(PTRACE_SETREGS, pid, NULL, &regs);
				fprintf(stderr, " = %ld\n", buf_size);
			}
		}

		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
	}

	return 0;
}
