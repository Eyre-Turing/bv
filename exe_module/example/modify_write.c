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

struct proc_backup_data {
	pid_t pid;
	char backup_buf[65536];
	long backup_size;
	struct proc_backup_data *next;
};

struct proc_backup_data *new_backup_data(struct proc_backup_data const *backup_data)
{
	struct proc_backup_data *ret;
	ret = (struct proc_backup_data *) malloc(sizeof(struct proc_backup_data));
	if (ret == NULL) {
		perror("malloc");
		return NULL;
	}
	ret->next = NULL;
	if (backup_data != NULL) {
		memcpy(ret, backup_data, sizeof(struct proc_backup_data));
	}
	return ret;
}

struct proc_backup_data *get_backup_data_pre(struct proc_backup_data *hair, pid_t pid)
{
	struct proc_backup_data *p = hair;
	if (p == NULL) {
		return NULL;
	}
	while (p->next) {
		if (p->next->pid == pid) {
			break;
		}
		p = p->next;
	}
	return p;
}

struct proc_backup_data *get_backup_data(struct proc_backup_data *hair, pid_t pid)
{
	struct proc_backup_data *ret;
	ret = get_backup_data_pre(hair, pid);
	if (ret == NULL) {
		return NULL;
	}
	return ret->next;
}

int put_backup_data(struct proc_backup_data *hair, struct proc_backup_data const *backup_data)
{
	struct proc_backup_data *p, *pn, *pnn = NULL;
	if (hair == NULL || backup_data == NULL) {
		return -1;
	}
	p = get_backup_data_pre(hair, backup_data->pid);
	if (p == NULL) {
		return -1;
	}
	pn = p->next;
	if (pn != NULL) {
		pnn = pn->next;
		memcpy(pn, backup_data, sizeof(struct proc_backup_data));
		pn->next = pnn;
	}
	else {
		pn = new_backup_data(backup_data);
		if (pn == NULL) {
			return -1;
		}
		p->next = pn;
		pn->next = NULL;
	}
	return 0;
}

struct proc_backup_data *take_backup_data(struct proc_backup_data *hair, pid_t pid)
{
	struct proc_backup_data *p, *ret;
	if (hair == NULL) {
		return NULL;
	}
	p = get_backup_data_pre(hair, pid);
	ret = p->next;
	if (ret == NULL) {
		return NULL;
	}
	p->next = ret->next;
	ret->next = NULL;
	return ret;
}

int free_backup_data(struct proc_backup_data *hair)
{
	struct proc_backup_data *p = hair, *pn;
	if (p == NULL) {
		return -1;
	}
	while (p != NULL) {
		pn = p->next;
		free(p);
		p = pn;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	char pid_str[16];
	pid_t pid = -1;
	pid_t child = -1;
	long child_long;
	int pipe_to_script[2], pipe_to_me[2];
	int status = 0;
	char *script = NULL;
	struct proc_backup_data backup_data;
	struct proc_backup_data *pid_backup_data;
	struct user_regs_struct regs;

	long fd, buf_addr, buf_size, buf_new_size;
	char buf_size_str[16];

	long n, i, data;
	char data_long_str[65536];
	char data_str[sizeof(long)];
	long write_size;

	DIR *dir;
	struct dirent *entry;
	char dir_str[128];

	if (argc < 3) {
		fprintf(stderr, "Usage: %s <pid> <script> [all_thread]\n", argv[0]);
		return 1;
	}

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

	put_backup_data(&backup_data, &( (struct proc_backup_data) {.pid = pid} ) );

	ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEFORK);

	ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

	while (1) {
		if ( (pid = wait(&status)) < 0 ) {
			break;
		}
		if (WIFEXITED(status)) {
			free(take_backup_data(&backup_data, pid));
		}

		if (! WIFSTOPPED(status)) {
			continue;
		}

		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		if ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)) ||
		     status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)) ||
		     status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8)) ) {
			ptrace(PTRACE_GETEVENTMSG, pid, NULL, &child_long);
			child = child_long;
			put_backup_data(&backup_data, &( (struct proc_backup_data) {.pid = child} ) );
		}
		else if ( regs.orig_rax == SYS_write &&
			    (pid_backup_data = get_backup_data(&backup_data, pid)) != NULL ) {
			if (regs.rax == -ENOSYS) {
				fd = regs.rdi;
				buf_addr = regs.rsi;
				buf_size = regs.rdx;

				if (buf_size > sizeof(pid_backup_data->backup_buf)) {
					fprintf(stderr, "buf_size too long (%ld), skip\n", buf_size);
					ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
					continue;
				}

				snprintf(pid_str, sizeof(pid_str), "%d", pid);
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

				pid_backup_data->backup_size = 0;
				buf_new_size = 0;

				i = 0;
				while ( (n = read(pipe_to_me[0], data_long_str + i, sizeof(data_long_str) - i)) > 0 ) {
					n += i;
					for (i = 0; i + sizeof(long) <= n; i += sizeof(long)) {
						data = ptrace(PTRACE_PEEKDATA, pid, buf_addr + pid_backup_data->backup_size, NULL);
						memcpy(pid_backup_data->backup_buf + pid_backup_data->backup_size, &data, sizeof(long));
						memcpy(&data, data_long_str + i, sizeof(long));
						ptrace(PTRACE_POKEDATA, pid, buf_addr + pid_backup_data->backup_size, data);
						pid_backup_data->backup_size += sizeof(long);
						buf_new_size += sizeof(long);
					}
					if (i < n) {
						if (i > 0) {
							memcpy(data_long_str, data_long_str + i, sizeof(long));
						}
						i = n - i;
					}
					else {
						i = 0;
					}
				}
				if (i > 0) {
					data = ptrace(PTRACE_PEEKDATA, pid, buf_addr + pid_backup_data->backup_size, NULL);
					memcpy(pid_backup_data->backup_buf + pid_backup_data->backup_size, &data, sizeof(long));
					memcpy(&data, data_long_str, sizeof(long));
					ptrace(PTRACE_POKEDATA, pid, buf_addr + pid_backup_data->backup_size, data);
					pid_backup_data->backup_size += sizeof(long);
					buf_new_size += i;
				}

				close(pipe_to_me[0]);

				waitpid(child, NULL, 0);

				regs.rdx = buf_new_size;
				ptrace(PTRACE_SETREGS, pid, NULL, &regs);
			}
			else {
				if (buf_size > sizeof(pid_backup_data->backup_buf)) {
					ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
					continue;
				}
				for (i = 0; i < pid_backup_data->backup_size; i += sizeof(long)) {
					memcpy(&data, pid_backup_data->backup_buf + i, sizeof(long));
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
