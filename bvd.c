#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <pthread.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#define BVD_UNIX_SOCKET_PATH	"/run/bvd/bvd.sock"

pid_t self_pid = -1;

int temp_request;
pid_t temp_target_pid;

#define BV_SYSCALL_LIST_SIZE	1024
typedef void (*bv_syscall_type)(pid_t target_pid);
bv_syscall_type bv_syscall[BV_SYSCALL_LIST_SIZE] = { NULL };

/*
 * bv_syscall[0] means: SYS_read ptrace function
 * bv_syscall[1] means: SYS_write ptrace function
 * and so on
 */

pthread_mutex_t ptrace_mutex;

pid_t ready_to_detach_pids[1024];
int ready_to_detach_pids_len = 0;

int load_bv_syscall_module(const char *so_path)
{
	void *dl_hdl;
	int (*bv_syscall_list)[];
	int *bv_syscall_list_len;
	int i;
	char buf[1024];

	fprintf(stderr, "ready to load module: \"%s\"\n", so_path);

	dl_hdl = dlopen(so_path, RTLD_LAZY);
	if (dl_hdl == NULL) {
		fprintf(stderr, "dlopen: %s\n", dlerror());
		return 1;
	}

	bv_syscall_list = (int (*)[]) dlsym(dl_hdl, "bv_syscall_list");
	bv_syscall_list_len = (int *) dlsym(dl_hdl, "bv_syscall_list_len");

	if (bv_syscall_list == NULL || bv_syscall_list_len == NULL) {
		fprintf(stderr, "dlsym: %s\n", dlerror());
		dlclose(dl_hdl);
		return 1;
	}

	pthread_mutex_lock(&ptrace_mutex);
	for (i = 0; i < *bv_syscall_list_len; ++i) {
		sprintf(buf, "bv_syscall_%d", (*bv_syscall_list)[i]);
		bv_syscall[ (*bv_syscall_list)[i] ] = (void (*)(pid_t)) dlsym(dl_hdl, buf);
		if ( bv_syscall[ (*bv_syscall_list)[i] ] == NULL ) {
			fprintf(stderr, "dlsym: %s\n", dlerror());
		}
	}
	pthread_mutex_unlock(&ptrace_mutex);

	return 0;
}

int add_pid(pid_t target_pid)
{
	fprintf(stderr, "ready to add pid: %d\n", target_pid);

	temp_request = PTRACE_ATTACH;
	temp_target_pid = target_pid;
	kill(self_pid, SIGUSR1);

	return 0;
}

int remove_bv_syscall(int sys_num)
{
	fprintf(stderr, "ready to remove bv syscall: %d\n", sys_num);

	pthread_mutex_lock(&ptrace_mutex);
	bv_syscall[sys_num] = NULL;
	pthread_mutex_unlock(&ptrace_mutex);

	return 0;
}

int remove_pid(pid_t target_pid)
{
	fprintf(stderr, "ready to remove pid: %d\n", target_pid);

	temp_request = PTRACE_DETACH;
	temp_target_pid = target_pid;
	kill(self_pid, SIGUSR1);

	return 0;
}

int check_and_mkdirs(const char *dir)
{
	char parent_dir[1024];
	fprintf(stderr, "check_and_mkdirs: \"%s\"\n", dir);
	if (access(dir, F_OK) != 0) {
		strcpy(parent_dir, dir);
		dirname(parent_dir);
		if (check_and_mkdirs(parent_dir) != 0) {
			return -1;
		}
		if (mkdir(dir, 0755) != 0) {
			perror("mkdir");
			return -1;
		}
	}
	return 0;
}

#define MY_WRITE(fd, str_data) write(fd, str_data, strlen(str_data))

void signal_hdl(int sig)
{
	if (sig == SIGPIPE) {
		fprintf(stderr, "pid: %d, recv a SIGPIPE signal\n", getpid());
	}
	else if (sig == SIGUSR1) {
		fprintf(stderr, "pid: %d, recv a SIGUSER1 signal\n", getpid());
		if (getpid() == self_pid) {
			if (temp_request == PTRACE_ATTACH) {
				fprintf(stderr, "ready to PTRACE_ATTACH %d\n", temp_target_pid);
				pthread_mutex_lock(&ptrace_mutex);
				if (ptrace(PTRACE_ATTACH, temp_target_pid, NULL, NULL) == -1) {
					perror("ptrace PTRACE_ATTACH");
				}
				while (waitpid(temp_target_pid, NULL, 0) != temp_target_pid);
				if (ptrace(PTRACE_SYSCALL, temp_target_pid, NULL, NULL) == -1) {
					perror("ptrace PTRACE_SYSCALL");
				}
				pthread_mutex_unlock(&ptrace_mutex);
			}
			else if (temp_request == PTRACE_DETACH) {
				fprintf(stderr, "ready to PTRACE_DETACH %d\n", temp_target_pid);
				pthread_mutex_lock(&ptrace_mutex);
				ready_to_detach_pids[ready_to_detach_pids_len++] = temp_target_pid;
				pthread_mutex_unlock(&ptrace_mutex);
			}
		}
	}
}

void *read_cmd(void *param)
{
	char bvd_unix_socket_dir[1024];
	int sockfd, peerfd;
	struct sockaddr_un addr, peeraddr;
	int peeraddr_len;
	char buf[1024];
	int i, n;
	int zero_flag = 0;

	strcpy(bvd_unix_socket_dir, BVD_UNIX_SOCKET_PATH);
	dirname(bvd_unix_socket_dir);

	fprintf(stderr, "bvd unix socket path: %s\nbvd unix socket dir: %s\n", BVD_UNIX_SOCKET_PATH, bvd_unix_socket_dir);
	if (check_and_mkdirs(bvd_unix_socket_dir) != 0) {
		fprintf(stderr, "could not use bvctl, bvd unix socket dir not found, and could not create!\n");
		return ;
	}
	if (access(BVD_UNIX_SOCKET_PATH, F_OK) == 0) {
		fprintf(stderr, "bvd unix socket path file exist, unlink it.\n");
		if (unlink(BVD_UNIX_SOCKET_PATH) != 0) {
			perror("could not use bvctl, unlink");
			return ;
		}
	}

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("could not use bvctl, socket");
		return ;
	}
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, BVD_UNIX_SOCKET_PATH);
	if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("could not use bvctl, bind");
		close(sockfd);
		return ;
	}
	if (listen(sockfd, 50) < 0) {
		perror("could not use bvctl, listen");
		close(sockfd);
		return ;
	}

	peeraddr_len = sizeof(peeraddr);
	while (1) {
		peerfd = accept(sockfd, (struct sockaddr *) &peeraddr, &peeraddr_len);
		if (peerfd < 0) {
			continue;
		}
		i = 0;
		while ( (n = read(peerfd, buf + i, 1)) > 0 ) {
			if (i >= sizeof(buf)) {
				break;
			}
			if (buf[i] == 0) {
				if (zero_flag != 0) {
					break;
				}
				zero_flag = 1;
				if (strcmp(buf, "stop") == 0) {
					MY_WRITE(peerfd, "ok, bvd stop!\n");
					_exit(0);
				}
				do_cmd(buf);
				i = 0;
				continue;
			}
			zero_flag = 0;
			i += n;
		}
		if (i >= sizeof(buf)) {
			MY_WRITE(peerfd, "command too long!\n");
			close(peerfd);
			continue;
		}
		MY_WRITE(peerfd, "ok\n");
		close(peerfd);
	}
	close(sockfd);
}

void ptrace_hdl()
{
	pid_t target_pid;
	int status;
	struct user_regs_struct regs;
	int i;

	while (1) {
		// fprintf(stderr, "ready to wait\n");
		target_pid = wait(&status);
		// fprintf(stderr, "wait out, target_pid: %d\n", target_pid);
		pthread_mutex_lock(&ptrace_mutex);
		if (target_pid >= 0) {
			for (i = 0; i < ready_to_detach_pids_len; ++i) {
				if (ready_to_detach_pids[i] == target_pid) {
					break;
				}
			}
			if (i < ready_to_detach_pids_len) {
				if (ptrace(PTRACE_DETACH, target_pid, NULL, NULL) == -1) {
					perror("ptrace PTRACE_DETACH");
				}
				for (; i < ready_to_detach_pids_len; ++i) {
					ready_to_detach_pids[i] = ready_to_detach_pids[i + 1];
				}
				--ready_to_detach_pids_len;
			}
			else {
				if (WIFEXITED(status) == 0) {
					if (ptrace(PTRACE_GETREGS, target_pid, NULL, &regs) == -1) {
						perror("ptrace PTRACE_GETREGS");
					}
					// fprintf(stderr, "target_pid: %d, orig_rax: %d\n", target_pid, regs.orig_rax);
					if (regs.orig_rax >= 0 && regs.orig_rax < BV_SYSCALL_LIST_SIZE &&
						bv_syscall[regs.orig_rax] != NULL) {

						bv_syscall[regs.orig_rax](target_pid);
					}
					if (ptrace(PTRACE_SYSCALL, target_pid, NULL, NULL) == -1) {
						perror("ptrace PTRACE_SYSCALL");
					}
				}
			}
		}
		pthread_mutex_unlock(&ptrace_mutex);
	}
}

void usage(FILE *out, const char *self)
{
	fprintf(out, "Usage: %s [/path/to/module/file.so] [pid] [-sys_call_num] [-pid] [daemon]\n"
			"  /path/to/module/file.so  like: /root/test/xxx.so, to load module file\n"
			"  pid                      like: 1234, to ptrace pid\n"
			"  -sys_call_num            like: -sys0, to remove ptrace sys call\n"
			"  -pid                     like: -1234, to remove ptrace pid\n"
			"  daemon                   daemon\n", self);
}

int do_cmd(const char *data)
{
	int len;
	int buf;

	len = strlen(data);
	if (len < 1) {
		return 1;
	}
	fprintf(stderr, "ready to do command: \"%s\"\n", data);
	if (data[0] >= '0' && data[0] <= '9') {
		// pid
		if (sscanf(data, "%d", &buf) == 1) {
			add_pid(buf);
		}
	}
	else if (data[0] == '-') {
		// -sys_call_num or -pid
		if (len > 4 && strncmp(data, "-sys", 4) == 0) {
			// -sys_call_num
			if (sscanf(data + 4, "%d", &buf) == 1) {
				remove_bv_syscall(buf);
			}
		}
		else {
			// -pid
			if (sscanf(data + 1, "%d", &buf) == 1) {
				remove_pid(buf);
			}
		}
	}
	else {
		// /path/to/module/file.so
		load_bv_syscall_module(data);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	pthread_t read_cmd_t;
	char **p;
	int use_daemon = 0;

	if (argc == 2) {
		if (strcmp(argv[1], "help") == 0 || 
			strcmp(argv[1], "?") == 0 || 
			strcmp(argv[1], "-h") == 0 || 
			strcmp(argv[1], "--help") == 0 || 
			strcmp(argv[1], "-?") == 0) {

			usage(stderr, argv[0]);
			return 0;
		}
	}

	for (p = argv + 1; *p; ++p) {
		if (strcmp(*p, "daemon") == 0) {
			use_daemon = 1;
			continue;
		}
		if (do_cmd(*p) != 0) {
			fprintf(stderr, "cmd: \"%s\", failed!\n", *p);
		}
	}

	if (use_daemon != 0) {
		daemon(0, 0);
	}

	self_pid = getpid();
	fprintf(stderr, "self_pid: %d\n", self_pid);

	signal(SIGPIPE, signal_hdl);
	signal(SIGUSR1, signal_hdl);

	pthread_mutex_init(&ptrace_mutex, NULL);

	if (pthread_create(&read_cmd_t, NULL, read_cmd, NULL) != 0) {
		perror("could not use bvctl, pthread_create");
	}

	ptrace_hdl();

	pthread_mutex_destroy(&ptrace_mutex);

	return 0;
}
