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
#include <signal.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/signalfd.h>
#include <poll.h>

#define BVD_UNIX_SOCKET_PATH	"/run/bvd/bvd.sock"

#define BV_SYSCALL_LIST_SIZE	1024
typedef void (*bv_syscall_type)(pid_t target_pid);
bv_syscall_type bv_syscall[BV_SYSCALL_LIST_SIZE] = { NULL };

/*
 * bv_syscall[0] means: SYS_read ptrace function
 * bv_syscall[1] means: SYS_write ptrace function
 * and so on
 */

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

	for (i = 0; i < *bv_syscall_list_len; ++i) {
		sprintf(buf, "bv_syscall_%d", (*bv_syscall_list)[i]);
		bv_syscall[ (*bv_syscall_list)[i] ] = (void (*)(pid_t)) dlsym(dl_hdl, buf);
		if ( bv_syscall[ (*bv_syscall_list)[i] ] == NULL ) {
			fprintf(stderr, "dlsym: %s\n", dlerror());
		}
	}

	return 0;
}

int add_pid(pid_t target_pid)
{
	fprintf(stderr, "ready to add pid: %d\n", target_pid);
	if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
		perror("ptrace PTRACE_ATTACH");
	}
	while (waitpid(target_pid, NULL, 0) != target_pid);
	if (ptrace(PTRACE_SYSCALL, target_pid, NULL, NULL) == -1) {
		perror("ptrace PTRACE_SYSCALL");
	}
	return 0;
}

int remove_bv_syscall(int sys_num)
{
	fprintf(stderr, "ready to remove bv syscall: %d\n", sys_num);
	bv_syscall[sys_num] = NULL;
	return 0;
}

int remove_pid(pid_t target_pid)
{
	fprintf(stderr, "ready to remove pid: %d\n", target_pid);
	ready_to_detach_pids[ready_to_detach_pids_len++] = target_pid;
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
}

void do_ptrace()
{
	pid_t target_pid;
	int status;
	struct user_regs_struct regs;
	int i;

	target_pid = wait(&status);
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

void read_cmd(int sockfd)
{
	int peerfd;
	struct sockaddr_un peeraddr;
	int peeraddr_len;
	char buf[1024];
	int i, n;
	int zero_flag = 0;

	peeraddr_len = sizeof(peeraddr);
	peerfd = accept(sockfd, (struct sockaddr *) &peeraddr, &peeraddr_len);
	if (peerfd < 0) {
		perror("accept");
		return ;
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
		return ;
	}
	MY_WRITE(peerfd, "ok\n");
	close(peerfd);
}

int create_sockfd()
{
	char bvd_unix_socket_dir[1024];
	int sockfd;
	struct sockaddr_un addr;

	strcpy(bvd_unix_socket_dir, BVD_UNIX_SOCKET_PATH);
	dirname(bvd_unix_socket_dir);

	fprintf(stderr, "bvd unix socket path: %s\nbvd unix socket dir: %s\n", BVD_UNIX_SOCKET_PATH, bvd_unix_socket_dir);
	if (check_and_mkdirs(bvd_unix_socket_dir) != 0) {
		fprintf(stderr, "could not use bvctl, bvd unix socket dir not found, and could not create!\n");
		return -1;
	}
	if (access(BVD_UNIX_SOCKET_PATH, F_OK) == 0) {
		fprintf(stderr, "bvd unix socket path file exist, unlink it.\n");
		if (unlink(BVD_UNIX_SOCKET_PATH) != 0) {
			perror("could not use bvctl, unlink");
			return -1;
		}
	}

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("could not use bvctl, socket");
		return -1;
	}
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, BVD_UNIX_SOCKET_PATH);
	if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("could not use bvctl, bind");
		close(sockfd);
		return -1;
	}
	if (listen(sockfd, 50) < 0) {
		perror("could not use bvctl, listen");
		close(sockfd);
		return -1;
	}

	return sockfd;
}

int loop_hdl()
{
	nfds_t nfds = 2;
	struct pollfd fds[2];

	sigset_t mask;
	int sfd;
	struct signalfd_siginfo fdsi;
	ssize_t s;

	int sockfd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);	// for get SIGSTOP from child process

	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
		perror("sigprocmask");
		return 1;
	}

	sfd = signalfd(-1, &mask, 0);
	if (sfd == -1) {
		perror("signalfd");
		return 1;
	}

	sockfd = create_sockfd();
	if (sockfd == -1) {
		close(sfd);
		return 1;
	}

	fds[0].fd = sfd;
	fds[0].events = POLLIN;
	fds[1].fd = sockfd;
	fds[1].events = POLLIN;

	while (1) {
		if (poll(fds, nfds, -1) <= 0) {
			continue;
		}

		if (fds[0].revents & POLLIN) {
			// ptrace
			s = read(sfd, &fdsi, sizeof(fdsi));
			if (s != sizeof(fdsi)) {
				perror("read");
			}
			if (fdsi.ssi_signo == SIGCHLD) {
				do_ptrace();
			}
		}

		if (fds[1].revents & POLLIN) {
			// unix socket accept
			read_cmd(sockfd);
		}
	}
	return 0;
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

int main(int argc, char *argv[])
{
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

	signal(SIGPIPE, signal_hdl);

	return loop_hdl();

	return 0;
}
