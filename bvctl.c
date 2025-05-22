#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define BVD_UNIX_SOCKET_PATH	"/run/bvd/bvd.sock"

void usage(FILE *out, const char *self)
{
	fprintf(out, "Usage: %s [/path/to/module/file.so] [pid] [-sys_call_num] [-pid]\n"
			"  /path/to/module/file.so  like: /root/test/xxx.so, to load module file\n"
			"  pid                      like: 1234, to ptrace pid\n"
			"  -sys_call_num            like: -sys0, to remove ptrace sys call\n"
			"  -pid                     like: -1234, to remove ptrace pid\n", self);
}

#define MY_WRITE(fd, str_data) write(fd, str_data, strlen(str_data))

int main(int argc, char *argv[])
{
	int sockfd;
	struct sockaddr_un addr;
	char **p;
	char buf[1024];
	int n;

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

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, BVD_UNIX_SOCKET_PATH);

	if (connect(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("connect");
		close(sockfd);
		return 1;
	}

	for (p = argv + 1; *p; ++p) {
		MY_WRITE(sockfd, *p);
		write(sockfd, "\0", 1);
	}
	write(sockfd, "\0", 1);

	while ( (n = read(sockfd, buf, sizeof(buf))) > 0 ) {
		write(1, buf, n);
	}

	return 0;
}
