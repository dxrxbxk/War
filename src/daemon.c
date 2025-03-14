#include <sys/file.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

#include "daemon.h"
#include "utils.h"
#include "syscall.h"

#define CLOSE_END 0
#define NO_CLOSE_END 1
#define MAX_CLIENTS 3

static int my_htons(int port)
{
	return ((port & 0xff) << 8) | ((port & 0xff00) >> 8);
}

static void logger(const char *msg)
{
	int fd = open(STR("/tmp/.daemon"), O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd == -1) {
		return;
	}

	write(fd, msg, ft_strlen(msg));
	close(fd);
}

static int create_server(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		return -1;
	}

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = my_htons(8080),
		.sin_addr.s_addr = INADDR_ANY
	};

	if (bind(fd, &addr, sizeof(addr)) == -1) {
		close(fd);
		return -1;
	}

	if (listen(fd, 0) == -1) {
		close(fd);
		return -1;
	}

	//if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
	//	close(fd);
	//	return -1;
	//}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1) {
		close(fd);
		return -1;
	}

	return fd;
}

static int accept_client(int fd)
{
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);

	int client_fd = accept(fd, &addr, &addr_len);
	if (client_fd == -1) {
		return -1;
	}

	return client_fd;
}

static void poller(int fd)
{
	struct pollfd fds[MAX_CLIENTS + 1];
	fds[0].fd = fd;
	fds[0].events = POLLIN;

	for (int i = 1; i < MAX_CLIENTS + 1; i++) {
		fds[i].fd = -1;
	}

	int use_client = 0;

	while (1) {
		if (poll(&fds, use_client + 1, -1) == -1) {
			break;
		}

		if (fds[0].revents & POLLIN) {
			int client_fd = accept_client(fd);
			if (client_fd != -1) {
				for (int i = 1; i < MAX_CLIENTS + 1; i++) {
					if (fds[i].fd == -1) {
						fds[i].fd = client_fd;
						fds[i].events = POLLIN;
						use_client++;
						logger(STR("new client\n"));
						break;
					}
				}
			}
		}

		for (int i = 1; i < MAX_CLIENTS + 1; i++) {
			if (fds[i].fd != -1 && fds[i].revents & POLLIN) {
				char buf[1024];
				int ret = read(fds[i].fd, buf, sizeof(buf));
				if (ret <= 0) {
					close(fds[i].fd);
					fds[i].fd = -1;
					use_client--;
					logger(STR("client disconnected\n"));
				}
				else {
					buf[ret] = '\0';
					logger(buf);
				}
			}
		}
	}
}

static int lock(int *lock_fd, int close_end)
{
	*lock_fd = open(STR("/tmp/.warlock"), O_CREAT | O_RDWR, 0644);

	if (*lock_fd == -1) {
		return 1;
	}


	if (flock(*lock_fd, LOCK_EX | LOCK_NB) == -1) {
		logger(STR("already locked\n"));
		close(*lock_fd);
		return 1;
	} else {
		logger(STR("locked\n"));
	}

	if (close_end == CLOSE_END) {
		close(*lock_fd);
	}

	return 0;
}

static int unlock(int *lock_fd)
{
	//lock_fd = open(STR("/tmp/.warlock"), O_RDONLY);

	if (*lock_fd == -1) {
		return 1;
	}
	else if (flock(*lock_fd, LOCK_UN) == -1) {

		logger(STR("unlock failed\n"));
		close(*lock_fd);
		return 1;
	} else {
		logger(STR("unlocked\n"));
	}


	close(*lock_fd);
	return 0;
}

void run(int *lock_fd)
{

	int server_fd = create_server();
	if (server_fd == -1) {
		return;
	}

	poller(server_fd);

	close(server_fd);

	unlock(lock_fd);
}

int	daemonize(void)
{
	int lock_fd = -1;
	if (lock(&lock_fd, CLOSE_END) == 1) {
		return 0;
	}

	int		fd;
	pid_t	pid;

	pid = fork();

	if (pid < 0)
		return -1;
	if (pid > 0)
		return 0;

	if (setsid() == -1)
		return -1;

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		exit(0);

	if (chdir(STR("/")) == -1)
		return -1;

	fd = open(STR("/dev/null"), O_RDONLY);
	if (fd == -1)
		return -1;

	if (dup2(fd, 0) < 0)
		return -1;
	if (dup2(fd, 1) < 0)
		return -1;
	if (dup2(fd, 2) < 0)
		return -1;

	close(fd);

	if (lock(&lock_fd, NO_CLOSE_END) == 1) {
		return 0;
	}

	run(&lock_fd);
	return 0;

}
