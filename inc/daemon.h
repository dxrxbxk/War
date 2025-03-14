#ifndef DAEMON_H
#define DAEMON_H

#include <sys/types.h>
#include <fcntl.h>

int	daemonize(void);
//int	daemonize(void (*famine)(void));
#endif
