#ifndef FT_PING_H
# define FT_PING_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

#include <stdio.h>
#include <strings.h>

# define COUNT_FLAG 0x1
# define VERBOSE_FLAG 0x2

# define HANDLED_FLAGS "v"
# define MSG_MAX_LEN 64

#define ECHO_REQUEST 8
#define ECHO_REPLY 0

enum e_errorcode {
	SUCCESS,
	PARSING_ERROR,
	INVALID_ARGUMENT,
	INVALID_OPTION,
	USAGE,
};

struct icmp4_hdr {
	uint8_t	msg_type;
	uint8_t	code;
	uint16_t checksum;
	uint16_t ident;
	uint16_t sequence;
};

struct s_env
{
	char *progname;
	uint16_t ident;
	struct sockaddr_in saddr;
	struct sockaddr_in daddr;
	struct icmp4_hdr *hdr;
	uint64_t flags;
	size_t count;
	int sock;
};

# endif /* FT_PING_H */
