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
# define SIZE_FLAG 0x4
# define PATTERN_FLAG 0x8
# define TIMESTAMP_IN_MSG 0x10


#define ECHO_REQUEST 8
#define ECHO_REPLY 0

#define MSG_SIZE 65507 + IPV4_HDR_SIZE + ICMP_HDR_SIZE
#define DATA_SIZE 65507
#define IPV4_HDR_SIZE 20
#define ICMP_HDR_SIZE 8

enum e_errorcode {
	SUCCESS,
	PARSING_ERROR,
	INVALID_ARGUMENT,
	INVALID_OPTION,
	RESOLUTION_ERROR,
	MUST_BE_HEX_ERROR,
	SIZE_TOO_BIG,
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
	char *pattern;
	size_t size;
	size_t seq;
};

int args_parsing(struct s_env *env, int ac, char **av);

int usage(struct s_env *env);
int invalid_option(struct s_env *env, char *arg);
int invalid_argument(struct s_env *env, char *arg);
int option_requires_argument(struct s_env *env, char *option);
int must_be_hex(struct s_env *env, char *arg);

# endif /* FT_PING_H */
