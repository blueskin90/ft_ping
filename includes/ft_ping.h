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

# define INCORRECT_IDENT 0x20


#define ECHO_REQUEST 8
#define ECHO_REPLY 0

#define MSG_SIZE 65507 + IPV4_HDR_SIZE + ICMP_HDR_SIZE
#define DATA_SIZE 65507
#define IPV4_HDR_SIZE 20
#define ICMP_HDR_SIZE 8

#define IPV4_FORMAT "%hhd.%hhd.%hhd.%hhd"

#define IPV4_ARGUMENTS(x) x.addr_split[0], x.addr_split[1], x.addr_split[2], x.addr_split[3]

enum e_errorcode {
	ERROR,
	SUCCESS,
	PARSING_ERROR,
	INVALID_ARGUMENT,
	INVALID_OPTION,
	RESOLUTION_ERROR,
	MUST_BE_HEX_ERROR,
	SIZE_TOO_BIG,
	INCORRECT_CHECKSUM,
	INCORRECT_SIZE,
	QUANTUM_PING,
	USAGE,
};

union ipv4_addr {
	uint32_t addr;
	char addr_split[4];
};

struct ipv4_hdr {
	uint8_t version:4;
	uint8_t ihl:4;
	uint8_t tos;
	uint16_t length;
	uint16_t ident;
	uint16_t flags;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	union ipv4_addr src;
	union ipv4_addr dest;
};

struct icmp4_hdr_notime {
	uint8_t	msg_type;
	uint8_t	code;
	uint16_t checksum;
	uint16_t ident;
	uint16_t sequence;
	char data[];
};

struct icmp4_hdr {
	uint8_t	msg_type;
	uint8_t	code;
	uint16_t checksum;
	uint16_t ident;
	uint16_t sequence;
	struct timeval time;
	char data[];
};

struct s_args {
	uint64_t flags;
	size_t count;
	char *pattern;
	size_t size;
	char *dest;
};

struct s_env
{
	struct timeval start_time;
	char *progname;
	char dest_ip[16];
	uint16_t ident;
	struct sockaddr_in saddr;
	struct sockaddr_in daddr;
	struct icmp4_hdr *hdr;
	struct s_args args;
	size_t seq;
	size_t transmitted;
	size_t error_transmitted;
	size_t received;
	size_t error_received;
	uint64_t usec_tot;
	struct timeval min;	
	struct timeval avg;	
	struct timeval max;	
	struct timeval mdev;	
};

int args_parsing(struct s_env *env, int ac, char **av);

int usage(struct s_env *env);
int invalid_option(struct s_env *env, char *arg);
int invalid_argument(struct s_env *env, char *arg);
int option_requires_argument(struct s_env *env, char *option);
int must_be_hex(struct s_env *env, char *arg);

# endif /* FT_PING_H */
