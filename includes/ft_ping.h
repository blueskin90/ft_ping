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

# define HANDLED_FLAGS "v"
# define MSG_MAX_LEN 64

#define ECHO_REQUEST 8
#define ECHO_REPLY 0

typedef struct		s_env
{
	char			*dest;
}			t_env;

struct icmp4_hdr {
	uint8_t	msg_type;
	uint8_t	code;
	uint16_t checksum;
	uint16_t ident;
	uint16_t sequence;
};

int		args_parsing(t_env* env, int ac, char **av);

# endif /* FT_PING_H */
