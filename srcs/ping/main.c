#include "ft_ping.h"
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

int usage(struct s_env *env)
{
	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "  %s [options] <destination>\n", env->progname);
	return USAGE;
}

int invalid_option(struct s_env *env, char *arg)
{
	fprintf(stderr, "%s: invalid option -- '%.1s'\n", env->progname, arg + 1);
	usage(env);
	return INVALID_OPTION;
}

int invalid_argument(struct s_env *env, char *arg)
{
	fprintf(stderr, "%s: invalid argument: '%s'\n", env->progname, arg);
	return INVALID_ARGUMENT;
}

int option_requires_argument(struct s_env *env, char *option)
{
	fprintf(stderr, "%s: option requires an argument -- '%s'\n", env->progname, option + 1);
	usage(env);
	return INVALID_ARGUMENT;
}

int must_be_hex(struct s_env *env, char *arg)
{
	fprintf(stderr, "%s: patterns must be specified as hex digits:%s\n", env->progname, arg);
	return MUST_BE_HEX_ERROR;
}

int parse_count(struct s_env *env, int ac, char **av, int *i)
{
	int found = 0;
	size_t count;
	char *end;

	env->flags |= COUNT_FLAG;
	if (av[*i][2] != 0) {							// parse in same arg
		count = strtoll(&(av[*i][2]), &end, 10);
		if (*end != 0)
			return invalid_argument(env, &(av[*i][2]));
		found = 1;
	}
	if (!found) {									// parse next arg as complement
		if (*i + 1 == ac)
			return option_requires_argument(env, av[*i]);
		(*i)++;
		count = strtoll(av[*i], &end, 10);
		if (end == av[*i] || *end != 0)
			return invalid_argument(env, av[*i]);
	}
	env->count = count;
	return SUCCESS;
}

void dump_res(struct addrinfo *res)
{
	struct sockaddr_in *addr;

	while (res) {
		printf("flags %#.4x\n", res->ai_flags);
		printf("family %#.4x\n", res->ai_family);
		printf("socktype %#.4x\n", res->ai_socktype);
		printf("protocol %#.4x\n", res->ai_protocol);
		printf("addrlen %#.4x\n", res->ai_addrlen);
		addr = (struct sockaddr_in*)res->ai_addr;
		if (addr) {
			printf("family %#.2hhx\n", addr->sin_family);
			printf("sin_port %#.hhx\n", addr->sin_port);
			printf("address %s\n", inet_ntoa(addr->sin_addr));
		}
		else
			printf("struct sockaddr NULL\n");
		printf("name %s\n", res->ai_canonname);
		res = res->ai_next;
	}
}

int parse_dest(struct s_env *env, char *dest)
{
	struct addrinfo hints;
	struct addrinfo *res;
	int retval;

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMP;
	retval = getaddrinfo(dest, 0, &hints, &res);
	printf("AF_INET %d\n", AF_INET);
	if (retval < 0) {
		fprintf(stderr, "%s: Couldn't resolve host %s: %s\n", env->progname, dest, gai_strerror(retval));
		freeaddrinfo(res);
		return RESOLUTION_ERROR;
	}
	env->daddr.sin_family = AF_INET;
	env->daddr.sin_port = 0;
	memcpy(&env->daddr.sin_addr, &((struct sockaddr_in*)res->ai_addr)->sin_addr, sizeof(env->daddr.sin_addr));
	freeaddrinfo(res);
	return SUCCESS;
}

int parse_size(struct s_env *env, int ac, char **av, int *i)
{
	int found = 0;
	size_t size;
	char *end;

	env->flags |= SIZE_FLAG;
	if (av[*i][2] != 0) {							// parse in same arg
		size = strtoll(&(av[*i][2]), &end, 10);
		if (*end != 0)
			return invalid_argument(env, &(av[*i][2]));
		found = 1;
	}
	if (!found) {									// parse next arg as complement
		if (*i + 1 == ac)
			return option_requires_argument(env, av[*i]);
		(*i)++;
		size = strtoll(av[*i], &end, 10);
		if (end == av[*i] || *end != 0)
			return invalid_argument(env, av[*i]);
	}
	if (size > 65507) {
		fprintf(stderr, "%s: Maximum size of ICMP data is 65507 (65535 with IP and ICMP header): %zu (%zu with IP and ICMP header)\n", env->progname, size, size + 28);
		return SIZE_TOO_BIG;
	}
	env->size = size;
	printf("size = %zu\n", size);
	return SUCCESS;
}

int parse_pattern(struct s_env *env, int ac, char **av, int *i)
{
	int found = 0;
	char *pattern;

	env->flags |= PATTERN_FLAG;
	if (av[*i][2] != 0) {							// parse in same arg
		pattern = &av[*i][2];
		if (strlen(pattern) != strspn(pattern, "abcdefABCDEF0123456789"))
			return must_be_hex(env, pattern);
		found = 1;
	}
	if (!found) {									// parse next arg as complement
		if (*i + 1 == ac)
			return option_requires_argument(env, av[*i]);
		(*i)++;
		pattern = av[*i];
		if (strlen(pattern) != strspn(pattern, "abcdefABCDEF0123456789"))
			return must_be_hex(env, pattern);
	}
	env->pattern = pattern;
	return SUCCESS;
}

int parse_arg(struct s_env *env, int ac, char **av, int *i)
{
	if (*i == ac - 1)
		return parse_dest(env, av[*i]);
	if (strncmp(av[*i], "-c", 2) == 0)
		return parse_count(env, ac, av, i);
	if (strncmp(av[*i], "-s", 2) == 0)
		return parse_size(env, ac, av, i);
	if (strncmp(av[*i], "-p", 2) == 0)
		return parse_pattern(env, ac, av, i);
	if (strcmp(av[*i], "-h") == 0) {
		return usage(env);
	}
	if (strcmp(av[*i], "-v") == 0) {
		env->flags |= VERBOSE_FLAG;
	}
	else {
		return invalid_option(env, av[*i]);
	}
	return SUCCESS;
}

int args_parsing(struct s_env *env, int ac, char **av)
{
	int retval;
	int i = 1;

	env->progname = av[0];
	if (ac < 2) {
		fprintf(stderr, "%s: usage error: Destination address required\n", env->progname);
		return PARSING_ERROR;
	}
	while (i < ac) {
		retval = parse_arg(env, ac, av, &i);
		if (retval != SUCCESS)
			return retval;
		i++;
	}
	if ((env->flags & SIZE_FLAG) == 0)
		env->size = 56;
	return SUCCESS;
}

int init_env(struct s_env *env)
{
	srand(time(0));
	env->ident = rand();
	env->saddr.sin_family = AF_INET;
	env->saddr.sin_port = 0;
	if (inet_pton(AF_INET, "10.0.2.15", &env->saddr.sin_addr) != 1)
	{
		printf("source IP configuration failed\n");
		return (0);
	}
	return SUCCESS;
}

int	fill_header(struct s_env *env, char *buffer, size_t buffsize)
{
	struct icmp4_hdr *hdr = (struct icmp4_hdr *)buffer;

	if (buffsize < sizeof(struct icmp4_hdr))
		return (0);
	hdr->msg_type = ECHO_REQUEST;
	hdr->ident = env->ident;
	hdr->sequence = 1;
	return (1);
}

void copy_mono_pattern(char *buffer, size_t buffsize, char pattern)
{
	char full_pattern;
	size_t i = 0;

	if (pattern >= '0' && pattern <= '9')
		full_pattern = pattern - '0';
	else if (pattern >= 'a' && pattern <= 'f')
		full_pattern = pattern - 'a' + 10;
	else if (pattern >= 'A' && pattern <= 'F')
		full_pattern = pattern - 'A' + 10;
	while (i < buffsize)
		buffer[i++] = full_pattern;
}

void copy_pattern(char *buffer, size_t buffsize, char *pattern)
{
	size_t i = 0;
	size_t patternindex = 0;
	size_t patternlen = strlen(pattern);

	if (patternlen == 1)
		copy_mono_pattern(buffer, buffsize, *pattern);
	else {
		while (i < buffsize)
		{
			if (pattern[patternindex] >= '0' && pattern[patternindex] <= '9') {
				buffer[i] |= (pattern[patternindex] - '0') << (patternindex % 2 ? 0 : 4);
				patternindex++;
			}
			else if (pattern[patternindex] >= 'a' && pattern[patternindex] <= 'f') {
				buffer[i] |= (pattern[patternindex] - 'a' + 10) << (patternindex % 2 ? 0 : 4);
				patternindex++;
			}
			else if (pattern[patternindex] >= 'A' && pattern[patternindex] <= 'F') {
				buffer[i] |= (pattern[patternindex] - 'A' + 10) << (patternindex % 2 ? 0 : 4);
				patternindex++;
			}
			else {
				patternindex++;
			}
			if ((i != 0 && patternindex % 2 == 0) || (i == 0 && patternindex == 2))
				i++;
			if (patternindex > patternlen)
				patternindex = 0;
		}
	}
}

void fill_buffer(struct s_env *env, char *buffer, size_t buffsize)
{
	struct timeval time;
	unsigned int i = 0;

	if (buffsize >= sizeof(struct timeval)) {
		gettimeofday(&time, NULL);
		memcpy(buffer, &time, sizeof(time));
		i += sizeof(time);
		env->flags |= TIMESTAMP_IN_MSG;
	}
	if (env->pattern == NULL) {
		while (i < buffsize) {
			buffer[i] = (i & 0xff);
			i++;
		}
	}
	else {
		copy_pattern(buffer + i, buffsize - i, env->pattern);
	}
}

int			compute_checksum(char *buffer, size_t buffsize)
{
	struct icmp4_hdr *hdr = (struct icmp4_hdr*)buffer;
	size_t buffsize_uint16 = buffsize / 2;
	uint16_t *buf = (uint16_t*)buffer;
	uint32_t checksum = 0;
	size_t i;

	if (buffsize == 0)
		return 0;
	for(i = 0; i < buffsize_uint16; i++)
		checksum += buf[i];
	if (buffsize % 2)
		checksum += ((uint16_t)buffer[buffsize - 1]);
	// folding checksum to get an uint16_t back
	checksum = (checksum & 0xffff) + (checksum >> 16);
	hdr->checksum = ~checksum;
	return 1;
}

int receive_answer(int sock, struct s_env *env)
{
	char msg[MSG_SIZE];
	int retval;
	struct sockaddr addr;
	socklen_t addrlen;

	(void)env;
	bzero(msg, MSG_SIZE);
	retval = recvfrom(sock, msg, MSG_SIZE, 0, &addr, &addrlen);
	printf("reval = %d\n",retval);
	if (retval != -1) {
		for (int i = 0; i < retval; i++) {
			printf("%.2hhx", msg[i]);
			if (i % 2 == 0 && i != 0)
				printf(" ");
			if (i % 16 == 0 && i != 0)
				printf("\n");
		}
	}
	return SUCCESS;
}

int ping(struct s_env *env)
{
	int sock;
	char buffer[ICMP_HDR_SIZE + DATA_SIZE];
	int retval;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0)
	{
		printf("Couldn't create the socket: %s\n", strerror(errno));
		return 0;
	}
	retval = bind(sock, (struct sockaddr*)&env->saddr, sizeof(env->saddr));
	if (retval < 0)
	{
		printf("error : %s\n", strerror(errno));
		return (0);
	}
	bzero(buffer, sizeof(buffer));
	if (!fill_header(env, buffer,sizeof(buffer)))
	{
		printf("Didn't have enough space for the ICMP header\n");
		return (0);
	}
	fill_buffer(env, buffer + ICMP_HDR_SIZE, env->size); // attention pas de verification de la size max au parsing
	compute_checksum(buffer, ICMP_HDR_SIZE + env->size);
	retval = sendto(sock, buffer, ICMP_HDR_SIZE + env->size, 0, (struct sockaddr*)&env->daddr, sizeof(env->daddr));
	if (retval < 0)
	{
		printf("error : %s\n", strerror(errno));
		return (0);
	}
	receive_answer(sock, env);
	return SUCCESS;
}

int			main(int ac, char **av)
{
	struct s_env env;
	int retval;

	bzero(&env, sizeof(env));
	retval = args_parsing(&env, ac, av);
	if (retval != SUCCESS)
		return retval;
	retval = init_env(&env);
	if (retval != SUCCESS)
		return retval;
	ping(&env);
	return 0;
}
