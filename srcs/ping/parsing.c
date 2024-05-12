#include "ft_ping.h"

#include <sys/socket.h>
#include <string.h>

static int parse_count(struct s_env *env, int ac, char **av, int *i)
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

/*
static void dump_res(struct addrinfo *res)
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
*/

static void parse_dest_ip(struct s_env *env, struct sockaddr_in* addr)
{
	uint8_t val;
	int offset = 0;

	for (int i = 0; i < 4; i++) {
		val = (addr->sin_addr.s_addr & (0xFF << (8 * i))) >> (8 * i);
		offset += sprintf(env->dest_ip + offset, "%d%c",val, i == 3 ? 0 : '.');
	}
}

static int parse_dest(struct s_env *env, char *dest)
{
	struct addrinfo hints;
	struct addrinfo *res;
	int retval;

	env->dest = dest;
	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMP;
	retval = getaddrinfo(dest, 0, &hints, &res);
	if (retval < 0) {
		fprintf(stderr, "%s: Couldn't resolve host %s: %s\n", env->progname, dest, gai_strerror(retval));
		freeaddrinfo(res);
		return RESOLUTION_ERROR;
	}
	parse_dest_ip(env, (struct sockaddr_in *)res->ai_addr);
	env->daddr.sin_family = AF_INET;
	env->daddr.sin_port = 0;
	memcpy(&env->daddr.sin_addr, &((struct sockaddr_in*)res->ai_addr)->sin_addr, sizeof(env->daddr.sin_addr));
	freeaddrinfo(res);
	return SUCCESS;
}

static int parse_size(struct s_env *env, int ac, char **av, int *i)
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

static int parse_pattern(struct s_env *env, int ac, char **av, int *i)
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

static int parse_arg(struct s_env *env, int ac, char **av, int *i)
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
