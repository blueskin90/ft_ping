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

int parse_dest(struct s_env *env, char *dest)
{
	printf("dest is %s\n", dest);
	env->daddr.sin_family = AF_INET;
	env->daddr.sin_port = 0;
	if (inet_pton(AF_INET, dest, &(env->daddr.sin_addr)) != 1)
	{
		fprintf(stderr, "destination IP configuration failed\n");
		return PARSING_ERROR;
	}
	return SUCCESS;
}

int parse_arg(struct s_env *env, int ac, char **av, int *i)
{
	if (*i == ac - 1)
		return parse_dest(env, av[*i]);
	if (strncmp(av[*i], "-c", 2) == 0)
		return parse_count(env, ac, av, i);
	else if (strcmp(av[*i], "-v") == 0) {
		env->flags |= VERBOSE_FLAG;
	}
	else if (strcmp(av[*i], "-h") == 0) {
		return usage(env);
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
	return SUCCESS;
}

int init_env(struct s_env *env)
{
	(void)env;
	srand(time(0));
	env->ident = rand();
	return SUCCESS;
}

int ping(struct s_env *env)
{
	(void)env;
	return SUCCESS;
}

int			main(int ac, char **av)
{
	struct s_env env;
	int retval;

	retval = args_parsing(&env, ac, av);
	if (retval != SUCCESS)
		return retval;
	retval = init_env(&env);
	if (retval != SUCCESS)
		return retval;
	ping(&env);
	return 0;
}
