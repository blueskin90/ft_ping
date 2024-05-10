#include <stdio.h>
#include "ft_ping.h"

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
