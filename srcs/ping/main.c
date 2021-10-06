#include "ft_ping.h"

int		ft_usage(void)
{
	ft_printf("usage: ping [-%s] [-h sweepincrsize] host\n", HANDLED_FLAGS);
	return (1);
}

int		ft_parsing(t_env* env, int ac, char **av)
{
	(void)ac;
	env->dest = av[0];
	return (1);
}

void		ft_print_addrinfo(struct addrinfo *ptr)
{
	printf("flags : %d\n", ptr->ai_flags);
	printf("family : %d\n", ptr->ai_family);
	printf("socktype : %d\n", ptr->ai_socktype);
	printf("protocol : %d\n", ptr->ai_protocol);
}

void		ft_ping(t_env *env)
{
	struct addrinfo	hints;
	struct addrinfo *res;
	int				error;

	(void)env;

	res = NULL;
	ft_bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	error = getaddrinfo(env->dest, "http", &hints, &res);
	if (error)
	{
		printf("error %d: %s\n", error, gai_strerror(error));
		return ;
	}
	ft_print_addrinfo(res);
}

int			main(int ac, char **av)
{
	t_env	env;

	if (ac < 2)
		return (ft_usage());
	if (!ft_parsing(&env, ac - 1, av + 1))
		return (1);
	ft_ping(&env);	
	return (0);
}
