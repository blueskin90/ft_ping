#include "ft_ping.h"
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

int		ft_usage(void)
{
	printf("usage: ping [-%s] [-h sweepincrsize] host\n", HANDLED_FLAGS);
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
	bzero(&hints, sizeof(struct addrinfo));
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

int			fill_header(char *buffer, size_t buffsize)
{
	struct icmp4_hdr *hdr = (struct icmp4_hdr *)buffer;

	if (buffsize < sizeof(struct icmp4_hdr))
		return (0);
	bzero(hdr, sizeof(*hdr));
	hdr->msg_type = ECHO_REQUEST; 
	// checksum checked after data are added
	hdr->ident = rand();
	hdr->sequence = 1;
	return (1);
}

void			fill_buffer(char *buffer, size_t buffsize)
{
	snprintf(buffer, buffsize, "pouet");	
}

void			calculate_checksum(char *buffer, size_t buffsize)
{
	uint16_t *buf = (uint16_t*)buffer;
	struct icmp4_hdr *hdr = (struct icmp4_hdr*)buffer;
	uint16_t checksum = 0;
	size_t i;

	buffsize /= 2; // penser au cas ou buffsize est impair
	for(i = 0; i < buffsize; i++)
		checksum += buf[i];
	if (buffsize % 2)
		checksum += (buffer[buffsize - 1] << 8);

	for (i = 0; i < buffsize; i++)
	{
		printf("%.4hx ", buffer[i]);
		if (i % 8 == 0 && i != 0)
			printf("\n");
	}


	hdr->checksum = ~checksum - 1; // why do i have to take 1 less ?
	printf("checksum non inverted : %hx\ninverted %hx\n correct one not inverted %hx\ncorect one %hx\n", checksum, ~checksum, ~((~checksum) - 1), ~(checksum - 1));

	for (i = 0; i < buffsize; i++)
	{
		printf("%.4hx ", buffer[i]);
		if (i % 8 == 0 && i != 0)
			printf("\n");
	}
}

int			ping(void)
{
	int sock;
	struct sockaddr_in saddr;
	struct sockaddr_in daddr;
	char buffer[MSG_MAX_LEN];

	srand(time(0));
	saddr.sin_family = AF_INET;
	saddr.sin_port = 6942;
	if (inet_pton(AF_INET, "10.0.2.15", &saddr.sin_addr) != 1)
	{
		printf("source IP configuration failed\n");
		return (0);
	}

	daddr.sin_family = AF_INET;
	daddr.sin_port = 42069;
	if (inet_pton(AF_INET, "8.8.8.8", &daddr.sin_addr) != 1)
	{
		printf("destination IP configuration failed\n");
		return (0);
	}


// check for CAP_NET_RAW capability in user namespace
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); 
	if (sock < 0)
		printf("Couldn't create the socket: %s\n", strerror(errno));
	bind(sock, (struct sockaddr*)&saddr, sizeof(saddr));

	bzero(buffer, sizeof(buffer));
	if (!fill_header(buffer,sizeof(buffer)))
		printf("Didn't have enough space for the ICMP header\n");
	fill_buffer(buffer + sizeof(struct icmp4_hdr), sizeof(buffer) - sizeof(struct icmp4_hdr));
	calculate_checksum(buffer, sizeof(buffer));
	sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&daddr, sizeof(daddr));
	return (sock);
}

int			main(int ac, char **av)
{
	t_env	env;

	if (ac < 2)
		return (ft_usage());
	if (!args_parsing(&env, ac - 1, av + 1))
		return (1);
//	ft_ping(&env);	
	ping();
	return (0);
}
