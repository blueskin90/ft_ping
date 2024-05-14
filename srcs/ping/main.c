#include "ft_ping.h"
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>

int init_env(struct s_env *env)
{
	srand(time(0));
	env->ident = rand();
	env->saddr.sin_family = AF_INET;
	env->saddr.sin_port = 0;
	env->seq = 1;
	if (inet_pton(AF_INET, "10.0.2.15", &env->saddr.sin_addr) != 1)
	{
		printf("source IP configuration failed\n");
		return (0);
	}
	env->min.tv_sec = LONG_MAX;
	env->min.tv_usec = LONG_MAX;
	return SUCCESS;
}

int	fill_header(struct s_env *env, char *buffer, size_t buffsize)
{
	struct icmp4_hdr *hdr = (struct icmp4_hdr *)buffer;

	if (buffsize < sizeof(struct icmp4_hdr))
		return (0);
	hdr->msg_type = ECHO_REQUEST;
	hdr->ident = env->ident;
	hdr->sequence = env->seq;
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
		env->args.flags |= TIMESTAMP_IN_MSG;
	}
	if (env->args.pattern == NULL) {
		while (i < buffsize) {
			buffer[i] = (i & 0xff);
			i++;
		}
	}
	else {
		copy_pattern(buffer + i, buffsize - i, env->args.pattern);
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

int verify_checksum(char* buffer, size_t buffsize)
{
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
	checksum = (checksum & 0xffff) + (checksum >> 16);
	return (checksum == 0xffff);
}

int parse_response(struct s_env *env, char *buffer, const struct timeval *time)
{
	struct ipv4_hdr *iphdr = (struct ipv4_hdr*)buffer;
	struct icmp4_hdr *icmphdr = (struct icmp4_hdr*)(iphdr + 1);
	struct timeval tv;
	char *data = (time == NULL ? (char*)(icmphdr + 1) : ((char*)(icmphdr + 1)) + sizeof(struct timeval));

	gettimeofday(&tv, NULL);
	printf("ident = %.4hx, ident received = %.4hx\n", env->ident, icmphdr->ident);
	if (!verify_checksum((char*)icmphdr, ICMP_HDR_SIZE + env->args.size)) {
		printf("incorrect checksum\n");
		return INCORRECT_CHECKSUM;
	}
	if (icmphdr->ident != env->ident)
		return INCORRECT_IDENT;

	if (time) {
		struct timeval final;
		
		final.tv_sec = tv.tv_sec - time->tv_sec;	
		final.tv_usec = tv.tv_usec - time->tv_usec;	

		printf("there is a time\n");
		if (final.tv_sec > env->max.tv_sec || ((final.tv_sec == env->max.tv_sec && final.tv_usec > env->max.tv_usec))) {
			printf("> THAN\n");
			memcpy(&final, &(env->max), sizeof(struct timeval));
		}
		else if (final.tv_sec < env->min.tv_sec || ((final.tv_sec == env->min.tv_sec && final.tv_usec < env->min.tv_usec))) {
			printf("< THAN\n");
			memcpy(&final, &(env->min), sizeof(struct timeval));
		}

	}
	(void)data;
	return (1);
}

int receive_answer(int sock, struct s_env *env, const struct timeval *time)
{
	struct sockaddr addr;
	char msg[MSG_SIZE];
	socklen_t addrlen;
	int retval;

	bzero(msg, MSG_SIZE);
	do {
		retval = recvfrom(sock, msg, MSG_SIZE, MSG_PEEK, &addr, &addrlen);
		if (retval != -1) {
			for (int i = 0; i < retval; i++) {
				printf("%.2hhx", msg[i]);
				if (i % 15 == 0 && i != 0)
					printf("\n");
				else if (i % 2 == 1)
					printf(" ");
			}
			env->received++;
		}
		else {
			printf("error when receiving\n");
			env->error_received++;
			break;
		}
		printf("\n");
	} while (parse_response(env, msg, time) == INCORRECT_IDENT);
		return SUCCESS;
}

int print_first_line(struct s_env *env)
{
	printf("PING %s (%s) %ld(%ld) bytes of data.\n", env->args.dest, env->dest_ip, env->args.size, env->args.size + IPV4_HDR_SIZE + ICMP_HDR_SIZE);
	return 1;
}

int fill_message(struct s_env *env, char *buffer, size_t bufsize)
{
	bzero(buffer, bufsize);
	if (!fill_header(env, buffer,bufsize))
	{
		printf("Didn't have enough space for the ICMP header\n");
		return (0);
	}
	fill_buffer(env, buffer + ICMP_HDR_SIZE, env->args.size);
	compute_checksum(buffer, ICMP_HDR_SIZE + env->args.size);
	return (SUCCESS);
}

int running = 1;

void intHandler(int dummy)
{
	(void)dummy;
	running = 0;
}

void fill_modifications(struct s_env *env, char *buffer)
{
	struct icmp4_hdr *msg = (struct icmp4_hdr*)buffer;

	msg->sequence = env->seq;
	bzero(&msg->checksum, sizeof(msg->checksum));
	if (env->args.flags & TIMESTAMP_IN_MSG)
		gettimeofday(&msg->time, NULL); // we do this last so its closer to reality
	compute_checksum(buffer, ICMP_HDR_SIZE + env->args.size);
}

void send_message(struct s_env *env, int sock, char *buffer)
{
	int retval;

	retval = sendto(sock, buffer, ICMP_HDR_SIZE + env->args.size, 0, (struct sockaddr*)&env->daddr, sizeof(env->daddr));
	if (retval < 0)
	{
		printf("error : %s\n", strerror(errno));
		env->error_transmitted++;
		return;
	}
	env->transmitted++;
}

void print_end_stats(struct s_env *env)
{
	struct timeval time_end;

	gettimeofday(&time_end, NULL);
	printf("--- %s ping statistics ---\n", env->args.dest);
	printf("%zu packets transmitted, %zu received, %ld%% packet loss, time (HERE SHOULD PRINT THE TIME PING HAS BEEN RUNNING)\n", env->transmitted, env->received, env->received == 0 ? (env->transmitted == 0 ? 0 : 100) : 100 - env->received * 100 / env->transmitted);
	printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", 1.921394, 1.124215, 12.213, 0.);
	printf("max %ld,%ld\n", env->max.tv_sec, env->max.tv_usec);
	printf("min %ld,%ld\n", env->min.tv_sec, env->min.tv_usec);
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
	fill_message(env, buffer,sizeof(buffer));
	print_first_line(env);
	signal(SIGINT, intHandler);
	gettimeofday(&env->start_time, NULL);
	while (running) {
		fill_modifications(env, buffer);
		send_message(env, sock, buffer);
		receive_answer(sock, env, (env->args.size >= sizeof(struct timeval) ? (struct timeval *)(buffer + ICMP_HDR_SIZE) : NULL));
		env->seq++;	
		if ((env->args.flags & COUNT_FLAG) && env->seq > env->args.count) 
			running = 0;
		sleep(1);
	}
	print_end_stats(env);
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
