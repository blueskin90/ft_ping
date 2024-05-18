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
	env->seq = 1;
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

int substract_timeval(struct timeval *result, const struct timeval *tv1, struct timeval *tv2) // return 1 - 2
{
	/* Perform the carry for the later subtraction by updating tv2. */
	if (tv1->tv_usec < tv2->tv_usec) {
	  int nsec = (tv2->tv_usec - tv1->tv_usec) / 1000000 + 1;
	  tv2->tv_usec -= 1000000 * nsec;
	  tv2->tv_sec += nsec;
	}
	if (tv1->tv_usec - tv2->tv_usec > 1000000) {
	  int nsec = (tv1->tv_usec - tv2->tv_usec) / 1000000;
	  tv2->tv_usec += 1000000 * nsec;
	  tv2->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	   tv_usec is certainly positive. */
	result->tv_sec = tv1->tv_sec - tv2->tv_sec;
	result->tv_usec = tv1->tv_usec - tv2->tv_usec;

	/* Return 1 if result is negative. */
	return tv1->tv_sec < tv2->tv_sec;
}

int parse_response(struct s_env *env, char *buffer, int buffersize, struct timeval *send_time)
{
	struct ipv4_hdr *iphdr = (struct ipv4_hdr*)buffer;
	struct icmp4_hdr *icmphdr = (struct icmp4_hdr*)(iphdr + 1);
	struct timeval recv_time;
	char *data = (send_time == NULL ? (char*)(icmphdr + 1) : ((char*)(icmphdr + 1)) + sizeof(struct timeval));

	gettimeofday(&recv_time, NULL);
	if (icmphdr->ident != env->ident)
		return INCORRECT_IDENT;
	if (!verify_checksum((char*)icmphdr, ICMP_HDR_SIZE + env->args.size)) {
		printf("incorrect checksum\n");
		return INCORRECT_CHECKSUM;
	}
	if ((size_t)buffersize < env->args.size) {
		printf("message should be the same size, weird (sent %zu received %d)\n", env->args.size, buffersize);
		return INCORRECT_SIZE;
	}
	if (send_time) {
		struct timeval final;
		
		bzero(&final, sizeof(struct timeval));
		if(substract_timeval(&final, &recv_time, send_time)) {
			printf("Impossible, message arrived before it was sent, and we are not doing quantum ping\n");
			return QUANTUM_PING;
		}
		if (final.tv_sec > env->max.tv_sec || ((final.tv_sec == env->max.tv_sec && final.tv_usec > env->max.tv_usec))) {
			memcpy(&(env->max), &final, sizeof(struct timeval));
		}
		if (final.tv_sec < env->min.tv_sec || ((final.tv_sec == env->min.tv_sec && final.tv_usec < env->min.tv_usec))) {
			memcpy(&(env->min), &final, sizeof(struct timeval));
		}
		env->usec_tot += final.tv_sec * 1000000 + final.tv_usec;
		if (env->received > 1) {
			int64_t val =(final.tv_sec * 1000000 + final.tv_usec) - (env->usec_tot / env->received);
			if (val < 0)
				env->usec_dev -= val;
			else
				env->usec_dev += val;
		}
		printf("%d bytes from "IPV4_FORMAT": icmp_seq=%hd ttl=%hhd time=%.2f ms\n", buffersize - IPV4_HDR_SIZE, IPV4_ARGUMENTS(iphdr->src), icmphdr->sequence, iphdr->ttl, (float)final.tv_sec * 1000 + (float)final.tv_usec / 1000);
		return (1);
	}
	printf("%d bytes from "IPV4_FORMAT": icmp_seq=%hd ttl=%hhd\n", buffersize - IPV4_HDR_SIZE, IPV4_ARGUMENTS(iphdr->src), icmphdr->sequence, iphdr->ttl);
	(void)data;
	return (1);
}

int receive_answer(int sock, struct s_env *env, struct timeval *time)
{
	struct sockaddr addr;
	char msg[MSG_SIZE];
	socklen_t addrlen;
	int retval;

	bzero(msg, MSG_SIZE);
	do {
		retval = recvfrom(sock, msg, MSG_SIZE, MSG_PEEK, &addr, &addrlen);
		if (retval != -1) {
	/*
			for (int i = 0; i < retval; i++) {
				printf("%.2hhx", msg[i]);
				if (i % 15 == 0 && i != 0)
					printf("\n");
				else if (i % 2 == 1)
					printf(" ");
			}
	*/
			env->received++;
		}
		else {
			printf("error when receiving\n");
			env->error_received++;
			break;
		}
	} while (parse_response(env, msg, retval, time) == INCORRECT_IDENT);
	recvfrom(sock, msg, MSG_SIZE, 0, &addr, &addrlen);
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
	struct timeval end_time;
	struct timeval total_time;

	gettimeofday(&end_time, NULL);
	substract_timeval(&total_time, &end_time, &env->start_time);
	printf("--- %s ping statistics ---\n", env->args.dest);
	printf("%zu packets transmitted, %zu received, %ld%% packet loss, time %ldms\n", env->transmitted, env->received, env->received == 0 ? (env->transmitted == 0 ? 0 : 100) : 100 - env->received * 100 / env->transmitted, total_time.tv_sec * 1000 + total_time.tv_usec / 1000);
	if (env->args.flags & TIMESTAMP_IN_MSG) {
		env->avg.tv_sec = env->usec_tot / 1000000;
		env->avg.tv_usec = (env->usec_tot - (env->avg.tv_sec * 1000000));
		env->avg.tv_sec /= env->received;
		env->avg.tv_usec /= env->received;
		env->mdev.tv_sec = env->usec_dev / 1000000;
		env->mdev.tv_usec = (env->usec_dev - (env->mdev.tv_sec * 1000000));
		env->mdev.tv_sec /= env->received;
		env->mdev.tv_usec /= env->received;

		printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", (float)env->min.tv_sec * 1000 + (float)env->min.tv_usec / 1000, (float)env->avg.tv_sec * 1000 + (float)env->avg.tv_usec / 1000, (float)env->max.tv_sec * 1000 + (float)env->max.tv_usec / 1000 , (float)env->mdev.tv_sec * 1000 + (float)env->mdev.tv_usec / 1000 );
	}
}

int ping(struct s_env *env)
{
	int sock;
	char buffer[ICMP_HDR_SIZE + DATA_SIZE];

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0)
	{
		printf("Couldn't create the socket: %s\n", strerror(errno));
		return 0;
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
