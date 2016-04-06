/*
 * af_ktls tool
 *
 * Copyright (C) 2016 Fridolin Pokorny <fpokorny@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>

#include "connection.h"

extern int udp_connect(const char *host, unsigned port)
{
	int err, sd, optval;
	struct sockaddr_in sa;

	sd = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	inet_pton(AF_INET, host, &sa.sin_addr);

#if defined(IP_DONTFRAG)
	optval = 1;
	setsockopt(sd, IPPROTO_IP, IP_DONTFRAG, (const void *) &optval, sizeof(optval));
#elif defined(IP_MTU_DISCOVER)
	optval = IP_PMTUDISC_DO;
	setsockopt(sd, IPPROTO_IP, IP_MTU_DISCOVER, (const void *) &optval, sizeof(optval));
#endif

	err = connect(sd, (struct sockaddr *) &sa, sizeof(sa));
	return err ? err : sd;
}

extern void udp_close(int sd) {
	close(sd);
}

extern int tcp_connect(const char *host, unsigned port) {
	int err, sd;
	struct sockaddr_in sa;

	sd = socket(AF_INET, SOCK_STREAM, 0);

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	inet_pton(AF_INET, host, &sa.sin_addr);

	err = connect(sd, (struct sockaddr *) &sa, sizeof(sa));

	return err ? err : sd;
}

extern void tcp_close(int sd) {
	shutdown(sd, SHUT_RDWR); //no more receptions
	close(sd);
}

