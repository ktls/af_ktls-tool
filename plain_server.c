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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include "server.h"
#include "plain_server.h"

#define BUFSIZE 65535

extern int plain_tcp_server(const struct server_opts *opts) {
	int err;
	int sd = 0;
	int sd_client = 0;
	socklen_t slen = sizeof(struct sockaddr_in);
	struct sockaddr_in si_me , si_other;
	char *buf = NULL;

    sd = socket(AF_INET , SOCK_STREAM , 0);
    if (sd == -1) {
        perror("socket");
        err = sd;
        goto end;
    }

    si_me.sin_family = AF_INET;
    si_me.sin_addr.s_addr = INADDR_ANY;
    si_me.sin_port = htons(opts->port);

    err = bind(sd,(struct sockaddr *)&si_me , sizeof(si_me));

    if (err < 0) {
        perror("bind");
        goto end;
    }

    listen(sd , 128);

    buf = malloc(BUFSIZE);
    if (!buf) {
    	perror("malloc");
    	goto end;
	}

	if (opts->condition_initialized) {
		// TODO: get actual port
		if (opts->port_mem)
			*opts->port_mem = opts->port;
		pthread_cond_broadcast(opts->condition_initialized);
	}

    sd_client = accept(sd, (struct sockaddr *)&si_other, (socklen_t*)&slen);
    if (sd_client < 0) {
		perror("accept");
		goto end;
    }

    for (;;) {
    	err = recv(sd_client, buf, BUFSIZE, 0);
    	if (err < 0) {
    		perror("recv");
    		goto end;
		}

		if (err == 0)
			break;

		if (opts->store_file)
			write(opts->store_file, buf, err);

		if (!opts->no_echo) {

			err = send(sd_client, buf, err, 0);
			if (err < 0) {
				perror("send");
				goto end;
			}
		}
	}

end:
	if (buf)
		free(buf);

	if (sd > 0)
		close(sd);

    return err;
}

extern int plain_udp_server(const struct server_opts *opts) {
	int err;
	int sd = 0;
	char *buf = NULL;
	struct sockaddr_in si_me, si_other;
	socklen_t slen = sizeof(si_other);

	sd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (sd < 0) {
		perror("socket");
		return sd;
	}

	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(opts->port);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);

	err = bind(sd, (struct sockaddr*) &si_me, sizeof(si_me));
	if (err < 0) {
		perror("bind");
		goto end;
	}

	buf = malloc(BUFSIZE);
	if (!buf) {
		perror("malloc");
		goto end;
	}

	if (opts->condition_initialized) {
		// TODO: get actual port
		if (opts->port_mem)
			*opts->port_mem = opts->port;
		pthread_cond_broadcast(opts->condition_initialized);
	}

	for (;;) {
		err = recvfrom(sd, buf, BUFSIZE, 0, (struct sockaddr*) &si_other, &slen);
		if (err < 0) {
			perror("recvfrom");
			goto end;
		}

		if (err == 0) {
			break;
		}

		if (opts->store_file)
			write(opts->store_file, buf, err);

		if (!opts->no_echo) {
			err = sendto(sd, buf, err, 0, (struct sockaddr*) &si_other, slen);
			if (err < 0) {
				perror("sendto");
				goto end;
			}
		}
	}

end:
   if (sd > 0)
   	   close(sd);

   if (buf)
   	   free(buf);

   return err;
}

