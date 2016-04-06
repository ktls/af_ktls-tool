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

#ifndef SERVER_H_
#define SERVER_H_

#include <sys/socket.h>
#include <pthread.h>

#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>

typedef struct {
        gnutls_session_t session;
        int fd;
        struct sockaddr *cli_addr;
        socklen_t cli_addr_size;
} priv_data_st;

struct server_opts {
	unsigned verbose_level;
	unsigned port;
	bool tls;
	int store_file;
	// used to contact client on which port is server running
	int *port_mem;
	// release this once server is up
	pthread_cond_t *condition_initialized;
	bool ktls;
	bool no_echo;
};

extern int server_err;
extern void *run_server(void *arg);

#endif // SERVER_H_

