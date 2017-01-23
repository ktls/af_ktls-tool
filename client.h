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

#ifndef CLIENT_H_
#define CLIENT_H_

#include <stdbool.h>
#include <sys/time.h>

#define VERIFY_NONE           (0)
#define VERIFY_SENDPAGE       (1 << 0)
#define VERIFY_TRANSMISSION   (1 << 1)
#define VERIFY_SPLICE_READ    (1 << 2)
#define VERIFY_HANDLING       (1 << 3)

#define DO_DROP_CACHES(O)        if (O->drop_caches) { if (do_drop_caches()) return -1; }

struct client_opts {
	bool tls;
	bool tcp;
	const char *server_host;
	unsigned server_port;
	unsigned src_port;
	const char *sendfile;
	const char *sendfile_user;
	size_t sendfile_mtu;
	size_t sendfile_size;
	unsigned send_ktls_count;
	unsigned send_gnutls_count;
	unsigned payload_size;
	unsigned splice_count;
	unsigned verbose_level;
	const char *sendfile_mmap;
	time_t send_ktls_time;
	time_t send_gnutls_time;
	time_t splice_time;
	const char *splice_file;
	unsigned splice_echo_count;
	time_t splice_echo_time;
	bool json;
	bool drop_caches;
	int server_store;
	bool server_ktls;
	bool server_openssl;
	unsigned verify;
	const char *output;
	bool server_no_echo;
	unsigned server_mtu;
	bool offload;
	unsigned raw_send_time;
#ifdef TLS_SPLICE_SEND_RAW_TIME
	unsigned splice_send_raw_time;
#endif
	const char *plain_sendfile;
	const char *plain_sendfile_user;
	const char *plain_sendfile_mmap;
	const char *plain_splice_emu;
};

extern int do_drop_caches(void);

#endif // CLIENT_H_

