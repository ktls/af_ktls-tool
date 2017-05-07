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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <stdarg.h>

#include <assert.h>
#include <getopt.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/stat.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <errno.h>

#include <gnutls/gnutls.h>

#include <malloc.h>
#include <alloca.h>

#include "ktls.h"
#include "connection.h"
#include "common.h"
#include "benchmark.h"
#include "xlibgnutls.h"
#include "action.h"
#include "client.h"
#include "server.h"
#include "verify.h"

#define TLS_MAX_PACKET_LENGTH   ((size_t)(1 << 12))
#define DTLS_OVERHEAD           ((size_t)(13 + 8 + 16))
#define TLS_OVERHEAD            ((size_t)(5 + 8 + 16))

#define OPT_TLS                   't'
#define OPT_DTLS                  'd'
#define OPT_SERVER_HOST           3
#define OPT_SERVER_PORT           'p'
#define OPT_SRC_PORT              5
#define OPT_SENDFILE              6
#define OPT_SEND_KTLS_COUNT       7
#define OPT_SEND_GNUTLS_COUNT     8
#define OPT_PAYLOAD               9
#define OPT_SPLICE_COUNT          0x0A
#define OPT_SENDFILE_MTU          'm'
#define OPT_VERBOSE               'v'
#define OPT_HELP                  'h'
#define OPT_SENDFILE_MMAP         0x0E
#define OPT_SEND_KTLS_TIME        0x0F
#define OPT_SEND_GNUTLS_TIME      0x10
#define OPT_SPLICE_TIME           0x11
#define OPT_SENDFILE_SIZE         0x12
#define OPT_SPLICE_FILE           0x13
#define OPT_SERVER_STORE          0x14
#define OPT_SPLICE_ECHO_COUNT     0x15
#define OPT_SPLICE_ECHO_TIME      0x16
#define OPT_SERVER_KTLS           0x17
#define OPT_JSON                  'j'
#define OPT_DROP_CACHES           'c'
#define OPT_VERIFY_SENDPAGE       0x21
#define OPT_VERIFY_TRANSMISSION   0x22
#define OPT_VERIFY_SPLICE_READ    0x23
#ifdef TLS_VERIFY_HANDLING
#define OPT_VERIFY_HANDLING       0x24
#endif
#define OPT_OUTPUT                'o'
#define OPT_SENDFILE_USER         0x26
#define OPT_SERVER_NO_ECHO        0x27
#define OPT_SERVER_MTU            0x28
#define OPT_RAW_SEND_TIME         0x29
#ifdef TLS_SPLICE_SEND_RAW_TIME
#define OPT_SPLICE_SEND_RAW_TIME  0x2A
#endif
#define OPT_PLAIN_SENDFILE        0x2B
#define OPT_PLAIN_SENDFILE_USER   0x2C
#define OPT_PLAIN_SPLICE_EMU      0x2D
#define OPT_PLAIN_SENDFILE_MMAP   0x2E
#define OPT_TCP                   0x2F
#define OPT_UDP                   0x30
#define OPT_SEND_RAW_COUNT       0x32
#define OPT_SHORT_OPTS          "td\x03:p:\x05:\x06:\x07:\x08:\x09:\x0A:m:vh\x0E:\x0F:\x10:\x11:\x12\x13\x14:\x15:\x16:\x17\x18\x19jc\x21\x22\x23\x24\x25o:\x26:\x27\x28:\x29:\x2A:\x2B:\x2C:\x2D:\x2E:\x2F\x30"

static int thread_server_port = 0;

static struct option long_options[] = {
	/* -t   */{"tls",                   no_argument,        0,  OPT_TLS},
	/* -d   */{"dtls",                  no_argument,        0,  OPT_DTLS},
	/* 0x3  */{"server-host",           required_argument,  0,  OPT_SERVER_HOST},
	/* -p   */{"server-port",           required_argument,  0,  OPT_SERVER_PORT},
	/* 0x05 */{"src-port",              required_argument,  0,  OPT_SRC_PORT},
	/* 0x06 */{"sendfile",              required_argument,  0,  OPT_SENDFILE},
	/* 0x07 */{"send-ktls-count",       required_argument,  0,  OPT_SEND_KTLS_COUNT},
	/* 0x08 */{"send-gnutls-count",     required_argument,  0,  OPT_SEND_GNUTLS_COUNT},
	/* 0x09 */{"payload",               required_argument,  0,  OPT_PAYLOAD},
	/* 0x0A */{"splice-count",          required_argument,  0,  OPT_SPLICE_COUNT},
	/* -m   */{"sendfile-mtu",          required_argument,  0,  OPT_SENDFILE_MTU},
	/* -v   */{"verbose",               no_argument,        0,  OPT_VERBOSE},
	/* -h   */{"help",                  no_argument,        0,  OPT_HELP},
	/* 0x0E */{"sendfile-mmap",         required_argument,  0,  OPT_SENDFILE_MMAP},
	/* 0x0F */{"send-ktls-time",        required_argument,  0,  OPT_SEND_KTLS_TIME},
	/* 0x10 */{"send-gnutls-time",      required_argument,  0,  OPT_SEND_GNUTLS_TIME},
	/* 0x11 */{"splice-time",           required_argument,  0,  OPT_SPLICE_TIME},
	/* 0x12 */{"sendfile-size",         required_argument,  0,  OPT_SENDFILE_SIZE},
	/* 0x13 */{"splice-file",           required_argument,  0,  OPT_SPLICE_FILE},
	/* 0x14 */{"server-store",          required_argument,  0,  OPT_SERVER_STORE},
	/* 0x15 */{"splice-echo-count",     required_argument,  0,  OPT_SPLICE_ECHO_COUNT},
	/* 0x16 */{"splice-echo-time",      required_argument,  0,  OPT_SPLICE_ECHO_TIME},
	/* 0x17 */{"server-ktls",           no_argument,        0,  OPT_SERVER_KTLS},
	/* -j   */{"json",                  no_argument,        0,  OPT_JSON},
	/* -c   */{"drop-caches",           no_argument,        0,  OPT_DROP_CACHES},
	/* 0x21 */{"verify-sendpage",       no_argument,        0,  OPT_VERIFY_SENDPAGE},
	/* 0x22 */{"verify-transmission",   no_argument,        0,  OPT_VERIFY_TRANSMISSION},
	/* 0x23 */{"verify-splice-read",    no_argument,        0,  OPT_VERIFY_SPLICE_READ},
#ifdef TLS_VERIFY_HANDLING
	/* 0x24 */{"verify-handling",       no_argument,        0,  OPT_VERIFY_HANDLING},
#endif
	/* -o   */{"output",                required_argument,  0,  OPT_OUTPUT},
	/* -o   */{"sendfile-user",         required_argument,  0,  OPT_SENDFILE_USER},
	/* 0x27 */{"server-no-echo",        no_argument,        0,  OPT_SERVER_NO_ECHO},
	/* 0x28 */{"server-mtu",            required_argument,  0,  OPT_SERVER_MTU},
	/* 0x29 */{"raw-send-time",         required_argument,  0,  OPT_RAW_SEND_TIME},
#ifdef TLS_SPLICE_SEND_RAW_TIME
	/* 0x2A */{"splice-send-raw-time",  required_argument,  0,  OPT_SPLICE_SEND_RAW_TIME},
#endif
	/* 0x2B */{"plain-sendfile",        required_argument,  0,  OPT_PLAIN_SENDFILE},
	/* 0x2C */{"plain-sendfile-user",   required_argument,  0,  OPT_PLAIN_SENDFILE_USER},
	/* 0x2D */{"plain-splice-emu",      required_argument,  0,  OPT_PLAIN_SPLICE_EMU},
	/* 0x2E */{"plain-sendfile-mmap",   required_argument,  0,  OPT_PLAIN_SENDFILE_MMAP},
	/* 0x2F */{"tcp",                   no_argument,        0,  OPT_TCP},
	/* 0x30 */{"udp",                   no_argument,        0,  OPT_UDP},
	/* 0x31 */{"send-raw-count",        required_argument,  0,  OPT_SEND_RAW_COUNT},
	{0, 0, 0, 0}
};


static void print_help(char *progname) {
	static const char *help_msg = \
		"Usage: %s OPTIONS\n"
		"Benchmark Gnu TLS and AL_TLS kernel implementation\n"
		"\nOptions:\n\n"
		"\t--tls|-t                     benchmark over TLS protocol\n"
		"\t--dtls|-d                    benchmark over DTLS protocol; the default is TLS\n"
		"\t--tcp                        benchmark over TCP protocol\n"
		"\t--udp                        benchmark over UDP protocol; the default is TCP\n"
		"\t--server-host|-h HOST        specify destination host; if omitted, server is run in a thread\n"
		"\t--server-port|-p PORT        specify destination port; if omitted, 5557 is used if server-host specified,\n"
		"\t                             otherwise port for thread server will be assigned\n"
		"\t--src-port PORT              specify source port to bind to; if omitted, assigned by OS\n"
		"\t--payload SIZE               specify TLS/DTLS and AF_KTLS packet payload;\n"
		"\t                             applies for:\n"
		"\t                               --splice-{time,count}\n"
		"\t                               --send-gnutls-{time,count}\n"
		"\t                               --send-ktls-{time,count}\n"
		"\t--drop-caches|-c             drop caches before each test (root needed)\n"
		"\n"
		"\t--server-store FILE          store received content to a file; only if run with thread server\n"
		"\t--server-ktls                use AF_KTLS on server side as well; only if run with thread server\n"
		"\n"
		"\t--sendfile FILE              perform sendfile(2) using AF_KTLS, send file FILE\n"
		"\t--sendfile-mtu SIZE|-m SIZE  specify sendfile(2) MTU\n"
		"\t--sendfile-mmap FILE         mmap(2) file FILE before sendfile(2)\n"
		"\t--sendfile-size SIZE         specify size of FILE for sendfile(2); otherwise the whole file is sent\n"
		"\n"
		"\t--send-ktls-count COUNT      perform send(2) with zero content using AF_KTLS COUNT times\n"
		"\t--send-ktls-time TIME        perform send(2) with zero content using AF_KTLS TIME secs\n"
		"\t--send-gnutls-count COUNT    perform send(2) with zero content using Gnu TLS COUNT times\n"
		"\t--send-gnutls-time TIME      perform send(2) with zero content using Gnu TLS TIME secs\n"
		"\t--raw-send-time TIME         send raw to server, server will return encrypted\n"
		"\n"
		"\t--splice-count COUNT         perform splice(2) COUNT times\n"
		"\t--splice-time TIME           perform splice(2) TIME secs\n"
		"\t--splice-file FILE           specify file to be used with --splice-{count,time}\n"
		"\t--splice-echo-count COUNT    perform echo splice(2) with server COUNT times\n"
		"\t--splice-echo-time TIME      perform echo splice(2) with server TIME secs\n"
#ifdef TLS_SPLICE_SEND_RAW_TIME
		"\t--splice-send-raw-time TIME  perform splice(2) on AF_KTLS and send raw data\n"
#endif
		"\n"
		"\t--verify-sendpage            verify tls_sendpage() kernel implementation\n"
		"\t--verify-transmission        verify tls_sendmsg(), tls_recvmsg() kernel implementation\n"
		"\t--verify-splice-read         verify tls_splice_read() kernel implementation\n"
#ifdef TLS_VERIFY_HANDLING
		"\t--verify-handling            verify tls_setsockopt()/tls_getsockopt() kernel implementation\n"
#endif
		"\n"
		"\t--plain-sendfile FILE        send file FILE unencrypted using sendfile(2)\n"
		"\t--plain-sendfile-user FILE   send file FILE unencrypted using read(2) and send(2)\n"
		"\t--plain-splice-emu FILE      send file FILE unencrypted using sendfile splice(2) emulation\n"
		"\t--plain-sendfile-mmap FILE   send file FILE unencrypted using mmap(2), read(2) and send(2)\n"
		"\n"
		"\t--output|-o                  set output file\n"
		"\t--verbose|-v                 be verbose like an old lady at marketplace, can be used multiple times\n"
		"\t--json|-j                    output in JSON instead of text\n"
		"\t--help|-h                    print this help\n\n";

	assert(progname);
	printf(help_msg, progname);
}

static int parse_opts(struct client_opts *opts, int argc, char *argv[]) {
	int c;
	int idx = 0;
	char *tmp_ptr = NULL;
	bool protocol_seen = false;
	bool no_tls_protocol_seen = false;

	// assign default values at first
	opts->tls = true;
	opts->tcp = true;
	opts->server_port = 5557;
	opts->src_port = 0;
	opts->sendfile = NULL;
	opts->send_raw_count = 0;
	opts->send_ktls_count = 0;
	opts->send_gnutls_count = 0;
	opts->payload_size = 1400;
	opts->verbose_level = VERBOSE_LEVEL_SILENT;
	opts->sendfile_mtu = 0;
	opts->splice_count = 0;
	opts->send_ktls_time = 0;
	opts->send_gnutls_time = 0;
	opts->splice_time = 0;
	opts->sendfile_mmap = NULL;
	opts->sendfile_size = 0;
	opts->server_host = NULL;
	opts->server_store = 0;
	opts->splice_echo_count = 0;
	opts->splice_echo_time = 0;
	opts->server_ktls = false;
	opts->json = false;
	opts->drop_caches = false;
	opts->verify = VERIFY_NONE;
	opts->output = NULL;
	opts->sendfile_user = NULL;
	opts->server_no_echo = false;
	opts->raw_send_time = 0;
#ifdef TLS_SPLICE_SEND_RAW_TIME
	opts->splice_send_raw_time = 0;
#endif
	opts->plain_sendfile = NULL;
	opts->plain_sendfile_user = NULL;
	opts->plain_sendfile_mmap = NULL;
	opts->plain_splice_emu = NULL;
	// we will check for multiple occurrences for these, default values assigned
	// later
	opts->splice_file = NULL;
	opts->server_mtu = 0;

	for (;;) {
		c = getopt_long (argc, argv, OPT_SHORT_OPTS, long_options, &idx);

		if (c == -1) // we are done
			break;

		switch (c) {
			case OPT_TLS:
				if (protocol_seen) {
					print_error("option '--dtls' is disjoint with --tls");
					return 1;
				}
				if (no_tls_protocol_seen) {
					print_error("option --dtls/--tls is disjoint with --udp/--tcp");
					return 1;
				}
				protocol_seen = true;
				opts->tls = true;
				break;
			case OPT_DTLS:
				if (protocol_seen) {
					print_error("option '--dtls' is disjoint with --tls");
					return 1;
				}
				if (no_tls_protocol_seen) {
					print_error("option --dtls/--tls is disjoint with --udp/--tcp");
					return 1;
				}
				protocol_seen = true;
				opts->tls = false;
				break;
			case OPT_TCP:
				if (no_tls_protocol_seen && !opts->tcp) {
					print_error("option --tcp is disjoint with --udp");
					return 1;
				}
				if (protocol_seen) {
					print_error("option --tcp/--udp is disjoint with --tls/--dtls");
					return 1;
				}
				no_tls_protocol_seen = true;
				opts->tcp = true;
				break;
			case OPT_UDP:
				if (no_tls_protocol_seen && opts->tcp) {
					print_error("option --udp is disjoint with --tcp");
					return 1;
				}
				if (protocol_seen) {
					print_error("option --tcp/--udp is disjoint with --tls/--dtls");
					return 1;
				}
				no_tls_protocol_seen = true;
				opts->tcp = false;
				break;
			case OPT_SERVER_HOST:
				if (opts->server_host) {
					print_error("multiple --server-host supplied");
					return -1;
				}
				opts->server_host = optarg;
				break;
			case OPT_SERVER_PORT:
				opts->server_port = strtoul(optarg, &tmp_ptr, 10);
				if (*tmp_ptr != '\0' || opts->server_port > 65535) {
					print_error("unknown destination port '%s'", optarg);
					return -1;
				}
				break;
			case OPT_SRC_PORT:
				opts->src_port = strtoul(optarg, &tmp_ptr, 10);
				if (*tmp_ptr != '\0' || opts->src_port > 65535) {
					print_error("unknown source port '%s'", optarg);
					return -1;
				}
				break;
			case OPT_SENDFILE:
				opts->sendfile = optarg;
				break;
			case OPT_SEND_RAW_COUNT:
				if (opts->send_raw_count) {
					print_error("multiple --send-ktls-count supplied");
					return -1;
				}
				opts->send_raw_count = strtoul(optarg, &tmp_ptr, 10);
				if (*tmp_ptr != '\0' || opts->send_raw_count == 0) {
					print_error("unknown send count '%s'", optarg);
					return -1;
				}
				break;
			case OPT_SEND_KTLS_COUNT:
				if (opts->send_ktls_count) {
					print_error("multiple --send-ktls-count supplied");
					return -1;
				}
				opts->send_ktls_count = strtoul(optarg, &tmp_ptr, 10);
				if (*tmp_ptr != '\0' || opts->send_ktls_count == 0) {
					print_error("unknown send count '%s'", optarg);
					return -1;
				}
				break;
			case OPT_SEND_GNUTLS_COUNT:
				if (opts->send_gnutls_count) {
					print_error("multiple --send-gnutls-count supplied");
					return -1;
				}
				opts->send_gnutls_count = strtoul(optarg, &tmp_ptr, 10);
				if (*tmp_ptr != '\0' || opts->send_gnutls_count == 0) {
					print_error("unknown send count '%s'", optarg);
					return -1;
				}
				break;
			case OPT_PAYLOAD:
				opts->payload_size = strtoul(optarg, &tmp_ptr, 10);
				if (*tmp_ptr != '\0' || opts->payload_size == 0) {
					print_error("unknown payload size '%s'", optarg);
					return -1;
				}
				break;
			case OPT_SPLICE_COUNT:
				opts->splice_count = strtoul(optarg, &tmp_ptr, 10);
				if (*tmp_ptr != '\0' || opts->splice_count == 0) {
					print_error("unknown splice(2) count '%s'", optarg);
					return -1;
				}
				break;
#ifdef TLS_SPLICE_SEND_RAW_TIME
			case OPT_SPLICE_SEND_RAW_TIME:
				opts->splice_send_raw_time = strtoul(optarg, &tmp_ptr, 10);
				if (*tmp_ptr != '\0' || opts->splice_send_raw_time == 0) {
					print_error("unknown splice(2) send raw time '%s'", optarg);
					return -1;
				}
				break;
#endif
			case OPT_SENDFILE_MTU:
				opts->sendfile_mtu = strtoul(optarg, &tmp_ptr, 10);
				if (*tmp_ptr != '\0' || opts->sendfile_mtu == 0) {
					print_error("unknown sendfile(2) MTU size '%s'", optarg);
					return -1;
				}
				break;
			case OPT_VERBOSE:
				if (opts->verbose_level < VERBOSE_LEVEL_ALL)
					opts->verbose_level++;
				break;
			case OPT_HELP:
				print_help(argv[0]);
				return -1;
				break;
			case OPT_SENDFILE_MMAP:
				opts->sendfile_mmap = optarg;
				break;
			case OPT_SEND_KTLS_TIME:
				if (opts->send_ktls_time) {
					print_error("multiple --send-ktls-time supplied");
					return -1;
				}
				opts->send_ktls_time = strtoul(optarg, &tmp_ptr, 10);
				if (*tmp_ptr != '\0' || opts->send_ktls_time == 0) {
					print_error("unknown send time '%s'", optarg);
					return -1;
				}
				break;
			case OPT_SEND_GNUTLS_TIME:
				if (opts->send_gnutls_time) {
					print_error("multiple --send-gnutls-time supplied");
					return -1;
				}
				opts->send_gnutls_time = strtoul(optarg, &tmp_ptr, 10);
				if (*tmp_ptr != '\0' || opts->send_gnutls_time == 0) {
					print_error("unknown send time '%s'", optarg);
					return -1;
				}
				break;
			case OPT_SPLICE_TIME:
				if (opts->splice_time) {
					print_error("multiple --send-splice-time supplied");
					return -1;
				}
				opts->splice_time = strtoul(optarg, &tmp_ptr, 10);
				if (*tmp_ptr != '\0' || opts->splice_time == 0) {
					print_error("unknown send time '%s'", optarg);
					return -1;
				}
				break;
			case OPT_SENDFILE_SIZE:
				if (opts->sendfile_size) {
					print_error("multiple --sendfile-size supplied");
					return -1;
				}
				opts->sendfile_size = strtoul(optarg, &tmp_ptr, 10);
				if (*tmp_ptr != '\0' || opts->sendfile_size == 0) {
					print_error("unknown size of a file '%s'", optarg);
					return -1;
				}
				break;
			case OPT_SPLICE_FILE:
				if (opts->splice_file) {
					print_error("multiple --splice-file supplied");
					return -1;
				}
				opts->splice_file = optarg;
				break;
			case OPT_SERVER_STORE:
				if (opts->server_store) {
					print_error("multiple --server-store supplied");
					return -1;
				}
				opts->server_store = open(optarg, O_WRONLY|O_CREAT|O_TRUNC);
				if (opts->server_store < 0) {
					perror(optarg);
					return -1;
				}
				break;
			case OPT_SPLICE_ECHO_COUNT:
				if (opts->splice_echo_count) {
					print_error("multiple --splice-echo-count supplied");
					return -1;
				}
				opts->splice_echo_count = strtoul(optarg, &tmp_ptr, 10);
				if (*tmp_ptr != '\0' || opts->splice_echo_count == 0) {
					print_error("unknown count '%s'", optarg);
					return -1;
				}
				break;
			case OPT_SPLICE_ECHO_TIME:
				if (opts->splice_echo_time) {
					print_error("multiple --splice-echo-time supplied");
					return -1;
				}
				opts->splice_echo_time = strtoul(optarg, &tmp_ptr, 10);
				if (*tmp_ptr != '\0' || opts->splice_echo_time == 0) {
					print_error("unknown time '%s'", optarg);
					return -1;
				}
				break;
			case OPT_RAW_SEND_TIME:
				if (opts->raw_send_time) {
					print_error("multiple --raw-send-send supplied");
					return -1;
				}
				opts->raw_send_time = strtoul(optarg, &tmp_ptr, 10);
				if (*tmp_ptr != '\0' || opts->raw_send_time == 0) {
					print_error("unknown raw send time '%s'", optarg);
					return -1;
				}
				break;
			case OPT_PLAIN_SENDFILE:
				if (opts->plain_sendfile) {
					print_error("multiple --plain-sendfile supplied");
					return -1;
				}
				opts->plain_sendfile = optarg;
				break;
			case OPT_PLAIN_SENDFILE_USER:
				if (opts->plain_sendfile_user) {
					print_error("multiple --plain-sendfile-user supplied");
					return -1;
				}
				opts->plain_sendfile_user = optarg;
				break;
			case OPT_PLAIN_SPLICE_EMU:
				if (opts->plain_splice_emu) {
					print_error("multiple --plain-splice-emu supplied");
					return -1;
				}
				opts->plain_splice_emu = optarg;
				break;
			case OPT_PLAIN_SENDFILE_MMAP:
				if (opts->plain_sendfile_mmap) {
					print_error("multiple --plain-sendfile-mmap supplied");
					return -1;
				}
				opts->plain_sendfile_mmap = optarg;
				break;
			case OPT_SERVER_NO_ECHO:
				opts->server_no_echo = true;
				break;
			case OPT_SERVER_KTLS:
				opts->server_ktls = true;
				break;
			case OPT_JSON:
				opts->json = true;
				break;
			case OPT_DROP_CACHES:
				opts->drop_caches = true;
				break;
			case OPT_VERIFY_SENDPAGE:
				opts->verify |= VERIFY_SENDPAGE;
				break;
			case OPT_VERIFY_TRANSMISSION:
				opts->verify |= VERIFY_TRANSMISSION;
				break;
			case OPT_VERIFY_SPLICE_READ:
				opts->verify |= VERIFY_SPLICE_READ;
				break;
#ifdef TLS_VERIFY_HANDLING
			case OPT_VERIFY_HANDLING:
				opts->verify |= VERIFY_HANDLING;
				break;
#endif
			case OPT_SENDFILE_USER:
				if (opts->sendfile_user) {
					print_error("multiple --sendfile-user supplied");
				}
				opts->sendfile_user = optarg;
				break;
			case OPT_OUTPUT:
				if (opts->output) {
					print_error("multiple --server-store supplied");
					return -1;
				}
				opts->output = optarg;
				break;
			case '?':
				print_help(argv[0]);
				return -1;
				break;
			default:
				/* should be unreachable */
				print_error("Unhandled parameter");
				assert(false);
		}
	}

	/* no additional arguments allowed */
	if (optind < argc) {
		print_error("unknown argument supplied: %s", argv[optind]);
		print_help(argv[0]);
		return -1;
	}

	if (!opts->sendfile &&
			!opts->send_gnutls_count &&
			!opts->send_raw_count &&
			!opts->send_ktls_count &&
			!opts->splice_count &&
			!opts->send_gnutls_time &&
			!opts->send_ktls_time &&
			!opts->splice_echo_count &&
			!opts->splice_echo_time &&
			!opts->splice_time &&
			!opts->sendfile_mmap &&
			!opts->sendfile_user &&
			!opts->raw_send_time &&
			!opts->plain_sendfile &&
			!opts->plain_sendfile_user &&
			!opts->plain_sendfile_mmap &&
#ifdef TLS_SPLICE_SEND_RAW_TIME
			!opts->plain_splice_emu &&
			!opts->splice_send_raw_time) {
#else
			!opts->plain_splice_emu) {
#endif
		if (!opts->verify) {
			print_error("specify at least one benchamrking or verification option");
			return -1;
		}

		if (opts->output) {
			print_error("output file stores results of benchmarks, nothing to store");
			return -1;
		}

	} else if (opts->verify) {
		print_error("to verify implementation, run only verification without benchnarking options");
		return -1;
	}

	if (opts->sendfile ||
			opts->send_gnutls_count ||
			opts->send_ktls_count ||
			opts->splice_count ||
			opts->send_gnutls_time ||
			opts->send_ktls_time ||
			opts->splice_echo_count ||
			opts->splice_echo_time ||
			opts->splice_time ||
			opts->sendfile_mmap ||
			opts->sendfile_user ||
			opts->verify) {
#ifdef TLS_SPLICE_SEND_RAW_TIME
		if (opts->raw_send_time || opts->splice_send_raw_time) {
#else
		if (opts->raw_send_time) {
#endif
			print_error("raw send tests can be run only as a standalone benchmark");
			return -1;
		}

		if (opts->plain_sendfile ||
				opts->plain_sendfile_mmap ||
				opts->plain_sendfile_user ||
				opts->plain_splice_emu) {
			print_error("plain tests can be run only as a standalone benchmark");
			return -1;
		}
	}

	if (opts->verify && (opts->verify & (opts->verify - 1))) {
		print_error("only one verification allowed per run");
		return -1;
	}

	if (opts->sendfile_user && !opts->sendfile_mtu) {
		print_error("--sendfile-user requires MTU specified with --sendfile-mtu");
		return -1;
	}

	if (opts->sendfile_mmap && !opts->sendfile_mtu) {
		print_error("--sendfile-mmap requires MTU specified with --sendfile-mtu");
		return -1;
	}

	if (!opts->sendfile_mtu &&
			(opts->plain_sendfile ||
			 opts->plain_sendfile_mmap ||
			 opts->plain_splice_emu ||
			 opts->plain_sendfile_user)) {
		print_error("--sendfile-mtu required");
		return -1;
	}

	if (opts->sendfile_mtu &&
			!opts->sendfile &&
			!opts->sendfile_user &&
			!opts->splice_echo_count &&
			!opts->splice_echo_time &&
			!opts->plain_sendfile &&
			!opts->plain_sendfile_mmap &&
			!opts->plain_sendfile_user &&
#ifdef TLS_SPLICE_SEND_RAW_TIME
			!opts->splice_send_raw_time &&
#endif
			!opts->plain_splice_emu) {
		print_error("invalid use of --sendfile-mtu");
		return -1;
	}


	if (!opts->splice_count && !opts->splice_time && opts->splice_file) {
		print_error("--splice-file can be used only with --splice-{time,count}");
		return -1;
	}

	if (opts->server_host && opts->server_ktls) {
		print_error("--server-ktls can be used only with threaded server (no --server-host)");
		return -1;
	}

	if (opts->server_host && opts->server_mtu) {
		print_error("--server-mtu can be used only with threaded server (no --server-host)");
		return -1;
	} else {
		opts->server_mtu = SERVER_MAX_MTU;
	}

	if (opts->server_host && opts->server_store) {
		print_error("--server-store can be used only with threaded server (no --server-host)");
		return -1;
	}

	if (opts->server_no_echo && opts->server_host) {
		print_error("--server-no-echo can be used only with threaded server");
		return -1;
	}

	if (opts->server_no_echo && (opts->splice_echo_count || opts->splice_echo_time)) {
		print_error("--server-no-echo is not acceptable when a response from the server is needed"
						" (--splice-echo-{time,count}");
		return -1;
	}

#ifdef BENCHMARK_RECV
	if (opts->server_no_echo
			&& (opts->send_gnutls_time || opts->send_gnutls_count ||
				opts->send_ktls_time || opts->send_ktls_count)) {
		print_error("cannot use --server-no-echo with send-{gnutls,ktls}-{count,time}"
					" (or BENCHMARK_RECV should not be set");
		return -1;
	}
#endif

	/*
	 * we will perform splice(2) on /dev/zero by default in order to avoid the
	 * impact of disk drive and FS
	 */
	if (opts->splice_count || opts->splice_time)
		if (!opts->splice_file)
			opts->splice_file = "/dev/zero";

	if (opts->send_ktls_count || opts->sendfile || opts->splice_count
			|| opts->send_ktls_time || opts->send_gnutls_time || opts->splice_time
			|| opts->splice_echo_count || opts->splice_echo_time || opts->verify
#ifdef TLS_SPLICE_SEND_RAW_TIME
			|| opts->splice_send_raw_time) {
#else
			) {
#endif
		opts->ktls = true;
	}

	return 0;
}

static void print_opts(const struct client_opts *opts) {
	print_debug_client(opts, "protocol:			%s", opts->tls ? "TLS" : "DTLS");
	if (!opts->server_host) {
		print_debug_client(opts, "server:			thread server");
		print_debug_client(opts, "server uses AF_KTLS:	%s", opts->server_ktls ? "true" : "false");
		print_debug_client(opts, "server lib:			Gnu TLS");
		print_debug_client(opts, "server mtu:			%u", opts->server_mtu);
	} else
		print_debug_client(opts, "destination host:		%s", opts->server_host);
	print_debug_client(opts, "drop caches:		%s", opts->drop_caches ? "true" : "false");
	print_debug_client(opts, "destination port:		%u", opts->server_port);
	print_debug_client(opts, "source port:		%u", opts->src_port);
	if (opts->verify & VERIFY_SENDPAGE) {
		print_debug_client(opts, "verifying tls_sendpage() in kernel");
		return;
	}
	if (opts->verify & VERIFY_TRANSMISSION) {
		print_debug_client(opts, "verifying tls_sendmsg()/tls_recvmsg() in kernel");
		return;
	}
	if (opts->verify & VERIFY_SPLICE_READ) {
		print_debug_client(opts, "verifying tls_splice_read() in kernel");
		return;
	}
	print_debug_client(opts, "packet payload:		%u", opts->payload_size);
	if (opts->sendfile || opts->sendfile_user) {
		if (opts->sendfile_mtu)
			print_debug_client(opts, "sendfile(2) MTU:		%u", opts->sendfile_mtu);
		else
			print_debug_client(opts, "sendfile(2) MTU:		max");
	}

	if (opts->sendfile_mmap)
		print_debug_client(opts, "mmap(2) send file %s", opts->sendfile_mmap);
	print_debug_client(opts, "output type:		%s", opts->json ? "JSON" : "text");
	if (opts->raw_send_time)
		print_debug_client(opts, "raw send time: %d", opts->raw_send_time);
	if (opts->plain_sendfile)
		print_debug_client(opts, "plain sendfile: %s", opts->plain_sendfile);
	if (opts->plain_sendfile_user)
		print_debug_client(opts, "plain user send file: %s", opts->plain_sendfile_user);
	if (opts->plain_splice_emu)
		print_debug_client(opts, "plain send file emulation using splice: %s", opts->plain_splice_emu);
	if (opts->plain_sendfile_mmap)
		print_debug_client(opts, "plain send file mmap(2): %s", opts->plain_splice_emu);
#ifdef TLS_SPLICE_SEND_RAW_TIME
	if (opts->splice_send_raw_time)
		print_debug_client(opts, "raw splice send raw time: %u", opts->splice_send_raw_time);
#endif
	if (opts->server_store)
		print_debug_client(opts, "server store file (fd):		'%s'", opts->server_store);
	if (opts->sendfile)
		print_debug_client(opts, "using sendfile(2) on file '%s'", opts->sendfile);
	if (opts->sendfile_user)
		print_debug_client(opts, "sending file '%s'", opts->sendfile_user);
	if (opts->send_ktls_count)
		print_debug_client(opts, "using send(2) on AF_KTLS socket %u times", opts->send_ktls_count);
	if (opts->send_ktls_time)
		print_debug_client(opts, "using send(2) on AF_KTLS socket %u secs", opts->send_ktls_time);
	if (opts->send_gnutls_count)
		print_debug_client(opts, "using gnutls_record_send() %u times", opts->send_gnutls_count);
	if (opts->send_gnutls_time)
		print_debug_client(opts, "using gnutls_record_send() %u secs", opts->send_gnutls_time);
	if (opts->splice_file)
		print_debug_client(opts, "using splice(2) on file '%s'", opts->splice_file);
	if (opts->splice_count)
		print_debug_client(opts, "using splice(2) %u times", opts->splice_count);
	if (opts->splice_time)
		print_debug_client(opts, "using splice(2) %u secs", opts->splice_time);
	if (opts->splice_echo_time)
		print_debug_client(opts, "using splice(2) echo %u secs", opts->splice_echo_time);
	if (opts->splice_echo_count)
		print_debug_client(opts, "using splice(2) echo %u times", opts->splice_echo_count);
	if (opts->server_no_echo)
		print_debug_client(opts, "server is not echoing data messages", opts->splice_echo_count);
}

extern int do_drop_caches(void) {
	int fd;
	int ret;

	fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
	if (fd < 0) {
		perror("open:failed to drop caches");
		return fd;
	}

	ret = write(fd, "3", 1);
	if (ret < 0) {
		perror("write:failed to drop caches");
		return ret;
	}

	ret = close(fd);
	if (ret < 0)
		perror("close:failed to drop caches");

	return ret;
}

static int do_plain_action(const struct client_opts *opts, int sd) {
	int err;

	if (opts->plain_sendfile) {
		err = do_plain_sendfile(opts, sd);
		if (err < 0) {
			print_error("failed to do plain sendfile");
			goto out;
		}
		DO_DROP_CACHES(opts);
	}

	if (opts->plain_sendfile_user) {
		err = do_plain_sendfile_user(opts, sd);
		if (err < 0) {
			print_error("failed to do plain sendfile");
			goto out;
		}
		DO_DROP_CACHES(opts);
	}

	if (opts->plain_sendfile_mmap) {
		err = do_plain_sendfile_mmap(opts, sd);
		if (err < 0) {
			print_error("failed to do plain send file with mmap(2)");
			goto out;
		}
		DO_DROP_CACHES(opts);
	}

	if (opts->plain_splice_emu) {
		err = do_plain_splice_emu(opts, sd);
		if (err < 0) {
			print_error("failed to do splice(2) sendfile emulation");
			goto out;
		}
		DO_DROP_CACHES(opts);
	}

out:
	return err;
}

static int do_action(const struct client_opts *opts, gnutls_session_t session,  int udp_sd) {
	int tls_init = false, err;
	char *mem = NULL; //just a bunch of zeroed memory used as a source data

	if (opts->send_raw_count || opts->send_ktls_count || opts->send_gnutls_count ||
			opts->send_ktls_time || opts->send_gnutls_time ||
			opts->splice_echo_time || opts->splice_echo_count ||
#ifdef TLS_SPLICE_SEND_RAW_TIME
			opts->raw_send_time || opts->splice_send_raw_time) {
#else
			opts->raw_send_time) {
#endif
		err = posix_memalign((void **) &mem, 16, opts->payload_size);
		memset(mem, 0, opts->payload_size);
		if (err) {
			perror("posix_memalign");
			return -1;
		}
	}

	DO_DROP_CACHES(opts); // drop before first run to be fair

	if (opts->send_gnutls_count) {
		err = do_gnutls_send_count(opts, session, mem);
		if (err < 0) {
			print_error("failed to do Gnu TLS gnutls_record_send()");
			goto action_error;
		}
		DO_DROP_CACHES(opts);
	}

	if (opts->send_gnutls_time) {
		err = do_gnutls_send_time(opts, session, mem);
		if (err < 0) {
			print_error("failed to do Gnu TLS gnutls_record_send()");
			goto action_error;
		}
		DO_DROP_CACHES(opts);
	}

	if (opts->sendfile_user) {
		err = do_sendfile_user(opts, session);
		if (err < 0) {
			print_error("failed to do Gnu TLS send file with user space buffer");
			goto action_error;
		}
		DO_DROP_CACHES(opts);
	}

	if (opts->sendfile_mmap) {
		err = do_sendfile_mmap(opts, session);
		if (err < 0) {
			print_error("failed to do Gnu TLS send file with mmap(2)");
			goto action_error;
		}
		DO_DROP_CACHES(opts);
	}

	if (opts->raw_send_time) {
		err = do_raw_send_time(opts, session, udp_sd, mem);
		if (err < 0) {
			print_error("failed to do raw send");
			goto action_error;
		}
		DO_DROP_CACHES(opts);
	}

	if (opts->ktls) {
#ifdef TLS_SET_MTU
		err = ktls_socket_init(session, udp_sd, opts->sendfile_mtu, true, opts->tls);
#else
		err = ktls_socket_init(session, udp_sd, true, opts->tls);
#endif
		if (err < 0) {
			print_error("failed to get AF_KTLS socket");
			goto action_error;
		}
		tls_init = true;
		DO_DROP_CACHES(opts);
	}

#ifdef TLS_SPLICE_SEND_RAW_TIME
	if (opts->splice_send_raw_time) {
		err = do_splice_send_raw_time(opts, udp_sd, ksd, mem);
		if (err < 0) {
			print_error("failed to do splice raw send");
			goto action_error_tls_init;
		}
		DO_DROP_CACHES(opts);
	}
#endif

	if (opts->splice_count) {
		err = do_splice_count(opts, udp_sd);
		if (err < 0) {
			print_error("failed to do splice(2)");
			goto action_error_tls_init;
		}
		DO_DROP_CACHES(opts);
	}

	if (opts->splice_time) {
		err = do_splice_time(opts, udp_sd);
		if (err < 0) {
			print_error("failed to do splice(2) time");
			goto action_error_tls_init;
		}
		DO_DROP_CACHES(opts);
	}

	if (opts->splice_echo_time) {
		err = do_splice_echo_time(opts, udp_sd, mem);
		if (err < 0) {
			print_error("failed to do splice(2) echo time");
			goto action_error_tls_init;
		}
		DO_DROP_CACHES(opts);
	}

	if (opts->splice_echo_count) {
		err = do_splice_echo_count(opts, udp_sd, mem);
		if (err < 0) {
			print_error("failed to do splice(2) echo count");
			goto action_error_tls_init;
		}
		DO_DROP_CACHES(opts);
	}

	if (opts->sendfile) {
		err = do_sendfile(opts, udp_sd);
		if (err < 0) {
			print_error("failed to do sendfile(2)");
			goto action_error_tls_init;
		}
		DO_DROP_CACHES(opts);
	}

	if (opts->send_raw_count) {
		err = do_send_count(opts, opts->send_raw_count, udp_sd, mem, session, 0);
		if (err < 0) {
			print_error("failed to do AF_ALG send() count");
			goto action_error;
		}
		DO_DROP_CACHES(opts);
	}

	if (opts->send_ktls_count) {
		err = do_send_count(opts, opts->send_ktls_count, udp_sd, mem, session, 0);
		if (err < 0) {
			print_error("failed to do AF_ALG send() count");
			goto action_error_tls_init;
		}
		DO_DROP_CACHES(opts);
	}

	if (opts->send_ktls_time) {
		err = do_send_time(opts, udp_sd, mem, 0);
		if (err < 0) {
			print_error("failed to do AF_ALG send() time");
			goto action_error_tls_init;
		}
		DO_DROP_CACHES(opts);
	}

	if (opts->verify & VERIFY_SENDPAGE) {
		err = verify_sendpage(udp_sd, opts->tls);
		if (err < 0) {
			print_error("failed to verify tls_sendpage() in kernel");
			goto action_error_tls_init;
		}
		DO_DROP_CACHES(opts);
	}

	if (opts->verify & VERIFY_TRANSMISSION) {
		err = verify_transmission(udp_sd);
		if (err < 0) {
			print_error("failed to verify tls_sendmsg()/tls_recvmsg() in kernel");
			goto action_error_tls_init;
		}
		DO_DROP_CACHES(opts);
	}

	if (opts->verify & VERIFY_SPLICE_READ) {
		err = verify_splice_read(udp_sd);
		if (err < 0) {
			print_error("failed to verify tls_splice_read() in kernel");
			goto action_error_tls_init;
		}
		DO_DROP_CACHES(opts);
	}

#ifdef TLS_VERIFY_HANDLING
	if (opts->verify & VERIFY_HANDLING) {
		err = verify_handling(udp_sd, opts->tls);
		if (err < 0) {
			print_error("failed to verify tls_getsockopt()/tls_setsockopt() in kernel");
			goto action_error_tls_init;
		}
		DO_DROP_CACHES(opts);
	}
#endif

	err = 0;
action_error_tls_init:
	if (tls_init)
		ktls_socket_destruct(session, udp_sd, true);
action_error:
	if (mem)
		free(mem);
	return err;
}

static int run_client(const struct client_opts *opts) {
	int err;
	int sd = 0;
	const char *host;
	gnutls_session_t session;

	/* connect to the peer */
	host = opts->server_host ? opts->server_host : "localhost";

	if (opts->plain_sendfile ||
			opts->plain_sendfile_user ||
			opts->plain_sendfile_mmap ||
			opts->plain_splice_emu) {
		if (opts->tcp)
			sd = tcp_connect(host, opts->server_port);
		else
			sd = udp_connect(host, opts->server_port);

		if (sd < 0)
			goto end;

		// these tests do not require TLS, so no handshake is done and so
		err = do_plain_action(opts, sd);

	} else {
		if (opts->tls)
			sd = tcp_connect(host, opts->server_port);
		else
			sd = udp_connect(host, opts->server_port);

		if (sd < 0)
			goto end;

		if (opts->tls)
			err = xlibgnutls_tls_handshake(&session, sd, opts->verbose_level);
		else
			err = xlibgnutls_dtls_handshake(&session, sd, opts->verbose_level);

		if (err < 0) {
			print_error("failed to do handshake");
			goto end;
		}
		print_touch_reset(); // handshake does not taint benchmarks, so reset flag
		err = do_action(opts, session, sd);

		if (opts->tls)
			xlibgnutls_tls_terminate(session, opts->ktls);
		else
			xlibgnutls_dtls_terminate(session);
	}

end:
	if (opts->tls && sd > 0)
		tcp_close(sd);
	else if (!opts->tls && sd > 0)
		udp_close(sd);

	return err < 0 ? err : 0;
}

static void client_opts2server_opts(const struct client_opts *client_opts,
		struct server_opts *server_opts,
		int *server_port_loc,
		pthread_cond_t *condition_server_initialized) {
	server_opts->verbose_level = client_opts->verbose_level;
	server_opts->port = client_opts->server_port;
	server_opts->tls = client_opts->tls;
	server_opts->store_file = client_opts->server_store;
	server_opts->port_mem = server_port_loc;
	server_opts->condition_initialized = condition_server_initialized;
	server_opts->ktls = client_opts->server_ktls;
	server_opts->no_echo = client_opts->server_no_echo;
	server_opts->mtu = client_opts->server_mtu;
#ifdef TLS_SPLICE_SEND_RAW_TIME
	server_opts->raw_recv = (client_opts->raw_send_time || client_opts->splice_send_raw_time);
#else
	server_opts->raw_recv = client_opts->raw_send_time;
#endif
	server_opts->no_tls = (client_opts->plain_sendfile ||
			client_opts->plain_sendfile_mmap ||
			client_opts->plain_sendfile_user ||
			client_opts->plain_splice_emu);
	server_opts->tcp = client_opts->tcp;
}

int main(int argc, char *argv[]) {
	int err;
	FILE *f_out = NULL;
	pthread_mutex_t mutex;
	pthread_cond_t condition_server_initialized;
	pthread_t thread_server;
	struct client_opts opts;
	struct server_opts server_opts;

	print_init();

	if (argc == 1) {
		print_error("no options supplied");
		print_help(argv[0]);
		err = 1;
		goto client_end;
	}

	err = parse_opts(&opts, argc, argv);
	if (err) {
		err = 2;
		goto client_end;
	}

	if (opts.output) {
		f_out = fopen(opts.output, "w");
		if (!f_out) {
			perror(opts.output);
			goto client_end;
		}
	}

	if (opts.verbose_level >= VERBOSE_LEVEL_CLIENT)
		print_opts(&opts);

	if (!opts.server_host) {
		err = pthread_cond_init(&condition_server_initialized, NULL);
		if (err) {
			perror("failed to init thread server init condition");
			err = 4;
			goto client_end;
		}

		err = pthread_mutex_init(&mutex, NULL);
		if (err) {
			pthread_cond_destroy(&condition_server_initialized);
			perror("failed to init mutex");
			err = 5;
			goto client_end;
		}

		client_opts2server_opts(&opts, &server_opts, &thread_server_port, &condition_server_initialized);

		err = pthread_create(&thread_server, NULL, run_server, &server_opts);
		if (err) {
			pthread_cond_destroy(&condition_server_initialized);
			pthread_mutex_destroy(&mutex);
			print_error("thread server creation failed");
			err = 6;
			goto client_end;
		}
		//wait for server to spawn and init
		pthread_mutex_lock(&mutex);
		pthread_cond_wait(&condition_server_initialized, &mutex);
		// retrieve port where the server resists
		opts.server_port = thread_server_port;
	}

	print_stats_file(f_out ? f_out : stdout);
	print_stats_json(opts.json);
	err = run_client(&opts);

	if (!opts.server_host) {
		// TODO: server is not correctly terminated
		pthread_cancel(thread_server);
		pthread_cond_destroy(&condition_server_initialized);
		pthread_mutex_destroy(&mutex);
	}

	if (!opts.verify && print_touched())
		print_warning("benchmark results could be tainted due to output messages");

client_end:
	print_destruct();

	if (f_out) // has to be after print_destruct()
		fclose(f_out);
	if (opts.server_store)
		close(opts.server_store);

	return err;
}

