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

#include <stdio.h>
#include <stdbool.h>
#include <getopt.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"
#include "server.h"

#define OPT_TLS                 't'
#define OPT_DTLS                'd'
#define OPT_PORT                'p'
#define OPT_VERBOSE             'v'
#define OPT_STORE               's'
#define OPT_HELP                'h'
#define OPT_KTLS                'k'
#define OPT_NO_ECHO             'x'
#define OPT_MTU                 'm'
#define OPT_RAW_RECV            'r'
#define OPT_SHORT_OPTS          "tdp:vs:hxm:"

static struct option long_options[] = {
	/* -t */{"tls",                no_argument,        0,  OPT_TLS},
	/* -d */{"dtls",               no_argument,        0,  OPT_DTLS},
	/* -p */{"port",               required_argument,  0,  OPT_PORT},
	/* -v */{"verbose",            no_argument,        0,  OPT_VERBOSE},
	/* -s */{"store",              required_argument,  0,  OPT_STORE},
	/* -h */{"help",               no_argument,        0,  OPT_HELP},
	/* -k */{"ktls",               no_argument,        0,  OPT_KTLS},
	/* -x */{"no-echo",            no_argument,        0,  OPT_NO_ECHO},
	/* -m */{"mtu",                required_argument,  0,  OPT_MTU},
	/* -r */{"raw-recv",           no_argument,        0,  OPT_RAW_RECV},
	{0, 0, 0, 0}
};
static void print_help(char *progname) {
	static const char *help_msg = \
		"Usage: %s OPTIONS\n"
		"Benchmark Gnu TLS and AL_TLS kernel implementation (echo server)\n"
		"\nOptions:\n\n"
		"\t--tls|-t                     benchmark TLS protocol\n"
		"\t--dtls|-d                    benchmark DTLS protocol; the default is TLS\n"
		"\t--port|-p                    benchmark DTLS protocol; the default is TLS\n"
		"\t--verbose|-v                 be verbose like an old lady at marketplace, can be used multiple times\n"
		"\t--store FILE|-s FILE         store result to file FILE\n"
		"\t--ktls|-k                    use AF_KTLS for communication\n"
		"\t--no-echo                    do not echo data messages\n"
		"\t--raw_recv                   expect unencrypted data\n"
		"\t--mtu                        set MTU"
		"\t--help|-h                    print this help\n\n";

	assert(progname);
	printf(help_msg, progname);
}

static int parse_opts(struct server_opts *opts, int argc, char *argv[]) {
	int c;
	int idx = 0;
	char *tmp_ptr = NULL;
	bool protocol_seen = false;

	// assign default values at first
	opts->tls = true;
	opts->port = 0;
	opts->verbose_level = VERBOSE_LEVEL_SILENT;
	opts->store_file = 0;
	// not used when standalone process
	opts->port_mem = NULL;
	opts->condition_initialized = NULL;
	opts->store_file = 0;
	opts->ktls = false;
	opts->no_echo = false;
	opts->raw_recv = false;
	opts->mtu = SERVER_MAX_MTU;

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
				protocol_seen = true;
				opts->tls = true;
				break;
			case OPT_DTLS:
				if (protocol_seen) {
					print_error("option '--dtls' is disjoint with --tls");
					return 1;
				}
				protocol_seen = true;
				opts->tls = false;
				break;
			case OPT_PORT:
				opts->port = strtoul(optarg, &tmp_ptr, 10);
				if (*tmp_ptr != '\0' || opts->port > 65535) {
					print_error("unknown port '%s'", optarg);
					return 1;
				}
				break;
			case OPT_MTU:
				opts->mtu = strtoul(optarg, &tmp_ptr, 10);
				if (*tmp_ptr != '\0' || opts->port > SERVER_MAX_MTU) {
					print_error("unknown mtu '%s'", optarg);
					return 1;
				}
				break;

			case OPT_STORE:
				if (opts->store_file) {
					print_error("multiple --store supplied");
					return 1;
				}
				opts->store_file = open(optarg, O_WRONLY|O_CREAT|O_TRUNC);
				if (opts->store_file < 0) {
					perror(optarg);
					return 1;
				}
				break;
			case OPT_VERBOSE:
				if (opts->verbose_level < VERBOSE_LEVEL_ALL)
					opts->verbose_level++;
				break;
			case OPT_KTLS:
				opts->ktls = true;
				break;
			case OPT_RAW_RECV:
				opts->raw_recv = true;
				break;
			case OPT_NO_ECHO:
				opts->no_echo = true;
				break;
			case OPT_HELP:
				print_help(argv[0]);
				return 1;
				break;
			case '?':
				print_help(argv[0]);
				return 1;
				break;
			default:
				/* should be unreachable */
				assert(&long_options);
		}
	}

	/* no additional arguments allowed */
	if (optind < argc) {
		print_error("unknown argument supplied: %s", argv[optind]);
		print_help(argv[0]);
		return 1;
	}

	return 0;
}

static void print_opts(struct server_opts *opts) {
	print_debug_server(opts, "protocol:			%s", opts->tls ? "TLS" : "DTLS");
	if (opts->port)
		print_debug_server(opts, "port:			%u", opts->port);
	else
		print_debug_server(opts, "port:			auto");
	if (opts->store_file)
		print_debug_server(opts, "store to file: (fd)		'%d'", opts->store_file);
	if (opts->ktls)
		print_debug_server(opts, "using AF_KTLS socket");
	if (opts->no_echo)
		print_debug_server(opts, "server is not echoing data messages");
}

int main(int argc, char *argv[]) {
	int err;
	struct server_opts opts;

	print_init();

	err = parse_opts(&opts, argc, argv);
	if (err)
		return err;

	if (opts.verbose_level >= VERBOSE_LEVEL_SERVER)
		print_opts(&opts);

	run_server(&opts);

	if (opts.store_file)
		close(opts.store_file);

	print_destruct();

	return server_err;
}

