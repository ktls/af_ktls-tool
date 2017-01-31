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
#include <assert.h>

#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <gnutls/gnutls.h>

#include "ktls.h"
#include "common.h"
#include "benchmark.h"
#include "client.h"

#include "action.h"

#define MIN(A, B)	((A) < (B) ? (A) : (B))

static ssize_t get_file_size(int fd) {
	ssize_t err;
	ssize_t filesize;

	filesize = lseek(fd, 0L, SEEK_END);
	if (filesize < 0) {
		perror("lseek() to EOF");
		err = filesize;
		goto out;
	}

	err = lseek(fd, 0L, SEEK_SET);
	if (err < 0) {
		perror("lseek() to beginning");
		goto out;
	}

	return filesize;

out:
	return err;
}

static void print_send_count_stats(const struct client_opts *opts, bool gnutls, size_t total_sent, size_t total_recv, double clocks) {
	const char *json_msg = \
		"  {\n"
		"    \"test\": \"%s\",\n"
		"    \"type\": \"count\",\n"
		"    \"configuration\": {\n"
		"      \"size\": %lu,\n"
		"      \"count\": %u\n"
		"    },\n"
		"    \"result\": {\n"
		"      \"sent\": %lu,\n"
		"      \"received\": %lu,\n"
		"      \"elapsed\": %g\n"
		"    }\n"
		"  }";
	const char *txt_msg = \
		"statistics for %s:\n"
		"data size in packet:   %lu\n"
		"number of calls:       %u\n"
		"total bytes sent:      %lu\n"
		"total bytes received:  %lu\n"
		"CPU clock time:        %g\n";

	const char *msg = opts->json ? json_msg : txt_msg;
	const char *name = gnutls ? "gnutls_record_send()" : "send(2)";
	const size_t count = gnutls ? opts->send_gnutls_count : opts->send_ktls_count;

	print_stats(msg, name, opts->payload_size, count, total_sent, total_recv, clocks);
}

static void print_send_time_stats(const struct client_opts *opts, bool gnutls, size_t total_sent, size_t total_recv, double elapsed) {
	const char *json_msg = \
		"  {\n"
		"    \"test\": \"%s\",\n"
		"    \"type\": \"time\",\n"
		"    \"configuration\": {\n"
		"      \"size\": %lu,\n"
		"      \"time\": %u\n"
		"    },\n"
		"    \"result\": {\n"
		"      \"sent\": %lu,\n"
		"      \"received\": %lu,\n"
		"      \"elapsed\": %g\n"
		"    }\n"
		"  }";
	const char *txt_msg = \
		"statistics for %s:\n"
		"data size in packet:   %lu\n"
		"number of seconds:     %lu\n"
		"total bytes sent:      %lu\n"
		"total bytes received:  %lu\n"
		"elapsed time:          %g\n";

	const char *msg = opts->json ? json_msg : txt_msg;
	const char *name = gnutls ? "gnutls_record_send()" : "send(2)";
	const size_t time = gnutls ? opts->send_gnutls_time : opts->send_ktls_time;

	print_stats(msg, name, opts->payload_size, time, total_sent, total_recv, elapsed);
}

static void print_raw_send_time_stats(const struct client_opts *opts, size_t total_sent, size_t total_recv, double elapsed) {
	const char *json_msg = \
		"  {\n"
		"    \"test\": \"raw send, enc recv\",\n"
		"    \"type\": \"time\",\n"
		"    \"configuration\": {\n"
		"      \"size\": %lu,\n"
		"      \"time\": %u\n"
		"    },\n"
		"    \"result\": {\n"
		"      \"sent\": %lu,\n"
		"      \"received\": %lu,\n"
		"      \"elapsed\": %g\n"
		"    }\n"
		"  }";
	const char *txt_msg = \
		"statistics for raw senc, enc recv:\n"
		"data size in packet:   %lu\n"
		"number of seconds:     %lu\n"
		"total bytes sent:      %lu\n"
		"total bytes received:  %lu\n"
		"elapsed time:          %g\n";

	const char *msg = opts->json ? json_msg : txt_msg;

	print_stats(msg, opts->payload_size, opts->raw_send_time, total_sent, total_recv, elapsed);
}

static void print_splice_count_stats(const struct client_opts *opts, size_t total_sent, size_t total_recv, double clocks) {
	const char *json_msg = \
		"  {\n"
		"    \"test\": \"splice(2)\",\n"
		"    \"type\": \"count\",\n"
		"    \"configuration\": {\n"
		"      \"size\": %lu,\n"
		"      \"count\": %u\n"
		"    },\n"
		"    \"result\": {\n"
		"      \"sent\": %lu,\n"
		"      \"received\": %lu,\n"
		"      \"elapsed\": %g\n"
		"    }\n"
		"  }";
	const char *txt_msg = \
		"statistics for splice(2):\n"
		"data size per call:    %lu\n"
		"number of calls:       %u\n"
		"total bytes sent:      %lu\n"
		"total bytes received:  %lu\n"
		"CPU clock time:        %g\n";

	const char *msg = opts->json ? json_msg : txt_msg;

	print_stats(msg, opts->payload_size, opts->splice_count, total_sent, total_recv, clocks);
}

static void print_splice_time_stats(const struct client_opts *opts, size_t total_sent, size_t total_recv, double elapsed) {
	const char *json_msg = \
		"  {\n"
		"    \"test\": \"splice(2)\",\n"
		"    \"type\": \"time\",\n"
		"    \"configuration\": {\n"
		"      \"size\": %lu\n"
		"    },\n"
		"    \"result\": {\n"
		"      \"sent\": %lu,\n"
		"      \"received\": %lu,\n"
		"      \"elapsed\": %g\n"
		"    }\n"
		"  }";
	const char *txt_msg = \
		"statistics for splice(2):\n"
		"data size per call:    %lu\n"
		"total bytes sent:      %lu\n"
		"total bytes received:  %lu\n"
		"elapsed time:          %g\n";

	const char *msg = opts->json ? json_msg : txt_msg;

	print_stats(msg, opts->payload_size, total_sent, total_recv, elapsed);
}

static void print_sendfile_mmap_stats(const struct client_opts *opts, size_t filesize, size_t total_sent, double clocks) {
	const char *json_msg = \
		"  {\n"
		"    \"test\": \"sendfile mmap(2)\",\n"
		"    \"type\": \"time\",\n"
		"    \"configuration\": {\n"
		"      \"file\": \"%s\",\n"
		"      \"file-size\": %lu,\n"
		"      \"mtu\": %lu\n"
		"    },\n"
		"    \"result\": {\n"
		"      \"sent\": %lu,\n"
		"      \"received\": 0,\n"
		"      \"elapsed\": %g\n"
		"    }\n"
		"  }";
	const char *txt_msg = \
		"file:  '%s'\n"
		"file size:             %lu\n"
		"total bytes sent:      %lu\n"
		"CPU clock time:        %0.4g\n";

	if (opts->json)
		print_stats(json_msg,
				opts->sendfile_mmap,
				filesize,
#ifdef TLS_SET_MTU
				opts->sendfile_mtu,
#endif
				total_sent,
				clocks);
	else
		print_stats(txt_msg, opts->sendfile_mmap, filesize, total_sent, clocks);
}


static void print_sendfile_user_stats(const struct client_opts *opts, size_t filesize, size_t total_sent, double clocks) {
	const char *json_msg = \
		"  {\n"
		"    \"test\": \"send file user\",\n"
		"    \"type\": \"time\",\n"
		"    \"configuration\": {\n"
		"      \"file\": \"%s\",\n"
		"      \"file-size\": %lu,\n"
		"      \"mtu\": %lu\n"
		"    },\n"
		"    \"result\": {\n"
		"      \"sent\": %lu,\n"
		"      \"received\": 0,\n"
		"      \"elapsed\": %g\n"
		"    }\n"
		"  }";
	const char *txt_msg = \
		"file:  '%s'\n"
		"file size:             %lu\n"
		"total bytes sent:      %lu\n"
		"CPU clock time:        %0.4g\n";

	if (opts->json)
		print_stats(json_msg,
				opts->sendfile_user,
				filesize,
#ifdef TLS_SET_MTU
				opts->sendfile_mtu,
#endif
				total_sent,
				clocks);
	else
		print_stats(txt_msg, opts->sendfile_user, filesize, total_sent, clocks);
}

static void print_sendfile_stats(const struct client_opts *opts, size_t filesize, size_t total_sent, double clocks) {
	const char *json_msg = \
		"  {\n"
		"    \"test\": \"sendfile(2)\",\n"
		"    \"type\": \"time\",\n"
		"    \"configuration\": {\n"
		"      \"file\": \"%s\",\n"
		"      \"file-size\": %lu,\n"
		"      \"mtu\": %lu\n"
		"    },\n"
		"    \"result\": {\n"
		"      \"sent\": %lu,\n"
		"      \"received\": 0,\n"
		"      \"elapsed\": %g\n"
		"    }\n"
		"  }";
	const char *txt_msg = \
		"file:  '%s'\n"
		"file size:             %lu\n"
		"total bytes sent:      %lu\n"
		"CPU clock time:        %0.4g\n";

	if (opts->json)
		print_stats(json_msg,
				opts->sendfile,
				filesize,
#ifdef TLS_SET_MTU
				opts->sendfile_mtu,
#endif
				total_sent,
				clocks);
	else
		print_stats(txt_msg, opts->sendfile, filesize, total_sent, clocks);
}

static void print_splice_echo_time_stats(const struct client_opts *opts, size_t total_sent, size_t total_recv, double clocks) {
	const char *json_msg = \
		"  {\n"
		"    \"test\": \"splice(2) echo\",\n"
		"    \"type\": \"time\",\n"
		"    \"configuration\": {\n"
		"      \"size\": \"%u\"\n"
		"    },\n"
		"    \"result\": {\n"
		"      \"sent\": %lu,\n"
		"      \"received\": 0,\n"
		"      \"elapsed\": %g\n"
		"    }\n"
		"  }";
	const char *txt_msg = \
		"payload:               %lu\n"
		"total bytes sent:      %lu\n"
		"total bytes received:  %lu\n"
		"CPU clock time:        %0.4g\n";

	if (opts->json)
		print_stats(json_msg,
				opts->payload_size,
				total_sent,
				total_recv,
				clocks);
	else
		print_stats(txt_msg, opts->payload_size, total_sent, total_recv, clocks);
}

static void print_splice_send_raw_time_stats(const struct client_opts *opts, size_t total_sent, size_t total_recv, double clocks) {
	const char *json_msg = \
		"  {\n"
		"    \"test\": \"splice(2) raw send\",\n"
		"    \"type\": \"time\",\n"
		"    \"configuration\": {\n"
		"      \"size\": \"%u\",\n"
		"      \"sendfile mtu\": \"%u\"\n"
		"    },\n"
		"    \"result\": {\n"
		"      \"sent\": %lu,\n"
		"      \"received\": %lu,\n"
		"      \"elapsed\": %g\n"
		"    }\n"
		"  }";
	const char *txt_msg = \
		"payload:               %lu\n"
		"sendfile mtu:                   %lu\n"
		"total bytes sent:      %lu\n"
		"total bytes received:  %lu\n"
		"CPU clock time:        %0.4g\n";

	if (opts->json)
		print_stats(json_msg,
				opts->payload_size,
#ifdef TLS_SET_MTU
				opts->sendfile_mtu,
#endif
				total_sent,
				total_recv,
				clocks);
	else
		print_stats(txt_msg, opts->payload_size, total_sent, total_recv, clocks);
}

static void print_splice_echo_count_stats(const struct client_opts *opts, size_t total_sent, size_t total_recv, double clocks) {
	const char *json_msg = \
		"  {\n"
		"    \"test\": \"splice(2) echo\",\n"
		"    \"type\": \"count\",\n"
		"    \"configuration\": {\n"
		"      \"size\": \"%u\",\n"
		"      \"count\": \"%u\"\n"
		"    },\n"
		"    \"result\": {\n"
		"      \"sent\": %lu,\n"
		"      \"received\": 0,\n"
		"      \"elapsed\": %g\n"
		"    }\n"
		"  }";
	const char *txt_msg = \
		"payload:               %lu\n"
		"count:                 %lu\n"
		"total bytes sent:      %lu\n"
		"total bytes received:  %lu\n"
		"CPU clock time:        %0.4g\n";

	if (opts->json)
		print_stats(json_msg,
				opts->payload_size,
				opts->splice_echo_count,
				total_sent,
				total_recv,
				clocks);
	else
		print_stats(txt_msg, opts->payload_size, opts->splice_echo_count, total_sent, total_recv, clocks);
}

static void print_plain_stats(const struct client_opts *opts, const char *testname, const char *filename, size_t total_sent, size_t total_recv, double elapsed) {
	const char *json_msg = \
		"  {\n"
		"    \"test\": \"%s\",\n"
		"    \"type\": \"time\",\n"
		"    \"configuration\": {\n"
		"      \"filesize\": %lu,\n"
		"      \"mtu\": %u,\n"
		"      \"filename\": \"%s\"\n"
		"    },\n"
		"    \"result\": {\n"
		"      \"sent\": %lu,\n"
		"      \"received\": %lu,\n"
		"      \"elapsed\": %g\n"
		"    }\n"
		"  }";
	const char *txt_msg = \
		"statistics for %s:\n"
		"file size (from param): %lu\n"
		"mtu:                    %lu\n"
		"file:                   %s\n"
		"total bytes sent:       %lu\n"
		"total bytes received:   %lu\n"
		"elapsed time:           %g\n";

	const char *msg = opts->json ? json_msg : txt_msg;

	print_stats(msg, testname,
			opts->sendfile_size,
#ifdef TLS_SET_MTU
			opts->sendfile_mtu,
#endif
			filename,
			total_sent,
			total_recv,
			elapsed);
}

extern int do_send_count(const struct client_opts *opts, int ksd, void *mem, gnutls_session_t session, int flags) {
	clock_t start, end;
	register int ret = -1;
	register size_t total_recv = 0;
	register size_t total_sent = 0;

	start = clock();
	for (register unsigned i = 0; i < opts->send_ktls_count; i++) {
		ret = send(ksd, mem, opts->payload_size, flags);
		if (ret < 0)
			perror("send");
		if (ret <= 0)
			break;
		total_sent += ret;
#ifdef BENCHMARK_RECV
		ret = recv(ksd, mem, opts->payload_size, flags);
		if (ret < 0)
			perror("recv");
		if (ret <= 0)
			break;
		total_recv += ret;
#endif
	}
	end = clock();

	print_send_count_stats(opts, 0, total_sent, total_recv, ((double) (end - start)) / CLOCKS_PER_SEC);
	/*return ret < 0 ? ret : total_sent;*/
	return ret < 0 ? ret : 0;
}

extern int do_send_time(const struct client_opts *opts, int ksd, void *mem, int flags) {
	int err;
	long unsigned elapsed;
	register int ret;
	register size_t total_recv = 0;
	register size_t total_sent = 0;
	struct benchmark_st bst;

	memset(&bst, 0, sizeof(bst));

	ret = start_benchmark(&bst, opts->send_ktls_time);
	if (ret < 0) {
		print_error("failed to set up timer");
		return -1;
	}

	do {
		//printf("benchmark_must_finish: %d\n", benchmark_must_finish);
		ret = send(ksd, mem, opts->payload_size, flags);
		if (ret < 0)
			perror("send");
		if (ret <= 0)
			break;
		total_sent += ret;
#ifdef BENCHMARK_RECV
		ret = recv(ksd, mem, opts->payload_size, flags);
		if (ret < 0)
			perror("recv");
		if (ret <= 0)
			break;
		total_recv += ret;
#endif
	} while(benchmark_must_finish == 0);

	err = stop_benchmark(&bst, &elapsed);

	print_send_time_stats(opts, 0, total_sent, total_recv, (double) elapsed / 1000);
	if (err < 0)
		print_error("failed to stop timer");

	return ret < 0 ? ret : total_sent;
}

extern int do_gnutls_send_count(const struct client_opts *opts, gnutls_session_t session, void *mem) {
	clock_t start, end;
	register int ret = -1;
	register size_t total_recv = 0;
	register size_t total_sent = 0;

	start = clock();
	for (register unsigned i = 0; i < opts->send_gnutls_count; i++) {
		ret = gnutls_record_send(session, mem, opts->payload_size);
		if (ret < 0)
			break;
		total_sent += ret;
#ifdef BENCHMARK_RECV
		ret = gnutls_record_recv(session, mem, opts->payload_size);
		if (ret < 0)
			break;
		total_recv += ret;
#endif
	}
	end = clock();

	if (ret < 0)
		gnutls_perror(ret);

	print_send_count_stats(opts, true, total_sent, total_recv, ((double) (end - start)) / CLOCKS_PER_SEC);
	return ret < 0 ? ret : total_sent;
}

extern int do_gnutls_send_time(const struct client_opts *opts, gnutls_session_t session, void *mem) {
	int err;
	long unsigned elapsed;
	register int ret;
	register size_t total_recv = 0;
	register size_t total_sent = 0;
	struct benchmark_st bst;

	memset(&bst, 0, sizeof(bst));

	ret = start_benchmark(&bst, opts->send_gnutls_time);
	if (ret < 0) {
		print_error("failed to set up timer");
		return -1;
	}

	do {
		ret = gnutls_record_send(session, mem, opts->payload_size);
		if (ret < 0)
			break;
		total_sent += ret;
#ifdef BENCHMARK_RECV
		ret = gnutls_record_recv(session, mem, opts->payload_size);
		if (ret < 0)
			break;
		total_recv += ret;
#endif
	} while(benchmark_must_finish == 0);

	if (ret < 0)
		gnutls_perror(ret);

	err = stop_benchmark(&bst, &elapsed);

	print_send_time_stats(opts, true, total_sent, total_recv, (double) elapsed / 1000);
	if (err < 0)
		print_error("failed to stop timer");

	return ret < 0 ? ret : total_sent;
}

extern int do_splice_count(const struct client_opts *opts, int ksd) {
	int err;
	int ret;
	int fd_f = 0;
	int p[2] = {0, 0};
	clock_t start, end;
	size_t total_sent = 0;
	size_t total_recv = 0; // not used now

	/*
	 * we will perform splice(2) on /dev/zero in order to avoid the impact of
	 * disk drive and FS
	 */

	err = pipe(p);
	if (err)
		return err;

	fd_f = open(opts->splice_file, O_RDONLY);
	if (fd_f < 0) {
		perror(opts->splice_file);
		return fd_f;
	}

	start = clock();

	for (register unsigned i = 0; i < opts->splice_count; i++) {
		ret = splice(fd_f, NULL, p[1], NULL, opts->payload_size, 0);
		if (err < 0) {
			perror("splice");
			err = ret;
			goto out;
		}

		if (ret != opts->payload_size)
			print_warning("splice(2) write size %d differs from return value %d", opts->payload_size, ret);

		ret = splice(p[0], NULL, ksd, NULL, opts->payload_size, 0);
		if (err < 0) {
			perror("splice");
			err = ret;
			goto out;
		}

		if (ret != opts->payload_size)
			print_warning("splice(2) write size %d differs from return value %d", opts->payload_size, ret);

		total_sent += ret;
	}

	end = clock();

	print_splice_count_stats(opts, total_sent, total_recv, ((double) (end - start)) / CLOCKS_PER_SEC);

out:
	if (p[0])
		close(p[0]);
	if (p[1])
		close(p[1]);
	if (fd_f > 0)
		close(fd_f);

	return err;
}


#ifdef TLS_SPLICE_SEND_RAW_TIME
extern int do_splice_send_raw_time(const struct client_opts *opts, int raw_sd, int ksd, void *mem) {
	int err;
	int ret;
	int p[2] = {0, 0};
	size_t total_recv, total_sent;
	unsigned long elapsed;
	struct benchmark_st bst;

	memset(&bst, 0, sizeof(bst));

	err = pipe(p);
	if (err) {
		perror("pipe");
		return err;
	}

	// do initial send
	err = send(raw_sd, mem, opts->payload_size, 0);
	if (err < 0) {
		perror("send");
		print_error("failed to do send");
		return err;
	}

	if (err != opts->payload_size)
		print_warning("send %u, send() returned %d", opts->payload_size, err);

	total_recv = 0;
	total_sent = 0;

	ret = start_benchmark(&bst, opts->splice_send_raw_time);
	if (ret < 0) {
		print_error("failed to set up timer");
		return -1;
	}

	do {
		err = splice(ksd, NULL, p[1], NULL, opts->payload_size, 0);
		if (err < 0) {
			perror("splice");
			print_error("failed to do splice(2)");
			goto out;
		}
		if (err == 0)
			break;

		total_recv += err;

		err = splice(p[0], NULL, raw_sd, NULL, opts->payload_size, 0);
		if (err < 0) {
			perror("splice");
			print_error("failed to do splice(2)");
			goto out;
		}

		if (err == 0)
			break;

		total_sent += err;

	} while(benchmark_must_finish == 0);

out:
	ret = stop_benchmark(&bst, &elapsed);
	if (!ret)
		print_splice_send_raw_time_stats(opts, total_sent, total_recv, (double) elapsed / 1000);

	if (ret < 0)
		print_error("failed to stop timer");

	if (p[0])
		close(p[0]);
	if (p[1])
		close(p[1]);

	return err;
}
#endif


extern int do_splice_time(const struct client_opts *opts, int ksd) {
	int err;
	int ret;
	int fd_f = 0;
	int p[2] = {0, 0};
	size_t total_sent = 0;
	size_t total_recv = 0; // unused now
	unsigned long elapsed;
	struct benchmark_st bst;

	memset(&bst, 0, sizeof(bst));

	err = pipe(p);
	if (err)
		return err;

	fd_f = open(opts->splice_file, O_RDONLY);
	if (fd_f < 0) {
		perror("open");
		return fd_f;
	}

	ret = start_benchmark(&bst, opts->splice_time);
	if (ret < 0) {
		print_error("failed to set up timer");
		return -1;
	}

	do {
		ret = splice(fd_f, NULL, p[1], NULL, opts->payload_size, 0);
		if (err < 0) {
			perror("splice");
			err = ret;
			goto out;
		}

		if (ret == 0)
			break;

		if (ret != opts->payload_size)
			print_warning("splice(2) write size %d differs from return value %d", opts->payload_size, ret);

		ret = splice(p[0], NULL, ksd, NULL, opts->payload_size, 0);
		if (err < 0) {
			perror("splice(2):");
			err = ret;
			goto out;
		}

		if (ret == 0)
			break;

		if (ret != opts->payload_size)
			print_warning("splice(2) write size %d differs from return value %d", opts->payload_size, ret);

		total_sent += ret;
	} while(benchmark_must_finish == 0);

out:
	ret = stop_benchmark(&bst, &elapsed);
	if (!err)
		print_splice_time_stats(opts, total_sent, total_recv, (double) elapsed / 1000);

	if (ret < 0)
		print_error("failed to stop timer");

	if (p[0])
		close(p[0]);
	if (p[1])
		close(p[1]);
	if (fd_f > 0)
		close(fd_f);

	return err;
}

extern int do_splice_echo_time(const struct client_opts *opts, int ksd, void *mem) {
	int err;
	int ret;
	int p[2] = {0, 0};
	size_t total_recv, total_sent;
	unsigned long elapsed;
	struct benchmark_st bst;

	memset(&bst, 0, sizeof(bst));

	err = pipe(p);
	if (err) {
		perror("pipe");
		return err;
	}

	// do initial send, so we have data in echo'ed -- ping-pong :)
	err = send(ksd, mem, opts->payload_size, 0);
	if (err < 0) {
		perror("send");
		return err;
	}

	if (err != opts->payload_size)
		print_warning("send %u, send() returned %d", opts->payload_size, err);

	ret = start_benchmark(&bst, opts->splice_echo_time);
	if (ret < 0) {
		print_error("failed to set up timer");
		return -1;
	}

	total_recv = 0;
	total_sent = 0;
	do {
		err = splice(ksd, NULL, p[1], NULL, opts->payload_size, 0);
		if (err < 0) {
			perror("splice");
			err = ret;
			goto out;
		}
		if (err == 0)
			break;

		total_recv += err;

		err = splice(p[0], NULL, ksd, NULL, opts->payload_size, 0);
		if (err < 0) {
			perror("splice(2):");
			err = ret;
			goto out;
		}

		if (err == 0)
			break;

		total_sent += err;

	} while(benchmark_must_finish == 0);

out:
	ret = stop_benchmark(&bst, &elapsed);
	if (!ret)
		print_splice_echo_time_stats(opts, total_sent, total_recv, (double) elapsed / 1000);

	if (ret < 0)
		print_error("failed to stop timer");

	if (p[0])
		close(p[0]);
	if (p[1])
		close(p[1]);

	return err;
}

extern int do_splice_echo_count(const struct client_opts *opts, int ksd, void *mem) {
	int err;
	int p[2] = {0, 0};
	clock_t start, end;
	size_t total_recv, total_sent;

	total_recv = 0;
	total_sent = 0;

	err = pipe(p);
	if (err) {
		perror("pipe");
		return err;
	}

	// do initial send, so we have data in echo'ed -- ping-pong :)
	err = send(ksd, mem, opts->payload_size, 0);
	if (err < 0) {
		perror("send");
		return err;
	}

	if (err != opts->payload_size)
		print_warning("send %u, send() returned %d", opts->payload_size, err);

	start = clock();
	for (unsigned i = 0; i < opts->splice_echo_count; i++) {

		err = splice(ksd, NULL, p[1], NULL, opts->payload_size, 0);
		if (err < 0) {
			perror("splice");
			goto out;
		}

		total_recv += err;

		err = splice(p[0], NULL, ksd, NULL, opts->payload_size, 0);
		if (err < 0) {
			perror("splice(2):");
			goto out;
		}

		total_sent += err;
	}
	end = clock();

	if (err > 0)
		print_splice_echo_count_stats(opts, total_sent, total_recv, ((double) (end - start)) / CLOCKS_PER_SEC);

out:

	if (p[0])
		close(p[0]);
	if (p[1])
		close(p[1]);
	return err;
}

extern int do_sendfile_mmap(const struct client_opts *opts, gnutls_session_t session) {
	int err;
	int in_fd = 0;
	clock_t start, end;
	ssize_t total = 0;
	ssize_t filesize;
	char *buf = NULL;

	in_fd = open(opts->sendfile_mmap, O_RDONLY);
	if (in_fd < 0) {
		perror("open");
		goto out;
	}

	if (opts->sendfile_size == 0) {
		filesize = lseek(in_fd, 0L, SEEK_END);
		if (filesize < 0) {
			perror("lseek() to EOF");
			err = filesize;
			goto out;
		}
		err = lseek(in_fd, 0L, SEEK_SET);
		if (err < 0) {
			perror("lseek() to beginning");
			goto out;
		}
	} else {
		filesize = opts->sendfile_size;
	}

	// we explicitly drop caches since we used seek
	DO_DROP_CACHES(opts);

	start = clock();

	buf = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, in_fd, /*offset*/ 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		goto out;
	}

	for (total = 0; total != filesize; total += err) {
#ifdef TLS_SET_MTU
		err = gnutls_record_send(session, buf + total, MIN(opts->sendfile_mtu, filesize - total));
#else
		err = gnutls_record_send(session, buf + total, filesize - total);
#endif
		if (err < 0) {
			print_error("failed to send via Gnu TLS");
			goto out;
		}
	}

	end = clock();

	print_sendfile_mmap_stats(opts, filesize, total, ((double) (end - start)) / CLOCKS_PER_SEC);

out:
	if (buf)
		munmap(buf, filesize);
	if (in_fd > 0)
		close(in_fd);

	return err;
}

extern int do_raw_send_time(const struct client_opts *opts, gnutls_session_t session, int raw_sd, void *mem) {
	int err;
	long unsigned elapsed;
	register int ret;
	register size_t total_recv = 0;
	register size_t total_sent = 0;
	struct benchmark_st bst;

	assert(raw_sd > 0);

	memset(&bst, 0, sizeof(bst));

	// initial send
	ret = send(raw_sd, mem, opts->payload_size, 0);
	if (ret < 0) {
		gnutls_perror(ret);
		print_error("failed to do initial send");
		return -1;
	}

	ret = start_benchmark(&bst, opts->raw_send_time);
	if (ret < 0) {
		print_error("failed to set up timer");
		return -1;
	}

	do {
		ret = gnutls_record_recv(session, mem, opts->payload_size);
		if (ret < 0) {
			gnutls_perror(ret);
			print_error("failed to do gnutls_record_recv");
			break;
		}
		total_recv += ret;

		ret = send(raw_sd, mem, opts->payload_size, 0);
		if (ret < 0) {
			gnutls_perror(ret);
			break;
		}
		total_sent += ret;
	} while(benchmark_must_finish == 0 && ret > 0);

	if (ret > 0) {
		err = stop_benchmark(&bst, &elapsed);

		print_raw_send_time_stats(opts, total_sent, total_recv, (double) elapsed / 1000);
		if (err < 0)
			print_error("failed to stop timer");
	}

	return ret < 0 ? ret : total_sent;
}

extern int do_sendfile_user(const struct client_opts *opts, gnutls_session_t session) {
	int err;
	int in_fd = 0;
	clock_t start, end;
	ssize_t total = 0;
	ssize_t filesize;
	char *buf = NULL;

	in_fd = open(opts->sendfile_user, O_RDONLY);
	if (in_fd < 0) {
		perror(opts->sendfile_user);
		err = -1;
		goto do_sendfile_user_end;
	}

	if (opts->sendfile_size == 0) {
		filesize = lseek(in_fd, 0L, SEEK_END);
		if (filesize < 0) {
			perror("lseek() to EOF");
			err = -1;
			goto do_sendfile_user_end;
		}
		err = lseek(in_fd, 0L, SEEK_SET);
		if (err < 0) {
			perror("lseek() to beginning");
			goto do_sendfile_user_end;
		}
	} else {
		filesize = opts->sendfile_size;
	}

	close(in_fd);

	buf = malloc(opts->sendfile_mtu);
	if (!buf) {
		perror("malloc");
		return -1;
	}

	// we explicitly drop caches since we used seek
	DO_DROP_CACHES(opts);

	start = clock();

	in_fd = open(opts->sendfile_user, O_RDONLY);
	if (in_fd < 0) {
		perror(opts->sendfile_user);
		err = -1;
		goto do_sendfile_user_end;
	}

	do {
		err = read(in_fd, buf, opts->sendfile_mtu);
		if (err < 0) {
			perror("read");
			goto do_sendfile_user_end;
		}

		err = gnutls_record_send(session, buf, err);
		if (err < 0) {
			print_error("failed to send via Gnu TLS");
			goto do_sendfile_user_end;
		}

		if (err == 0)
			print_warning("premature end of send");

		total += err;
	} while (total != filesize && err != 0);

	end = clock();

	print_sendfile_user_stats(opts, filesize, total, ((double) (end - start)) / CLOCKS_PER_SEC);

	err = total;

do_sendfile_user_end:
	if (buf)
		free(buf);

	if (in_fd)
		close(in_fd);

	return err;
}

extern int do_sendfile(const struct client_opts *opts, int ksd) {
	int err;
	int fd;
	clock_t start, end;
	ssize_t total = 0;
	ssize_t filesize;
	off_t offset = 0;

	fd = open(opts->sendfile, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return fd;
	}

	if (opts->sendfile_size == 0) {
		filesize = lseek(fd, 0L, SEEK_END);
		if (filesize < 0) {
			perror("lseek() to EOF");
			return -1;
		}
		err = lseek(fd, 0L, SEEK_SET);
		if (err < 0) {
			perror("lseek() to beginning");
			return err;
		}
	} else {
		filesize = opts->sendfile_size;
	}

	// we do it explicitly because of lseek()
	DO_DROP_CACHES(opts);

	start = clock();
	total = sendfile(ksd, fd, &offset, filesize);
	end = clock();

	if (total < 0)
		perror("sendfile");
	else
		print_sendfile_stats(opts, filesize, total, ((double) (end - start)) / CLOCKS_PER_SEC);

	return total;
}

/* actions not using TLS - plain text actions  */

extern int do_plain_sendfile_user(const struct client_opts *opts, int sd) {
	int err;
	int fd = 0;
	off_t offset = 0;
	ssize_t filesize;
	size_t sent, mtu;
	clock_t start, end;
	char *buf = NULL;

	fd = open(opts->plain_sendfile_user, O_RDONLY);
	if (fd < 0) {
		perror("open");
		err = fd;
		goto out;
	}

	if (opts->sendfile_size == 0) {
		filesize = get_file_size(fd);
		if (filesize < 0) {
			err = filesize;
			goto out;
		}
	} else
		filesize = opts->sendfile_size;

	buf = malloc(opts->sendfile_mtu);
	if (!buf) {
		perror("malloc");
		err = -errno;
		goto out;
	}

	// we do this explicitly because of get_file_size()
	DO_DROP_CACHES(opts);

	start = clock();

	for (sent = 0; sent != filesize; sent += err) {
		err = read(fd, buf, opts->sendfile_mtu);
		if (err < 0) {
			perror("read");
			goto out;
		}

		if (err == 0) // EOF reached
			break;

		err = send(sd, buf, err, 0);

		if (err < 0) {
			perror("send");
			goto out;
		}
	}

	end = clock();

	print_plain_stats(opts, "plain send file user", opts->plain_sendfile_user,
			sent, 0, ((double) (end - start)) / CLOCKS_PER_SEC);

out:
	if (fd > 0)
		close(fd);

	if (buf)
		free(buf);

	return err;
}

extern int do_plain_sendfile_mmap(const struct client_opts *opts, int sd) {
	int err;
	int fd = 0;
	off_t offset = 0;
	ssize_t filesize;
	size_t sent, mtu;
	clock_t start, end;
	char *mem;

	fd = open(opts->plain_sendfile_mmap, O_RDONLY);
	if (fd < 0) {
		perror("open");
		err = fd;
		goto out;
	}

	if (opts->sendfile_size == 0) {
		filesize = get_file_size(fd);
		if (filesize < 0) {
			err = filesize;
			goto out;
		}
	} else
		filesize = opts->sendfile_size;

	mtu = MIN(filesize, opts->sendfile_mtu);

	// we do this explicitly because of get_file_size()
	DO_DROP_CACHES(opts);

	mem = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, /*offset*/0);
	if (!mem) {
		perror("mmap");
		err = -1;
		goto out;
	}

	start = clock();

	for (sent = 0; sent != filesize; sent += err) {
		err = send(sd, mem + sent, MIN(filesize - sent, mtu), 0);
		if (err < 0) {
			perror("sendfile");
			goto out;
		}
	}

	end = clock();

	print_plain_stats(opts, "plain send file mmap", opts->plain_sendfile_mmap,
			sent, 0, ((double) (end - start)) / CLOCKS_PER_SEC);

out:
	if (fd > 0)
		close(fd);

	if (mem)
		munmap(mem, filesize);

	return err;
}

extern int do_plain_splice_emu(const struct client_opts *opts, int sd) {
	int err;
	int fd = 0;
	int p[2] = {0, 0};
	clock_t start, end;
	size_t total_sent = 0;
	size_t total_recv = 0; // not used now
	ssize_t filesize;

	err = pipe(p);
	if (err) {
		perror("pipe");
		return err;
	}

	fd = open(opts->plain_splice_emu, O_RDONLY);
	if (fd < 0) {
		perror(opts->plain_splice_emu);
		err = fd;
		goto out;
	}

	if (!opts->sendfile_size) {
		filesize = get_file_size(fd);
		if (filesize < 0) {
			err = filesize;
			goto out;
		}
	} else
		filesize = opts->sendfile_size;

	// explicitly because of get_file_size()
	DO_DROP_CACHES(opts);

	start = clock();

	for (total_sent = 0; total_sent != filesize; total_sent += err) {
		err = splice(fd, NULL, p[1], NULL, opts->sendfile_mtu, 0);
		if (err < 0) {
			perror("splice");
			goto out;
		}

		if (err == 0) // EOF reached
			break;

		err = splice(p[0], NULL, sd, NULL, opts->sendfile_mtu, 0);
		if (err < 0) {
			perror("splice");
			goto out;
		}
	}

	end = clock();

	print_plain_stats(opts, "plain splice(2) send file emu", opts->plain_splice_emu,
			total_sent, 0, ((double) (end - start)) / CLOCKS_PER_SEC);
out:
	if (p[0])
		close(p[0]);
	if (p[1])
		close(p[1]);
	if (fd > 0)
		close(fd);

	return err;
}

extern int do_plain_sendfile(const struct client_opts *opts, int sd) {
	int err;
	int fd = 0;
	off_t offset = 0;
	ssize_t filesize;
	size_t sent, mtu;
	clock_t start, end;

	fd = open(opts->plain_sendfile, O_RDONLY);
	if (fd < 0) {
		perror("open");
		err = fd;
		goto out;
	}

	if (opts->sendfile_size == 0) {
		filesize = get_file_size(fd);
		if (filesize < 0) {
			err = filesize;
			goto out;
		}
	} else
		filesize = opts->sendfile_size;

#ifdef TLS_SET_MTU
	if (opts->sendfile_mtu)
		mtu = MIN(filesize, opts->sendfile_mtu);
	else
		mtu = filesize;
#else
	mtu = filesize;
#endif

	// we do this explicitly because of get_file_size()
	DO_DROP_CACHES(opts);

	start = clock();

	for (sent = 0; sent != filesize; sent += err) {
		err = sendfile(sd, fd, &offset, mtu);
		if (err < 0) {
			perror("sendfile");
		}
	}

	end = clock();

	print_plain_stats(opts, "plain sendfile(2)", opts->plain_sendfile,
			sent, 0, ((double) (end - start)) / CLOCKS_PER_SEC);

out:
	if (fd > 0)
		close(fd);
	return err;
}

