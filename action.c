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

#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
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

static void print_sendfile_user_stats(const struct client_opts *opts, size_t filesize, size_t total_sent, double clocks) {
	const char *json_msg = \
		"  {\n"
		"    \"test\": \"send file user\",\n"
		"    \"type\": \"time\",\n"
		"    \"configuration\": {\n"
		"      \"file\": \"%s\",\n"
		"      \"file-size\": %lu,\n"
		"      \"mtu\": %lu,\n"
		"      \"mmap\": %s\n"
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
				opts->sendfile_mtu,
				opts->sendfile_mmap ? "true" : "false",
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
		"      \"mtu\": %lu,\n"
		"      \"mmap\": %s\n"
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
				opts->sendfile_mtu,
				opts->sendfile_mmap ? "true" : "false",
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
	return ret < 0 ? ret : total_sent;
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
	int fd_f;
	int p[2];
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
	close(p[0]);
	close(p[1]);
	close(fd_f);

	return err;
}

extern int do_splice_time(const struct client_opts *opts, int ksd) {
	int err;
	int ret;
	int fd_f;
	int p[2];
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

	close(p[0]);
	close(p[1]);
	close(fd_f);

	return err;
}

extern int do_splice_echo_time(const struct client_opts *opts, int ksd, void *mem) {
	int err;
	int ret;
	int p[2];
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

	close(p[0]);
	close(p[1]);

	return err;
}

extern int do_splice_echo_count(const struct client_opts *opts, int ksd, void *mem) {
	int err;
	int p[2];
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

	close(p[0]);
	close(p[1]);

out:
	return err;
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

	if (opts->sendfile_mmap)
		print_warning("mmap(2) not implemented");

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

	close(in_fd);

	end = clock();

	print_sendfile_user_stats(opts, filesize, total, ((double) (end - start)) / CLOCKS_PER_SEC);

	err = 0;
	in_fd = 0;

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

	if (opts->sendfile_mmap)
		print_warning("mmap(2) not implemented");

	start = clock();
	total = sendfile(ksd, fd, &offset, filesize);
	end = clock();

	if (total < 0)
		perror("sendfile");
	else
		print_sendfile_stats(opts, filesize, total, ((double) (end - start)) / CLOCKS_PER_SEC);

	return total;
}


