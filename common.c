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
#include <stdarg.h>
#include <stdbool.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "client.h"
#include "server.h"

#include "common.h"

/*
 * we want to be informed about printing, since printing effects
 * benchmarks
 */
static bool was_printed;

/*
 * if server runs in a separate thread, we want to be thread safe
 */
pthread_mutex_t output_mutex;

/*
 * if print_stats() should expect JSON to be printed
 */
static bool stats_json = false;
/*
 * we need to handle JSON in special case since it starts with [, there are
 * comma separators, but last entry does not contain comma delimiter
 * true, if we have already printed some statistics in JSON
 * I know this is ugly, but for simplicity it is enough
 */
static bool stats_json_printed = false;

static FILE *stats_file = NULL;

extern int do_print_error(const char *file, unsigned line, const char *fmt, ...) {
	int ret;
	va_list va;

	va_start(va, fmt);

	pthread_mutex_lock(&output_mutex);

	fprintf(stderr, "ERR:%s:%u: ", file, line);
	ret = vfprintf(stderr, fmt, va);
	fputs("\n", stderr);

	was_printed = true;
	pthread_mutex_unlock(&output_mutex);

	va_end(va);
	return ret;
}

extern int do_print_info(const char *file, unsigned line, const char *fmt, ...) {
	int ret;
	va_list va;

	va_start(va, fmt);

	pthread_mutex_lock(&output_mutex);

	fprintf(stderr, "INFO:%s:%u: ", file, line);
	ret = vfprintf(stderr, fmt, va);
	fputs("\n", stderr);

	was_printed = true;
	pthread_mutex_unlock(&output_mutex);

	va_end(va);
	return ret;
}

extern void print_stats(const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);

	if (!stats_file) {
		fprintf(stderr, "FATAL ERROR: print_init() not called\n");
		assert(false);
	}

	pthread_mutex_lock(&output_mutex);

	if (stats_json) {
		if (!stats_json_printed)
			fprintf(stats_file, "[\n");
		else
			fprintf(stats_file, ",\n");

		vfprintf(stats_file, fmt, va);
		stats_json_printed = true;
	} else {
		fprintf(stats_file, "============ Benchmark statistics ============\n");
		vfprintf(stats_file, fmt, va);
		fprintf(stats_file, "==============================================\n");
	}

	// we do not set was_printed here, since these are actual statistics
	pthread_mutex_unlock(&output_mutex);

	va_end(va);
}

extern void print_stats_json(bool json) {
	stats_json = json;
}

extern int do_print_warning(const char *file, unsigned line, const char *fmt, ...) {
	int ret;
	va_list va;

	va_start(va, fmt);

	pthread_mutex_lock(&output_mutex);
	fprintf(stderr, "WARN:%s:%u: ", file, line);
	ret = vfprintf(stderr, fmt, va);
	fputs("\n", stderr);

	was_printed = true;
	pthread_mutex_unlock(&output_mutex);

	va_end(va);
	return ret;
}

extern int print_debug_client(const struct client_opts *opts, const char *fmt, ...) {
	int ret = 0;
	va_list va;

	if (opts->verbose_level >= VERBOSE_LEVEL_CLIENT) {
		va_start(va, fmt);

		pthread_mutex_lock(&output_mutex);
		fputs("DBG:CLIENT: ", stderr);
		ret = vfprintf(stderr, fmt, va);
		fputs("\n", stderr);

		was_printed = true;
		pthread_mutex_unlock(&output_mutex);

		va_end(va);
	}

	return ret;
}

extern int print_debug_server(const struct server_opts *opts, const char *fmt, ...) {
	int ret = 0;
	va_list va;

	if (opts->verbose_level >= VERBOSE_LEVEL_SERVER) {
		va_start(va, fmt);

		pthread_mutex_lock(&output_mutex);
		fputs("DBG:SERVER: ", stderr);
		ret = vfprintf(stderr, fmt, va);
		fputs("\n", stderr);

		was_printed = true;
		pthread_mutex_unlock(&output_mutex);

		va_end(va);
	}

	return ret;
}

extern int print_debug_tls(const struct client_opts *opts, const char *fmt, ...) {
	int ret = 0;
	va_list va;

	if (opts->verbose_level >= VERBOSE_LEVEL_CLIENT) {
		va_start(va, fmt);

		pthread_mutex_lock(&output_mutex);
		fputs("DBG:TLS: ", stderr);
		ret = vfprintf(stderr, fmt, va);
		fputs("\n", stderr);

		was_printed = true;
		pthread_mutex_unlock(&output_mutex);

		va_end(va);
	}

	return ret;
}

extern void gnutls_log(int level, const char *msg) {
	UNUSED(level);
	pthread_mutex_lock(&output_mutex);
	fprintf(stderr, "DBG:TLS-LIB: %s", msg);
	was_printed = true;
	pthread_mutex_unlock(&output_mutex);
}

extern void print_hex(const char * data, size_t len) {
	pthread_mutex_lock(&output_mutex);
	fputs("hex: ", stderr);
	for (size_t i = 0; i < len; i++)
		fprintf(stderr, "%02X", (unsigned char) data[i]);
	fputs("\n", stderr);
	was_printed = true;
	pthread_mutex_unlock(&output_mutex);
}

#if 0
extern ssize_t gnutls_push_func_custom(gnutls_transport_ptr_t p, const void *data, size_t size) {
	int s = (int) p;
	int ret;

	print_hex(data, size);
	ret = send(s, data, size, 0);
	return ret;
}
#endif

extern void print_init(void) {
	was_printed = false;
	stats_json = false;
	stats_json_printed = false;
	stats_file = stdout;
	pthread_mutex_init(&output_mutex, NULL);
}

extern void print_stats_file(FILE *f) {
	stats_file = f;
}

extern void print_destruct(void) {
	if (stats_json && stats_json_printed) { // we have to terminate JSON
		fprintf(stats_file, "\n]\n");
	}
	was_printed = false;
	stats_json = false;
	stats_json_printed = false;
	stats_file = stdout;
	pthread_mutex_destroy(&output_mutex);
}

extern bool print_touched(void) {
	return was_printed;
}

extern bool print_touch_reset(void) {
	bool old;

	old = was_printed;
	was_printed = false;
	return old;
}

