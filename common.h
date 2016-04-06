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

#ifndef COMMON_H_
#define COMMON_H_

#include <stdio.h>
#include <stdbool.h>
#include <gnutls/gnutls.h>

#define UNUSED(X)               ((void) X)

#define VERBOSE_LEVEL_SILENT    0
#define VERBOSE_LEVEL_CLIENT    1
#define VERBOSE_LEVEL_SERVER    VERBOSE_LEVEL_CLIENT
#define VERBOSE_LEVEL_GNUTLS    2
#define VERBOSE_LEVEL_PACKETS   3
#define VERBOSE_LEVEL_ALL       4

struct client_opts;
struct server_opts;

#define print_info(...)        do_print_info(__FILE__, __LINE__, __VA_ARGS__)
#define print_error(...)       do_print_error(__FILE__, __LINE__, __VA_ARGS__)
#define print_warning(...)     do_print_warning(__FILE__, __LINE__, __VA_ARGS__)

extern int do_print_error(const char *file, unsigned line, const char *fmt, ...);
extern int do_print_info(const char *file, unsigned line, const char *fmt, ...);
extern int do_print_warning(const char *file, unsigned line, const char *fmt, ...);

extern int print_debug_client(const struct client_opts *opts, const char *fmt, ...);
extern int print_debug_server(const struct server_opts *opts, const char *fmt, ...);
extern int print_debug_tls(const struct client_opts *opts, const char *fmt, ...);
extern void gnutls_log(int level, const char *msg);
extern void print_hex(const char * data, size_t len);
extern ssize_t gnutls_push_func_custom(gnutls_transport_ptr_t p, const void *data, size_t size);

extern void print_stats(const char *fmt, ...);
extern void print_stats_json(bool json);
extern void print_stats_file(FILE *f);

extern void print_init(void);
extern void print_destruct(void);
extern bool print_touched(void);
extern bool print_touch_reset(void);

#endif

