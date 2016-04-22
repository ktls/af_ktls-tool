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

#ifndef ACTION_H_
#define ACTION_H_

struct client_opts;

extern int do_send_count(const struct client_opts *opts, int ksd, void *mem, gnutls_session_t session, int flags);
extern int do_send_time(const struct client_opts *opts, int ksd, void *mem, int flags);
extern int do_gnutls_send_count(const struct client_opts *opts, gnutls_session_t session, void *mem);
extern int do_gnutls_send_time(const struct client_opts *opts, gnutls_session_t session, void *mem);
extern int do_splice_count(const struct client_opts *opts, int ksd);
extern int do_splice_time(const struct client_opts *opts, int ksd);
extern int do_splice_echo_time(const struct client_opts *opts, int ksd, void *mem);
extern int do_splice_echo_count(const struct client_opts *opts, int ksd, void *mem);
extern int do_sendfile_mmap(const struct client_opts *opts, gnutls_session_t session);
extern int do_sendfile_user(const struct client_opts *opts, gnutls_session_t session);
extern int do_sendfile(const struct client_opts *opts, int ksd);
extern int do_raw_send_time(const struct client_opts *opts, gnutls_session_t session, int raw_sd, void *mem);
extern int do_splice_send_raw_time(const struct client_opts *opts, int raw_sd, int ksd, void *mem);

#endif // ACTION_H_
