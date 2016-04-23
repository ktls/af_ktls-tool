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

#ifndef PLAIN_SERVER_H_
#define PLAIN_SERVER_H_

struct server_opts;

extern int plain_udp_server(const struct server_opts *opts);
extern int plain_tcp_server(const struct server_opts *opts);

#endif // PLAIN_SERVER_H_
