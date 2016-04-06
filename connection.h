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

#ifndef CONNECTION_H_
#define CONNECTION_H_

extern int udp_connect(const char *host, unsigned port);
extern void udp_close(int sd);
extern int tcp_connect(const char *host, unsigned port);
extern void tcp_close(int sd);


#endif /* CONNECTION_H_ */

