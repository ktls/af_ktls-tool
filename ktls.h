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

#ifndef KTLS_H_
#define KTLS_H_

extern int ktls_socket_init(gnutls_session_t session, int sd, size_t sendfile_mtu, bool tls, bool offload);
extern int ktls_socket_destruct(int ksd, gnutls_session_t session);


#endif // KTLS_H_
