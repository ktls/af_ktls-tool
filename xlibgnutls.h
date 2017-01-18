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

#ifndef XLIBGNUTLS_H_
#define XLIBGNUTLS_H_

#include <gnutls/gnutls.h>

extern int xlibgnutls_dtls_handshake(gnutls_session_t *session, int udp_sd, unsigned verbose_level);
extern int xlibgnutls_dtls_terminate(gnutls_session_t session);

extern int xlibgnutls_tls_handshake(gnutls_session_t *session, int tcp_sd, unsigned verbose_level);
extern int xlibgnutls_tls_terminate(gnutls_session_t session, bool offload);

#endif // XLIBGNUTLS_H_

