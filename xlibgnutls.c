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

#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>

#include "common.h"

#include "xlibgnutls.h"
#include "connection.h"

#include <sys/types.h>
#include <sys/socket.h>

// this is ugly, but let's simplify things
static gnutls_certificate_credentials_t xcred;
static gnutls_anon_client_credentials_t anoncred;

static int verify_certificate_callback(gnutls_session_t session) {
	return 0;
}

extern int xlibgnutls_dtls_handshake(gnutls_session_t *session, int udp_sd, unsigned verbose_level) {
	const char *CAFILE = "ca-cert.pem"; // TODO: use anoncred
	int ret;
	const char *err;

	if (gnutls_check_version("3.1.4") == NULL) {
		print_error("GnuTLS 3.1.4 or later is required");
		return -1;
	}

	/* for backwards compatibility with gnutls < 3.3.0 */
	gnutls_global_init();

	if (verbose_level >= VERBOSE_LEVEL_GNUTLS) {
		gnutls_global_set_log_level(9999);
		gnutls_global_set_log_function(gnutls_log);
	}

	/* X509 stuff */
	gnutls_certificate_allocate_credentials(&xcred);

	/* sets the trusted cas file */
	gnutls_certificate_set_x509_trust_file(xcred, CAFILE, GNUTLS_X509_FMT_PEM);
	gnutls_certificate_set_verify_function(xcred, verify_certificate_callback);

	/* Initialize TLS session */
	gnutls_init(session, GNUTLS_CLIENT | GNUTLS_DATAGRAM);

	/* put the x509 credentials to the current session */
	gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_server_name_set(*session, GNUTLS_NAME_DNS, "my_host_name", strlen("my_host_name"));

	if (verbose_level >= VERBOSE_LEVEL_PACKETS) {
		gnutls_transport_set_push_function(*session, gnutls_push_func_custom);
		//gnutls_transport_set_pull_function(*session, gnutls_pull_func_custom);
		//gnutls_transport_set_pull_timeout_function(*session, gnutls_pull_timeout_func_custom);
	}

	gnutls_dtls_set_mtu(*session, 1 << 14);
	gnutls_set_default_priority(*session);
	/* if more fine-graned control is required */
	ret = gnutls_priority_set_direct(*session, "NORMAL", &err);
	if (ret < 0) {
		if (ret == GNUTLS_E_INVALID_REQUEST)
			print_error("syntax error at: %d", err);
		goto end;
	}

	gnutls_transport_set_int(*session, udp_sd);
	gnutls_handshake_set_timeout(*session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	if (verbose_level >= VERBOSE_LEVEL_CLIENT)
		print_info("handshake started");
	do {
		ret = gnutls_handshake(*session);
	}
	while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
	/* Note that DTLS may also receive GNUTLS_E_LARGE_PACKET */
	if (verbose_level >= VERBOSE_LEVEL_CLIENT)
		print_info("handshake finished");

	if (ret < 0) {
		print_error("handshake failed with return code %d", ret);
		gnutls_perror(ret);
		goto end;
	} else {
		char *desc;
		desc = gnutls_session_get_desc(*session);
		if (verbose_level >= VERBOSE_LEVEL_CLIENT)
			print_info("session info: %s", desc);
		gnutls_free(desc);
	}

	ret = 0;

end:
	return ret;
}

extern int xlibgnutls_dtls_terminate(gnutls_session_t session) {
	gnutls_bye(session, GNUTLS_SHUT_WR);

	gnutls_deinit(session);
	gnutls_certificate_free_credentials(xcred);
	gnutls_global_deinit();

	return 0;
}

extern int xlibgnutls_tls_handshake(gnutls_session_t *session, int tcp_sd, unsigned verbose_level) {
	int ret, ii;
	/* Need to enable anonymous KX specifically. */

	gnutls_global_init();
	gnutls_anon_allocate_client_credentials(&anoncred);
	gnutls_init(session, GNUTLS_CLIENT);

	gnutls_priority_set_direct(*session, "NORMAL:+ANON-ECDH:+ANON-DH", NULL);
	gnutls_credentials_set(*session, GNUTLS_CRD_ANON, anoncred);
	gnutls_transport_set_int(*session, tcp_sd);
	gnutls_handshake_set_timeout(*session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	do {
		ret = gnutls_handshake(*session);
	}
	while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

	if (ret < 0) {
		print_error("handshake failed");
		gnutls_perror(ret);
	} else {
		char *desc;
		desc = gnutls_session_get_desc(*session);
		print_info("- Session info: %s\n", desc);
		gnutls_free(desc);
	}

	return ret;
}

/* Record Protocol */
typedef enum content_type_t {
	GNUTLS_CHANGE_CIPHER_SPEC = 20, GNUTLS_ALERT,
	GNUTLS_HANDSHAKE, GNUTLS_APPLICATION_DATA,
	GNUTLS_HEARTBEAT
} content_type_t;


static int xlibgnutls_bye(gnutls_session_t session, bool offload)
{
	if (!offload) {
		gnutls_bye(session, GNUTLS_SHUT_WR);
	} else {
		/* HACK to send control message directly from the tool
		 * TODO: Edit gnutls to work with no encryption */
		int tls = gnutls_transport_get_int(session);
		char data[3] = {GNUTLS_ALERT, 0, 0};
		struct msghdr msg = {0};
		msg.msg_control = data;
		msg.msg_controllen = sizeof(data);
		sendmsg(tls, &msg, 0);
	}

	return 0;
}

extern int xlibgnutls_tls_terminate(gnutls_session_t session, bool offload)
{
	xlibgnutls_bye(session, offload);

	gnutls_deinit(session);
	gnutls_anon_free_client_credentials(anoncred);
	gnutls_global_deinit();

	return 0;
}

