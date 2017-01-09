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

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"

#include "ktls.h"

static int ktls_socket_update_state(gnutls_session_t session, int ksd, bool tls)
{
	int err;
	gnutls_datum_t mac_key;
	gnutls_datum_t iv_read;
	gnutls_datum_t iv_write;
	gnutls_datum_t cipher_key_read;
	gnutls_datum_t cipher_key_write;
	unsigned char seq_number_read[8];
	unsigned char seq_number_write[8];

	// now we need to initialize state after the handshake in the kernel
	err = gnutls_record_get_state(session, 1, &mac_key, &iv_read, &cipher_key_read, seq_number_read);
	if (err < 0) {
		print_error("failed to get receiving state from Gnu TLS session");
		goto update_state_error;
	}

	err = gnutls_record_get_state(session, 0, &mac_key, &iv_write, &cipher_key_write, seq_number_write);
	if (err < 0) {
		print_error("failed to get sendig state from Gnu TLS session");
		goto update_state_error;
	}

	err = setsockopt(ksd, AF_KTLS, KTLS_SET_SALT_SEND, iv_write.data, 4);
	if (err < 0) {
		perror("failed to set send salt on AF_KTLS socket using setsockopt(2)");
		goto update_state_error;
	}

	err = setsockopt(ksd, AF_KTLS, KTLS_SET_SALT_RECV, iv_read.data, 4);
	if (err < 0) {
		perror("failed to set recv salt on AF_KTLS socket using setsockopt(2)");
		goto update_state_error;
	}

	err = setsockopt(ksd, AF_KTLS, KTLS_SET_KEY_SEND, cipher_key_write.data, cipher_key_write.size);
	if (err < 0) {
		perror("failed to set send key on AF_KTLS socket using setsockopt(2)");
		goto update_state_error;
	}

	err = setsockopt(ksd, AF_KTLS, KTLS_SET_KEY_RECV, cipher_key_read.data, cipher_key_read.size);
	if (err < 0) {
		perror("failed to set receive key on AF_KTLS socket using setsockopt(2)");
		goto update_state_error;
	}

	err = setsockopt(ksd, AF_KTLS, KTLS_SET_IV_SEND, seq_number_write, 8);
	if (err < 0) {
		print_error("failed to set send IV on AF_KTLS socket using setsockopt(2)");
		goto update_state_error;
	}

	/*
	 * Gnu TLS this is a workaround since Gnu TLS does not propagate recv seq num
	 * for DTLS.
	 * It should be fixed in the new release (today is Apr 1 2016). Once fixed,
	 * this has to be removed.
	 */
	if (!tls) {
		seq_number_read[1] = 1;
		seq_number_read[7] = 1;
	}

	err = setsockopt(ksd, AF_KTLS, KTLS_SET_IV_RECV, seq_number_read, 8);
	if (err < 0) {
		print_error("failed to set receive IV on AF_KTLS socket using setsockopt(2)");
		goto update_state_error;
	}

	return 0;

update_state_error:
	return err;
}

extern int ktls_socket_init(gnutls_session_t session, int sd, size_t sendfile_mtu, bool tls, bool offload) {
	int err;
	struct sockaddr_ktls sa_ktls;

	int ksd = socket(AF_KTLS, tls ? SOCK_STREAM : SOCK_DGRAM, 0);
	if (ksd == -1) {
		perror("socket error:");
		return -1;
	}

	sa_ktls.sa_cipher = KTLS_CIPHER_AES_GCM_128;
	sa_ktls.sa_socket = sd; // bind to this socket
	sa_ktls.sa_version = KTLS_VERSION_1_2;

	err = bind(ksd, (struct sockaddr *) &sa_ktls, sizeof(sa_ktls));
	if (err < 0) {
		perror("failed to bind TCP/UCP socket");
		goto init_error;
	}

	err = ktls_socket_update_state(session, ksd, tls);
	if (err < 0)
		goto init_error;

	if (offload) {
		int offload_temp = 1;
		err = setsockopt(ksd, AF_KTLS, KTLS_SET_OFFLOAD, &offload_temp, sizeof(offload_temp));
		if (err < 0) {
			print_error("failed to enable offload using setsockopt(2)");
			goto init_error;
		}
	}

	if (sendfile_mtu) {
		err = setsockopt(ksd, AF_KTLS, KTLS_SET_MTU, &sendfile_mtu, sizeof(sendfile_mtu));
		if (err < 0) {
			perror("setsockopt");
			print_error("failed to set MTU on AF_KTLS socket using setsockopt(2)");
			goto init_error;
		}
	}

	return ksd;

init_error:
	close(ksd);
	return -1;
}

extern int ktls_socket_destruct(int ksd, gnutls_session_t session) {
	const int iv_len = 8;
	int err;
	unsigned char new_iv[iv_len];

	err = getsockopt(ksd, AF_KTLS, KTLS_GET_IV_SEND, new_iv, (socklen_t *) &iv_len);
	if (err < 0) {
		perror("getsockopt");
		print_error("failed to get send IV from AF_KTLS socket");
		goto destruct_error;
	}

	// we set only sequence number
	err = gnutls_record_set_state(session, 0, new_iv);
	if (err) {
		print_error("failed to set send IV on Gnu TLS's session");
		goto destruct_error;
	}

	err = getsockopt(ksd, AF_KTLS, KTLS_GET_IV_RECV, new_iv, (socklen_t *) &iv_len);
	if (err < 0) {
		print_error("failed to get receive IV from AF_KTLS socket");
		goto destruct_error;
	}

	// we set only sequence number
	err = gnutls_record_set_state(session, 1, new_iv);
	if (err) {
		print_error("failed to set receive IV on Gnu TLS's session");
		goto destruct_error;
	}

	close(ksd);
	return 0;

destruct_error:
	// we close kernel TLS socket anyway...
	close(ksd);
	return -1;
}

