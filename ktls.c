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
#include <string.h>

#include "common.h"
#include "ktls.h"

#include "netinet/tcp.h"

static int ktls_socket_set_crypto_state(gnutls_session_t session, int ksd, bool send, bool tls, bool offload)
{
	struct tls12_crypto_info_aes_gcm_128 crypto_info;
	int optname, rc = -1;
	gnutls_datum_t mac_key;
	gnutls_datum_t iv_read;
	gnutls_datum_t iv_write;
	gnutls_datum_t cipher_key_read;
	gnutls_datum_t cipher_key_write;
	unsigned char seq_number_read[8];
	unsigned char seq_number_write[8];

	// now we need to initialize state after the handshake in the kernel
	rc = gnutls_record_get_state(session, 1, &mac_key, &iv_read, &cipher_key_read, seq_number_read);
	if (rc < 0) {
		print_error("failed to get receiving state from Gnu TLS session");
		goto err;
	}

	rc = gnutls_record_get_state(session, 0, &mac_key, &iv_write, &cipher_key_write, seq_number_write);
	if (rc < 0) {
		print_error("failed to get sendig state from Gnu TLS session");
		goto err;
	}

	memset(&crypto_info, 0, sizeof(crypto_info));

	/* version is hardcoded for now */
	crypto_info.info.version = TLS_1_2_VERSION;

	/* cipher type is hardcoded for now
	 * TODO: [AY] get it from certificate */
	crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

	crypto_info.info.state = offload ? TLS_STATE_HW :
		TLS_STATE_SW;

	if (send) {
		memcpy(crypto_info.iv, seq_number_write, TLS_CIPHER_AES_GCM_128_IV_SIZE);
		memcpy(crypto_info.rec_seq, seq_number_write,
		       TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
		if (cipher_key_write.size != TLS_CIPHER_AES_GCM_128_KEY_SIZE) {
			print_error("mismatch in send key size");
			goto err;
		}
		memcpy(crypto_info.key, cipher_key_write.data, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
		memcpy(crypto_info.salt, iv_write.data, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
		optname = TCP_TLS_TX;
	} else {
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
		memcpy(crypto_info.iv, seq_number_read, TLS_CIPHER_AES_GCM_128_IV_SIZE);
		if (cipher_key_read.size != TLS_CIPHER_AES_GCM_128_KEY_SIZE) {
			print_error("mismatch in recv key size");
			goto err;
		}
		memcpy(crypto_info.key, cipher_key_read.data, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
		memcpy(crypto_info.salt, iv_read.data, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
		optname = TCP_TLS_RX;
	}

	rc = setsockopt(ksd, SOL_TCP, optname, &crypto_info, sizeof(crypto_info));
	if (rc < 0) {
		print_error("failed to set send crypto info using setsockopt(2)");
		goto err;
	}

	return 0;

err:
	return rc;
}

static int ktls_socket_get_crypto_state(gnutls_session_t session, int ksd, bool send, bool offload)
{
	struct tls12_crypto_info_aes_gcm_128 crypto_info;
	int optname, rc = -1;
	socklen_t optlen = sizeof(crypto_info);

	if (send) {
		optname = TCP_TLS_TX;
	} else {
		optname = TCP_TLS_RX;
	}

	memset(&crypto_info, 0, sizeof(crypto_info));

	rc = getsockopt(ksd, SOL_TCP, optname, &crypto_info, &optlen);
	if (rc < 0) {
		print_error("failed to get send crypto info using getsockopt(2)");
		goto err;
	}

	/* check version */
	if (crypto_info.info.version != TLS_1_2_VERSION) {
		print_error("incorrect version queried");
		goto err;
	}

	/* check cipher */
	if (crypto_info.info.cipher_type != TLS_CIPHER_AES_GCM_128) {
		print_error("incorrect cipher type queried");
		goto err;
	}

	/* check offload state */
	if (offload && crypto_info.info.state != TLS_STATE_HW) {
		print_error("incorrect offload state queried");
		goto err;
	}
	if (!offload && crypto_info.info.state != TLS_STATE_SW) {
		print_error("incorrect offload state queried");
		goto err;
	}

	/* we set only sequence number */
	rc = gnutls_record_set_state(session, !send, crypto_info.iv);
	if (rc) {
		print_error("failed to set receive IV on Gnu TLS's session");
		goto err;
	}

	return 0;

err:
	return rc;
}


#ifdef TLS_SET_MTU
extern int ktls_socket_init(gnutls_session_t session, int sd, size_t sendfile_mtu, bool send, bool tls, bool offload)
#else
extern int ktls_socket_init(gnutls_session_t session, int sd, bool send, bool tls, bool offload)
#endif
{
	int err;

	err = ktls_socket_set_crypto_state(session, sd, send, tls, offload);
	if (err) {
		print_error("failed to set crypto state");
		goto set_crypto_error;
	}

#ifdef TLS_SET_MTU
	if (sendfile_mtu) {
		err = setsockopt(ksd, AF_KTLS, KTLS_SET_MTU, &sendfile_mtu, sizeof(sendfile_mtu));
		if (err < 0) {
			perror("setsockopt");
			print_error("failed to set MTU on AF_KTLS socket using setsockopt(2)");
			goto init_error;
		}
	}
#endif

	return 0;

set_crypto_error:
	return err;
}

extern int ktls_socket_destruct(gnutls_session_t session, int sd, bool send, bool offload)
{
	int err;

	err = ktls_socket_get_crypto_state(session, sd, send, offload);
	if (err < 0) {
		print_error("failed to get crypto state");
		goto get_crypto_error;
	}

	return 0;

get_crypto_error:
	return err;
}
