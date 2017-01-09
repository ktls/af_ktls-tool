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

#define _GNU_SOURCE
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/user.h>

#include "common.h"
#include "verify.h"

#define TLS_PAYLOAD_MAX_LEN         (1 << 14)
#define DTLS_OVERHEAD               (13 + 8 + 16) // TODO: rewrite
#define TLS_OVERHEAD                (5 + 8 + 16)  // TODO: rewrite
#define MIN(X, Y)                   ((X) > (Y) ? (Y) : (X))
#define AES128_GCM_KEY_SIZE          ((size_t) 16)
#define AES128_GCM_IV_SIZE           ((size_t)8)
#define AES128_GCM_SALT_SIZE         ((size_t)4)

static int pipe_write(int ksd, char *mem_send, size_t send_size, char *mem_recv, size_t recv_size, unsigned mtu) {
	int err;
	int p[2] = {0, 0};
	size_t received;

	err = pipe(p);
	if (err < 0) {
		perror("pipe");
		goto pipe_write_end;
	}

	memset(mem_send, 0x12, send_size);
	memset(mem_recv, 0x43, recv_size);

	print_info("verifying tls_sendpage() for MTU == %u, size of send data %ld, size of recv buffer %ld", mtu, send_size, recv_size);

	err = write(p[1], mem_send, send_size);
	if (err < 0) {
		perror("write");
		goto pipe_write_end;
	}

	if (err != send_size)
		print_warning("write: return value differs from write count");

	err = splice(p[0], NULL, ksd, NULL, send_size, 0);
	if (err < 0) {
		perror("splice");
		goto pipe_write_end;
	}

	if (err != send_size)
		print_warning("splice: return value differs from splice len");

	received = 0;
	do {
		err = recv(ksd, mem_recv, recv_size, 0);

		if (err < 0) {
			perror("received");
			goto pipe_write_end;
		}

		if (memcmp(mem_send + received, mem_recv, err)) {
			print_error("sent and received data differ");
			print_error("sent chunk:");
			print_hex(mem_send + received, err);
			print_error("received:");
			print_hex(mem_recv, recv_size);
			err = -EBADMSG;
			goto pipe_write_end;
		}

		received += err;

		if (err == 0) {
			print_error("premature end of connection");
			err = -ECONNABORTED;
			break;
		}
	} while (received != send_size);

	if (received != send_size) {
		print_error("not all data received");
		err = -EAGAIN;
	}

pipe_write_end:
	if (p[0])
		close(p[0]);
	if (p[1])
		close(p[1]);
	return err;
}

extern int verify_sendpage(int ksd, bool tls) {
	int err;
	char *mem_send = NULL;
	char *mem_recv = NULL;
	size_t size;
	size_t mtu;

	assert(ksd > 0);

	mem_send = malloc(TLS_PAYLOAD_MAX_LEN + 1);
	mem_recv = malloc(TLS_PAYLOAD_MAX_LEN + 1);
	if (!mem_send || !mem_recv) {
		perror("malloc");
		err = errno;
		goto verify_sendpage_end;
	}

	print_info("verifying tls_sendpage() implementation, page size == %ld", PAGE_SIZE);

	mtu = TLS_PAYLOAD_MAX_LEN;
	err = setsockopt(ksd, AF_KTLS, KTLS_SET_MTU, &mtu, sizeof(mtu));
	if (err < 0) {
		perror("failed to perform setsockopt()");
		goto verify_sendpage_end;
	}

	size = PAGE_SIZE >> 1;
	err = pipe_write(ksd, mem_send, size, mem_recv, size, mtu);
	if (err < 0)
		goto verify_sendpage_end;

	size = PAGE_SIZE;
	err = pipe_write(ksd, mem_send, size, mem_recv, size, mtu);
	if (err < 0)
		goto verify_sendpage_failed;

	size = (PAGE_SIZE << 1) + 10;
	err = pipe_write(ksd, mem_send, size, mem_recv, size, mtu);
	if (err < 0)
		goto verify_sendpage_end;

	//if (!tls)
		size = TLS_PAYLOAD_MAX_LEN - DTLS_OVERHEAD;
	//else
	//	size = TLS_PAYLOAD_MAX_LEN - TLS_OVERHEAD;
	err = pipe_write(ksd, mem_send, size, mem_recv, size, mtu);
	if (err < 0) {
		print_error("failed to verify tls_sendpage() for size == %ld", size);
		goto verify_sendpage_end;
	}

	mtu = 100;
	err = setsockopt(ksd, AF_KTLS, KTLS_SET_MTU, &mtu, sizeof(mtu));
	if (err < 0) {
		perror("failed to perform setsockopt()");
		goto verify_sendpage_end;
	}

	size = PAGE_SIZE;
	err = pipe_write(ksd, mem_send, size, mem_recv, size, mtu);
	if (err < 0)
		goto verify_sendpage_failed;

	size = PAGE_SIZE*2 + 42;
	err = pipe_write(ksd, mem_send, size, mem_recv, size, mtu);
	if (err < 0)
		goto verify_sendpage_failed;

	err = 0;
	print_info("verify tls_sendpage() passed");

verify_sendpage_failed:
	if (err < 0)
		print_error("failed to verify tls_sendpage() for size == %ld", size);

verify_sendpage_end:
	if (mem_send)
		free(mem_send);
	if (mem_recv)
		free(mem_recv);
	return err;
}

static int send_recv(int ksd, char *mem_send, size_t send_size, char *mem_recv, size_t recv_size) {
	int err;
	size_t received;

	memset(mem_send, 0x98, send_size);
	memset(mem_recv, 0x67, send_size);

	print_info("verifying tls_sendmsg()/tls_recvmsg(), size of send data %ld, size of recv buffer %ld", send_size, recv_size);

	err = send(ksd, mem_send, send_size, 0);
	if (err < 0) {
		perror("send");
		goto send_recv_end;
	}

	if (err != send_size)
		print_warning("send returned different");

	received = 0;
	do {
		err = recv(ksd, mem_recv, recv_size, 0);
		if (err < 0) {
			perror("recv");
			goto send_recv_end;
		}

		if (err == 0) {
			print_error("premature end of connection");
			err = -ECONNABORTED;
			goto send_recv_end;
		}

		if (memcmp(mem_send + received, mem_recv, err)) {
			print_error("sent and received data differ");
			print_error("sent chunk:");
			print_hex(mem_send + received, err);
			print_error("received:");
			print_hex(mem_recv, recv_size);
			err = -EBADMSG;
			goto send_recv_end;
		}

		received += err;

	} while(send_size != received);

send_recv_end:
	return err;
}

extern int verify_transmission(int ksd) {
	int err;
	size_t size;
	char *mem_send = NULL;
	char *mem_recv = NULL;

	assert(ksd > 0);

	print_info("verifying tls_sendmsg()/tls_recvmsg() implementation, page size == %ld", PAGE_SIZE);

	mem_send = malloc(TLS_PAYLOAD_MAX_LEN + 1);
	mem_recv = malloc(TLS_PAYLOAD_MAX_LEN + 1);
	if (!mem_send || !mem_recv) {
		perror("malloc");
		err = errno;
		goto verify_transmission_end;
	}

	/*
	 * normal send() first
	 */
	size = TLS_PAYLOAD_MAX_LEN - DTLS_OVERHEAD;
	err = send_recv(ksd, mem_send, size, mem_recv, size);
	if (err < 0)
		goto verify_transmission_failed;

	size = 100;
	err = send_recv(ksd, mem_send, size, mem_recv, size);
	if (err < 0)
		goto verify_transmission_failed;

	size = (PAGE_SIZE*2) + 42;
	err = send_recv(ksd, mem_send, size, mem_recv, size);
	if (err < 0)
		goto verify_transmission_failed;

	size = PAGE_SIZE;
	err = send_recv(ksd, mem_send, size, mem_recv, size);
	if (err < 0)
		goto verify_transmission_failed;

	/*
	 * Try to send in a record more than allowed
	 */

	print_info("trying to send more than allowed per record - error signalization expected");
	size = TLS_PAYLOAD_MAX_LEN + 1;
	err = send(ksd, mem_send, size, 0);
	if (errno != E2BIG) {
		print_error("AF_KTLS allowed to send bigger record than allowed");
		err = -EBADMSG;
	}

	err = 0;
	print_info("verify tls_sendmsg()/tls_recvmsg() passed");

verify_transmission_failed:
	if (err < 0)
		print_error("failed to verify tls_sendmsg()/tls_recvmsg() for size == %ld", size);

verify_transmission_end:
	if (mem_send)
		free(mem_send);
	if (mem_recv)
		free(mem_recv);
	return err;
}

static int splice_read(int ksd, char *mem_send, size_t send_size, char *mem_recv, size_t recv_size) {
	int err;
	int p[2] = {0, 0};
	size_t received;

	print_info("verifying tls_splice_read(), size of send data %ld, size of recv buffer %ld", send_size, recv_size);

	err = pipe(p);
	if (err < 0) {
		perror("pipe");
		goto splice_read_end;
	}

	memset(mem_recv, 0x67, recv_size);
	memset(mem_send, 0x92, send_size);

	err = send(ksd, mem_send, send_size, 0);
	if (err < 0) {
		perror("send");
		goto splice_read_end;
	}

	received = 0;
	do {
		// be careful with pipe buf len
		err = splice(ksd, NULL, p[1], NULL, recv_size, 0);
		if (err < 0) {
			perror("splice");
			goto splice_read_end;
		}

		if (err != send_size)
			print_warning("splice returned different size");

		err = read(p[0], mem_recv, recv_size);
		if (err < 0)
			perror("read");

		if (memcmp(mem_send + received, mem_recv, err)) {
			print_error("sent and received data differ");
			print_error("sent chunk:");
			print_hex(mem_send + received, err);
			print_error("received:");
			print_hex(mem_recv, recv_size);
			err = -EBADMSG;
			goto splice_read_end;
		}

		received += err;

		if (err == 0) {
			print_error("premature end of connection");
			err = -ECONNABORTED;
			break;
		}
	} while (received != send_size);

	err = 0;

splice_read_end:
	if (p[0])
		close(p[0]);
	if (p[1])
		close(p[1]);
	return err;
}

extern int verify_splice_read(int ksd) {
	int err;
	char *mem_recv = NULL;
	char *mem_send = NULL;
	size_t size;

	assert(ksd > 0);

	print_info("verifying tls_splice_read() implementation, page size == %ld", PAGE_SIZE);

	mem_send = malloc(TLS_PAYLOAD_MAX_LEN + 1);
	mem_recv = malloc(TLS_PAYLOAD_MAX_LEN + 1);
	if (!mem_send  || !mem_recv) {
		perror("malloc");
		err = -ENOMEM;
		goto verify_splice_read_end;
	}

	size = TLS_PAYLOAD_MAX_LEN - DTLS_OVERHEAD;
	err = splice_read(ksd, mem_send, size, mem_recv, size);
	if (err < 0)
		goto verify_splice_read_failed;

	size = 100;
	err = splice_read(ksd, mem_send, size, mem_recv, size);
	if (err < 0)
		goto verify_splice_read_failed;

	size = (PAGE_SIZE*2) + 42;
	err = splice_read(ksd, mem_send, size, mem_recv, size);
	if (err < 0)
		goto verify_splice_read_failed;

	size = PAGE_SIZE;
	err = splice_read(ksd, mem_send, size, mem_recv, size);
	if (err < 0)
		goto verify_splice_read_failed;

	err = 0;

verify_splice_read_failed:
	if (err < 0)
		print_error("failed to verify tls_splice_read() for size == %ld", size);

verify_splice_read_end:
	if (mem_recv)
		free(mem_recv);
	if (mem_send)
		free(mem_send);
	return err;
}

static int sockopt_iv(int ksd, bool recv) {
	int err;
	const int optname_set = recv ? KTLS_SET_IV_RECV : KTLS_SET_IV_SEND;
	const int optname_get = recv ? KTLS_GET_IV_RECV : KTLS_GET_IV_SEND;
	socklen_t optlen;
	char buf[AES128_GCM_IV_SIZE + 1];
	char buf_tmp[AES128_GCM_IV_SIZE + 1];

	print_info("trying to get IV, but not enough memory supplied");
	optlen = AES128_GCM_IV_SIZE - 1;
	err = getsockopt(ksd, AF_KTLS, optname_get, buf, &optlen);
	if (err >= 0 || errno != ENOMEM) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_iv_end;
	}

	print_info("trying to set IV, but smaller IV size supplied");
	optlen = AES128_GCM_IV_SIZE - 1;
	err = setsockopt(ksd, AF_KTLS, optname_set, buf, optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_iv_end;
	}

	print_info("trying to set IV, but bigger IV size supplied");
	optlen = AES128_GCM_IV_SIZE - 1;
	err = setsockopt(ksd, AF_KTLS, optname_set, buf, optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_iv_end;
	}

	print_info("trying to set IV");
	optlen = AES128_GCM_IV_SIZE;
	memset(buf, 0, sizeof(buf));
	err = setsockopt(ksd, AF_KTLS, optname_set, buf, optlen);
	if (err < 0) {
		perror("setsockopt: failed to set IV");
		goto sockopt_iv_end;
	}

	print_info("trying to get IV");
	optlen = AES128_GCM_IV_SIZE;
	memset(buf_tmp, 0x11, sizeof(buf_tmp));
	err = getsockopt(ksd, AF_KTLS, optname_get, buf_tmp, &optlen);
	if (err < 0) {
		perror("getsockopt: failed to get IV");
		goto sockopt_iv_end;
	}

	if (optlen != AES128_GCM_IV_SIZE) {
		print_error("getsockopt: optlen does not match IV size");
		err = -EBADMSG;
		goto sockopt_iv_end;
	}

	if (memcmp(buf, buf_tmp, AES128_GCM_IV_SIZE)) {
		print_error("set and received IV differs from ");
		err = -EBADMSG;
		goto sockopt_iv_end;
	}

	err = 0;

sockopt_iv_end:
	return err;
}

static int sockopt_key(int ksd, bool recv) {
	int err;
	const int optname_set = recv ? KTLS_SET_KEY_RECV : KTLS_SET_KEY_SEND;
	const int optname_get = recv ? KTLS_GET_KEY_RECV : KTLS_GET_KEY_SEND;
	socklen_t optlen;
	char buf[AES128_GCM_KEY_SIZE + 1];
	char buf_tmp[AES128_GCM_KEY_SIZE + 1];

	print_info("trying to get key, but not enough memory supplied");
	optlen = AES128_GCM_KEY_SIZE - 1;
	err = getsockopt(ksd, AF_KTLS, optname_get, buf, &optlen);
	if (err >= 0 || errno != ENOMEM) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_key_end;
	}

	print_info("trying to set key, but smaller key size supplied");
	optlen = AES128_GCM_KEY_SIZE - 1;
	err = setsockopt(ksd, AF_KTLS, optname_set, buf, optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_key_end;
	}

	print_info("trying to set key, but bigger key size supplied");
	optlen = AES128_GCM_KEY_SIZE - 1;
	err = setsockopt(ksd, AF_KTLS, optname_set, buf, optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_key_end;
	}

	print_info("trying to set key");
	optlen = AES128_GCM_KEY_SIZE;
	memset(buf, 0, sizeof(buf));
	err = setsockopt(ksd, AF_KTLS, optname_set, buf, optlen);
	if (err < 0) {
		perror("setsockopt: failed to set key");
		goto sockopt_key_end;
	}

	print_info("trying to get key");
	optlen = AES128_GCM_KEY_SIZE;
	memset(buf_tmp, 0x11, sizeof(buf_tmp));
	err = getsockopt(ksd, AF_KTLS, optname_get, buf_tmp, &optlen);
	if (err < 0) {
		perror("getsockopt: failed to get key");
		goto sockopt_key_end;
	}

	if (optlen != AES128_GCM_KEY_SIZE) {
		print_error("getsockopt: optlen does not match key size");
		err = -EBADMSG;
		goto sockopt_key_end;
	}

	if (memcmp(buf, buf_tmp, AES128_GCM_KEY_SIZE)) {
		print_error("set and received key differs from ");
		err = -EBADMSG;
		goto sockopt_key_end;
	}

	err = 0;

sockopt_key_end:
	return err;
}

static int sockopt_salt(int ksd, bool recv) {
	int err;
	const int optname_set = recv ? KTLS_SET_SALT_RECV : KTLS_SET_SALT_SEND;
	const int optname_get = recv ? KTLS_GET_SALT_RECV : KTLS_GET_SALT_SEND;
	socklen_t optlen;
	char buf[AES128_GCM_SALT_SIZE + 1];
	char buf_tmp[AES128_GCM_SALT_SIZE + 1];

	print_info("trying to get salt, but not enough memory supplied");
	optlen = AES128_GCM_SALT_SIZE - 1;
	err = getsockopt(ksd, AF_KTLS, optname_get, buf, &optlen);
	if (err >= 0 || errno != ENOMEM) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_salt_end;
	}

	print_info("trying to set salt, but smaller salt size supplied");
	optlen = AES128_GCM_SALT_SIZE - 1;
	err = setsockopt(ksd, AF_KTLS, optname_set, buf, optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_salt_end;
	}

	print_info("trying to set salt, but bigger salt size supplied");
	optlen = AES128_GCM_SALT_SIZE - 1;
	err = setsockopt(ksd, AF_KTLS, optname_set, buf, optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_salt_end;
	}

	print_info("trying to set salt");
	optlen = AES128_GCM_SALT_SIZE;
	memset(buf, 0, sizeof(buf));
	err = setsockopt(ksd, AF_KTLS, optname_set, buf, optlen);
	if (err < 0) {
		perror("setsockopt: failed to set salt");
		goto sockopt_salt_end;
	}
	print_info("trying to get salt");
	optlen = AES128_GCM_SALT_SIZE;
	memset(buf_tmp, 0x11, sizeof(buf_tmp));
	err = getsockopt(ksd, AF_KTLS, optname_get, buf_tmp, &optlen);
	if (err < 0) {
		perror("getsockopt: failed to get salt");
		goto sockopt_salt_end;
	}

	if (optlen != AES128_GCM_SALT_SIZE) {
		print_error("getsockopt: optlen does not match salt size");
		err = -EBADMSG;
		goto sockopt_salt_end;
	}

	if (memcmp(buf, buf_tmp, AES128_GCM_SALT_SIZE)) {
		print_error("set and received salt differs from ");
		err = -EBADMSG;
		goto sockopt_salt_end;
	}

	err = 0;

sockopt_salt_end:
	return err;
}

static int sockopt_mtu(int ksd, bool tls) {
	int err;
	const size_t probe_mtu = 1280;
	size_t mtu;
	socklen_t size;

	print_info("trying to set MTU");
	mtu = probe_mtu;
	err = setsockopt(ksd, AF_KTLS, KTLS_SET_MTU, &mtu, sizeof(mtu));
	if (err < 0) {
		perror("setsockopt");
		goto sockopt_mtu_end;
	}

	print_info("trying to get MTU");
	mtu = 0;
	size = sizeof(mtu);
	err = getsockopt(ksd, AF_KTLS, KTLS_GET_MTU, &mtu, &size);
	if (err < 0) {
		perror("getsockopt");
		goto sockopt_mtu_end;
	}

	if (mtu != probe_mtu) {
		print_error("set and get MTU are different; set: %lu, got: %lu", probe_mtu, mtu);
		err = -EBADMSG;
		goto sockopt_mtu_end;
	}

	if (sizeof(mtu) != size) {
		print_error("suspicious MTU size from getsockopt(2) (%u)", size);
		err = -EBADMSG;
		goto sockopt_mtu_end;
	}

	err = 0;

sockopt_mtu_end:
	return err;
}

static int sockopt_unbinded(void) {
	int err;
	int ksd = 0;
	size_t mtu;
	int p[2] = {0, 0};
	const char buf_len = AES128_GCM_KEY_SIZE;
	char buf[buf_len];
	socklen_t optlen;

	/*
	 * SEQPACKET is not supported
	 */
	//print_info("trying to create unsupported type");
	//ksd = socket(AF_KTLS, SOCK_SEQPACKET, 0);
	//if (ksd >= 0 || errno != ESOCKTNOSUPPORT) {
	//	print_error("getsockopt: AF_KTLS did not populated error correctly");
	//	err = -EBADMSG;
	//	goto sockopt_unbinded_end;
	//}

	print_info("creating unbinded socket");
	ksd = socket(AF_KTLS, SOCK_DGRAM, 0);
	if (ksd < 0) {
		perror("socket");
		err = errno;
		goto sockopt_unbinded_end;
	}

	print_info("getting IV recv from uninitialized socket");
	optlen = AES128_GCM_IV_SIZE;
	err = getsockopt(ksd, AF_KTLS, KTLS_GET_IV_RECV, buf, &optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_unbinded_end;
	}

	print_info("setting IV recv from uninitialized socket");
	optlen = AES128_GCM_IV_SIZE;
	err = setsockopt(ksd, AF_KTLS, KTLS_GET_IV_RECV, buf, optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_unbinded_end;
	}

	print_info("getting IV send from uninitialized socket");
	optlen = AES128_GCM_IV_SIZE;
	err = getsockopt(ksd, AF_KTLS, KTLS_GET_IV_SEND, buf, &optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_unbinded_end;
	}

	print_info("setting IV send from uninitialized socket");
	optlen = AES128_GCM_IV_SIZE;
	err = setsockopt(ksd, AF_KTLS, KTLS_GET_IV_SEND, buf, optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_unbinded_end;
	}

	print_info("getting key recv from uninitialized socket");
	optlen = AES128_GCM_KEY_SIZE;
	err = getsockopt(ksd, AF_KTLS, KTLS_GET_KEY_RECV, buf, &optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_unbinded_end;
	}

	print_info("setting key recv from uninitialized socket");
	optlen = AES128_GCM_KEY_SIZE;
	err = setsockopt(ksd, AF_KTLS, KTLS_GET_KEY_RECV, buf, optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_unbinded_end;
	}

	print_info("getting key send from uninitialized socket");
	optlen = AES128_GCM_KEY_SIZE;
	err = getsockopt(ksd, AF_KTLS, KTLS_GET_KEY_SEND, buf, &optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_unbinded_end;
	}

	print_info("setting key send from uninitialized socket");
	optlen = AES128_GCM_KEY_SIZE;
	err = setsockopt(ksd, AF_KTLS, KTLS_GET_KEY_SEND, buf, optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_unbinded_end;
	}

	print_info("getting salt recv from uninitialized socket");
	optlen = AES128_GCM_SALT_SIZE;
	err = getsockopt(ksd, AF_KTLS, KTLS_GET_SALT_RECV, buf, &optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_unbinded_end;
	}

	print_info("setting salt recv from uninitialized socket");
	optlen = AES128_GCM_SALT_SIZE;
	err = setsockopt(ksd, AF_KTLS, KTLS_GET_SALT_RECV, buf, optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_unbinded_end;
	}

	print_info("getting salt send from uninitialized socket");
	optlen = AES128_GCM_SALT_SIZE;
	err = getsockopt(ksd, AF_KTLS, KTLS_GET_SALT_SEND, buf, &optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_unbinded_end;
	}

	print_info("setting salt send from uninitialized socket");
	optlen = AES128_GCM_SALT_SIZE;
	err = setsockopt(ksd, AF_KTLS, KTLS_GET_SALT_SEND, buf, optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_unbinded_end;
	}

	print_info("getting MTU from uninitialized socket");
	optlen = sizeof(mtu);
	err = getsockopt(ksd, AF_KTLS, KTLS_GET_MTU, &mtu, &optlen);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_unbinded_end;
	}

	print_info("trying to call send(2) on unbinded socket");
	err = send(ksd, buf, buf_len, 0);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_unbinded_end;
	}

	print_info("trying to call recv(2) on unbinded socket");
	err = recv(ksd, buf, buf_len, 0);
	if (err >= 0 || errno != EBADMSG) {
		print_error("getsockopt: AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_unbinded_end;
	}

	/*
	 * verify tls_sendpage() and tls_splice_read()
	 */
	err = pipe(p);
	if (err < 0) {
		perror("pipe");
		goto sockopt_unbinded_end;
	}

	print_info("testing tls_splice_read() on uninitialized socket");
	err = splice(ksd, NULL, p[1], NULL, 100, 0);
	if (err >= 0 || errno != EBADMSG) {
		print_error("AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_unbinded_end;
	}

	err = write(p[1], buf, buf_len);
	if (err < 0) {
		print_error("write");
		goto sockopt_unbinded_end;
	}

	print_info("testing tls_sendpage() on uninitialized socket");
	err = splice(p[0], NULL, ksd, NULL, buf_len, 0);
	if (err >= 0 || errno != EBADMSG) {
		print_error("AF_KTLS did not populated error correctly");
		err = -EBADMSG;
		goto sockopt_unbinded_end;
	}

	err = 0;

sockopt_unbinded_end:
	if (p[0])
		close(p[0]);
	if (p[1])
		close(p[1]);
	if (ksd)
		close(ksd);
	return err;
}

extern int verify_handling(int ksd, bool tls) {
	// TODO: sockopt_{iv,key,salt} can be merged into one
	int err;

	assert(ksd > 0);

	print_info("verifying tls_setsockopt()/tls_getsockopt() implementation");

	/*
	 * Expected AES GCM, currently the only supported cipher by AF_KTLS
	 */
	err = sockopt_iv(ksd, 0);
	if (err < 0) {
		print_error("failed to verify tls_setsockopt()/tls_getsockopt() of IV recv");
		goto verify_handling_end;
	} else {
		print_info("tls_setsockopt()/tls_getsockopt() of IV recv passed");
	}

	err = sockopt_iv(ksd, 1);
	if (err < 0) {
		print_error("failed to verify tls_setsockopt()/tls_getsockopt() of IV send");
		goto verify_handling_end;
	} else {
		print_info("tls_setsockopt()/tls_getsockopt() of IV send passed");
	}

	err = sockopt_key(ksd, 0);
	if (err < 0) {
		print_error("failed to verify tls_setsockopt()/tls_getsockopt() of key recv");
		goto verify_handling_end;
	} else {
		print_info("tls_setsockopt()/tls_getsockopt() of key recv passed");
	}

	err = sockopt_key(ksd, 1);
	if (err < 0) {
		print_error("failed to verify tls_setsockopt()/tls_getsockopt() of key send");
		goto verify_handling_end;
	} else {
		print_info("tls_setsockopt()/tls_getsockopt() of key send passed");
	}

	err = sockopt_salt(ksd, 0);
	if (err < 0) {
		print_error("failed to verify tls_setsockopt()/tls_getsockopt() of salt recv");
		goto verify_handling_end;
	} else {
		print_info("tls_setsockopt()/tls_getsockopt() of salt recv passed");
	}

	err = sockopt_salt(ksd, 0);
	if (err < 0) {
		print_error("failed to verify tls_setsockopt()/tls_getsockopt() of salt send");
		goto verify_handling_end;
	} else {
		print_info("tls_setsockopt()/tls_getsockopt() of salt send passed");
	}

	err = sockopt_mtu(ksd, tls);
	if (err < 0) {
		print_error("failed to verify tls_setsockopt()/tls_getsockopt() of MTU");
		goto verify_handling_end;
	} else {
		print_info("tls_setsockopt()/tls_getsockopt() of MTU passed");
	}

	/*
	 * Operations on nonbinded socket should reveal errors
	 */
	err = sockopt_unbinded();
	if (err < 0) {
		print_error("failed to verify correct behaviour of AF_KTLS on unbinded socket");
		goto verify_handling_end;
	} else {
		print_info("tls_setsockopt()/tls_getsockopt() on unbinded socket passed");
	}

	print_info("vefify handling passed, the connection will not be closed "
					"properly since socket state is tainted");

	err = 0;

verify_handling_end:
	return err;
}

