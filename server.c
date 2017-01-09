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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <unistd.h>
#include <netdb.h>

#include <gnutls/gnutls.h>
#include <gnutls/compat.h>
#include <gnutls/dtls.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <gnutls/crypto.h>

#include "plain_server.h"
#include "server.h"
#include "common.h"
#include "ktls.h"

#define KEYFILE "certs/server-key.pem"
#define CERTFILE "certs/server-cert.pem"
#define CAFILE "certs/ca-cert.pem"
#define CRLFILE "/etc/ocserv/cert.key"

#define SOCKET_ERR(err,s) if(err==-1) {perror(s);return(1);}

/*
 * we will do it with global var since we want to capture error in thread even
 * in a standalone process and we want to keep it simple; modified only by
 * run_server();
 */
int server_err = 0;

static int dtls_pull_timeout_func(gnutls_transport_ptr_t ptr, unsigned int ms);
static ssize_t dtls_push_func(gnutls_transport_ptr_t p, const void *data,
			 size_t size);
static ssize_t dtls_pull_func(gnutls_transport_ptr_t p, void *data,
			 size_t size);
static const char *human_addr(const struct sockaddr *sa, socklen_t salen,
			      char *buf, size_t buflen);
static int dtls_wait_for_connection(int fd);
static int generate_dh_params(void);

/* Use global credentials and parameters to simplify
 * the example. */
static gnutls_certificate_credentials_t x509_cred;
static gnutls_dh_params_t dh_params;


static int server_gnutls_loop(const struct server_opts *opts, gnutls_session_t session,
								char *buffer, int sd) {
	int ret;
	unsigned char sequence[8];

	for (;;) {
		if (!opts->raw_recv) {
			do {
				ret = gnutls_record_recv_seq(session, buffer, opts->mtu, sequence);
			} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
		} else {
			ret = recv(sd, buffer, opts->mtu, 0);
			if (ret < 0) {
				perror("recv");
				print_error("failed to recv");
				break;
			}
		}

		if (!opts->raw_recv) {
			if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
				print_warning("*** Warning: %s", gnutls_strerror(ret));
				continue;
			} else if (ret < 0) {
				print_error("Error in recv(): %s", gnutls_strerror(ret));
				break;
			}
		}

		if (ret == 0) {
			if (opts->verbose_level >= VERBOSE_LEVEL_PACKETS)
				print_info("connection closed");
			break;
		}

		if (opts->verbose_level >= VERBOSE_LEVEL_PACKETS) {
			buffer[ret] = 0;
			print_info
				("received[%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x]: ",
				sequence[0], sequence[1], sequence[2],
				sequence[3], sequence[4], sequence[5],
				sequence[6], sequence[7]);

			print_hex(buffer, ret);
		}

		if (!opts->no_echo) {
			ret = gnutls_record_send(session, buffer, ret);
			if (ret < 0) {
				// if we do raw recv, just ignore recv errors, since recv channel is tainted,
				// this handling is OK for benchmark tests
				if (!opts->raw_recv) {
					print_error("Error in send(): %s",
						gnutls_strerror(ret));
				} else {
					ret = 0;
				}
				break;
			}
		}

		if (opts->store_file)
			write(opts->store_file, buffer, ret);
	}
	printf("server loop done\n");
	return ret < 0 ? ret : 0;
}

static int server_ktls_loop(const struct server_opts *opts, gnutls_session_t session, int sd, struct sockaddr *cli_addr, socklen_t cli_addr_size, char *buf) {
	int tls_init = false, err;
	socklen_t cli_addr_size_tmp;

#ifdef TLS_SET_MTU
	err = ktls_socket_init(session, sd, 0, false, opts->tls, false);
#else
	err = ktls_socket_init(session, sd, false, opts->tls, false);
#endif
	if (err < 0) {
		print_error("failed to make AF_KTLS socket on server");
		return -1;
	}
	tls_init = true;

	for (;;) {
		err = recvfrom(sd, buf, opts->mtu, 0, cli_addr, &cli_addr_size_tmp);
		if (err < 0) {
			perror("recv");
			print_error("probably not data packet, fallback to Gnu TLS");
			err = server_gnutls_loop(opts, session, buf, sd);
			goto ktls_loop_end;
		}

		if (err == 0) {
			print_info("connection terminated by client");
			goto ktls_loop_end;
		}

		if (opts->store_file)
			write(opts->store_file, buf, err);

		if (!opts->no_echo) {
			err = sendto(sd, buf, err, 0, cli_addr, cli_addr_size);
			if (err < 0) {
				perror("send");
				print_error("failed to sent to AF_KTLS on server");
				goto ktls_loop_end;
			}
		}
	}

ktls_loop_end:
	if (tls_init)
		ktls_socket_destruct(session, sd, false, false);
	return err < 0 ? err : 0;
}

// TODO: use anoncred
static int dtls_run_server(struct server_opts *opts) {
	int listen_sd = 0;
	int sock, ret;
	struct sockaddr_in sa_serv;
	struct sockaddr_in cli_addr;
	socklen_t cli_addr_size;
	gnutls_session_t session;
	char buffer[opts->mtu];
	priv_data_st priv;
	gnutls_datum_t cookie_key;
	gnutls_dtls_prestate_st prestate;

	gnutls_global_init();

	if (opts->verbose_level >= VERBOSE_LEVEL_GNUTLS) {
		gnutls_global_set_log_level(9999);
		gnutls_global_set_log_function(gnutls_log);
	}

	gnutls_certificate_allocate_credentials(&x509_cred);
	//gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE,
	//				       GNUTLS_X509_FMT_PEM);
	//gnutls_certificate_set_x509_crl_file(x509_cred, CRLFILE,
	//				     GNUTLS_X509_FMT_PEM);

	ret = gnutls_certificate_set_x509_key_file(x509_cred, CERTFILE, KEYFILE,
															GNUTLS_X509_FMT_PEM);

	if (ret < 0) {
		print_error("No certificate or key were found");
		goto dtls_run_server_end;
	}

	generate_dh_params();
	gnutls_certificate_set_dh_params(x509_cred, dh_params);
	gnutls_key_generate(&cookie_key, GNUTLS_COOKIE_KEY_SIZE);

	listen_sd = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(opts->port);

	{
		/* DTLS requires the IP don't fragment (DF) bit to be set */
#if defined(IP_DONTFRAG)
		int optval = 1;
		setsockopt(listen_sd, IPPROTO_IP, IP_DONTFRAG, (const void *) &optval, sizeof(optval));
#elif defined(IP_MTU_DISCOVER)
		int optval = IP_PMTUDISC_DO;
		setsockopt(listen_sd, IPPROTO_IP, IP_MTU_DISCOVER,
			   (const void *) &optval, sizeof(optval));
#endif
	}

	bind(listen_sd, (struct sockaddr *) &sa_serv, sizeof(sa_serv));

	if (opts->verbose_level >= VERBOSE_LEVEL_SERVER)
		print_info("UDP server ready. Listening to port '%d'!", opts->port);

	if (opts->condition_initialized) {
		if (opts->port_mem)
			// TODO: get actual port
			*opts->port_mem = opts->port;
		pthread_cond_broadcast(opts->condition_initialized);
	}

	for (;;) {
		print_debug_server(opts, "Waiting for connection...");
		sock = dtls_wait_for_connection(listen_sd);
		if (sock < 0)
			continue;

		cli_addr_size = sizeof(cli_addr);
		ret = recvfrom(sock, buffer, sizeof(buffer), MSG_PEEK,
			       (struct sockaddr *) &cli_addr,
			       &cli_addr_size);
		if (ret > 0) {
			if (opts->verbose_level >= VERBOSE_LEVEL_PACKETS) {
				print_info("received:");
				print_hex(buffer, ret);
			}
			memset(&prestate, 0, sizeof(prestate));
			ret =
			    gnutls_dtls_cookie_verify(&cookie_key,
						      &cli_addr,
						      sizeof(cli_addr),
						      buffer, ret,
						      &prestate);
			if (ret < 0) {  /* cookie not valid */
				priv_data_st s;

				memset(&s, 0, sizeof(s));
				s.fd = sock;
				s.cli_addr = (void *) &cli_addr;
				s.cli_addr_size = sizeof(cli_addr);

				//printf
				//    ("Sending hello verify request to %s",
				//     human_addr((struct sockaddr *)
				//		&cli_addr,
				//		sizeof(cli_addr), buffer,
				//		sizeof(buffer)));

				gnutls_dtls_cookie_send(&cookie_key,
							&cli_addr,
							sizeof(cli_addr),
							&prestate,
							(gnutls_transport_ptr_t)
							& s, dtls_push_func);

				/* discard peeked data */
				recvfrom(sock, buffer, sizeof(buffer), 0,
					 (struct sockaddr *) &cli_addr,
					 &cli_addr_size);
				usleep(100);
				continue;
			}
			//print_info("Accepted connection from %s",
			//       human_addr((struct sockaddr *)
			//		  &cli_addr, sizeof(cli_addr),
			//		  buffer, sizeof(buffer)));
		} else
			continue;

		gnutls_init(&session, GNUTLS_SERVER | GNUTLS_DATAGRAM);
		gnutls_set_default_priority(session);
		/* if more fine-graned control is required */

		//ret = gnutls_priority_set_direct(session,
		//			   "NORMAL:+ANON-ECDH:+ANON-DH",
		//			   NULL);
		ret = gnutls_priority_set_direct(session,
						 "NORMAL", NULL);
		if (ret < 0) {
			if (ret == GNUTLS_E_INVALID_REQUEST) {
				print_error("Syntax error at: %d", ret);
			}
			exit(1);
		}

		gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
				       x509_cred);

		gnutls_dtls_prestate_set(session, &prestate);
		gnutls_dtls_set_mtu(session, SERVER_MAX_MTU);

		priv.session = session;
		priv.fd = sock;
		priv.cli_addr = (struct sockaddr *) &cli_addr;
		priv.cli_addr_size = sizeof(cli_addr);

		gnutls_transport_set_ptr(session, &priv);
		gnutls_transport_set_push_function(session, dtls_push_func);
		gnutls_transport_set_pull_function(session, dtls_pull_func);
		gnutls_transport_set_pull_timeout_function(session, dtls_pull_timeout_func);

		do {
			ret = gnutls_handshake(session);
		}
		while (ret == GNUTLS_E_INTERRUPTED
		       || ret == GNUTLS_E_AGAIN);
		/* Note that DTLS may also receive GNUTLS_E_LARGE_PACKET.
		 * In that case the MTU should be adjusted.
		 */

		if (ret < 0) {
			print_error("Error in handshake(): %s",
				gnutls_strerror(ret));
			gnutls_deinit(session);
			continue;
		}

		if (opts->verbose_level >= VERBOSE_LEVEL_PACKETS)
			print_info("Handshake was completed");

		if (opts->ktls) {
			server_ktls_loop(opts, session, sock, (struct sockaddr *)&cli_addr, sizeof(cli_addr), buffer);
		} else {
			server_gnutls_loop(opts, session, buffer, sock);
		}

		gnutls_bye(session, GNUTLS_SHUT_WR);
		gnutls_deinit(session);
	}

	ret = 0;

dtls_run_server_end:
	if (listen_sd);
		close(listen_sd);

	gnutls_certificate_free_credentials(x509_cred);

	gnutls_global_deinit();

	return ret;
}

static int dtls_wait_for_connection(int fd) {
	fd_set rd, wr;
	int n;

	FD_ZERO(&rd);
	FD_ZERO(&wr);

	FD_SET(fd, &rd);

	/* waiting part */
	n = select(fd + 1, &rd, &wr, NULL, NULL);
	if (n == -1 && errno == EINTR)
		return -1;

	if (n < 0) {
		perror("select()");
		exit(1);
	}

	return fd;
}

/* Wait for data to be received within a timeout period in milliseconds
 */
static int dtls_pull_timeout_func(gnutls_transport_ptr_t ptr, unsigned int ms) {
	fd_set rfds;
	struct timeval tv;
	priv_data_st *priv = ptr;
	struct sockaddr_in cli_addr;
	socklen_t cli_addr_size;
	int ret;
	char c;

	FD_ZERO(&rfds);
	FD_SET(priv->fd, &rfds);

	tv.tv_sec = 0;
	tv.tv_usec = ms * 1000;

	while (tv.tv_usec >= 1000000) {
		tv.tv_usec -= 1000000;
		tv.tv_sec++;
	}

	ret = select(priv->fd + 1, &rfds, NULL, NULL, &tv);

	if (ret <= 0)
		return ret;

	/* only report ok if the next message is from the peer we expect from */
	cli_addr_size = sizeof(cli_addr);
	ret = recvfrom(priv->fd, &c, 1, MSG_PEEK,
			(struct sockaddr *) &cli_addr, &cli_addr_size);
	if (ret > 0) {
		if (cli_addr_size == priv->cli_addr_size &&
				memcmp(&cli_addr, priv->cli_addr, sizeof(cli_addr)) == 0)
		return 1;
	}

	return 0;
}

static ssize_t dtls_push_func(gnutls_transport_ptr_t p, const void *data, size_t size) {
	priv_data_st *priv = p;

#if 0
	// this can occour missplaced in output, but who cares?, if you, patch it!
	print_info("push (%lu (%lu))", size, size);
	print_hex(data, size);
#endif

	return sendto(priv->fd, data, size, 0, priv->cli_addr, priv->cli_addr_size);
}

static ssize_t dtls_pull_func(gnutls_transport_ptr_t p, void *data, size_t size) {
	priv_data_st *priv = p;
	struct sockaddr_in cli_addr;
	socklen_t cli_addr_size;
	char buffer[64];
	int ret;

	cli_addr_size = sizeof(cli_addr);
	ret = recvfrom(priv->fd, data, size, 0,
	     (struct sockaddr *) &cli_addr, &cli_addr_size);

#if 0
	if (ret > 0) {
		// this can occour missplaced in output, but who cares?, if you, patch it!
		print_info("pull (%d):", ret);
		print_hex(data, ret);
	}
#endif

	if (ret == -1)
		return ret;

	if (cli_addr_size == priv->cli_addr_size &&
			memcmp(&cli_addr, priv->cli_addr, sizeof(cli_addr)) == 0)
		return ret;

	print_warning("Denied connection from %s", human_addr((struct sockaddr *)
				&cli_addr, sizeof(cli_addr), buffer, sizeof(buffer)));

	gnutls_transport_set_errno(priv->session, EAGAIN);
	return -1;
}

static const char *human_addr(const struct sockaddr *sa, socklen_t salen,
		char *buf, size_t buflen) {
	const char *save_buf = buf;
	size_t l;

	if (!buf || !buflen)
		return NULL;

	*buf = '\0';

	switch (sa->sa_family) {
#if HAVE_IPV6
		case AF_INET6:
			snprintf(buf, buflen, "IPv6 ");
			break;
#endif
		case AF_INET:
			snprintf(buf, buflen, "IPv4 ");
			break;
	}

	l = strlen(buf);
	buf += l;
	buflen -= l;

	if (getnameinfo(sa, salen, buf, buflen, NULL, 0, NI_NUMERICHOST) != 0)
		return NULL;

	l = strlen(buf);
	buf += l;
	buflen -= l;

	strncat(buf, " port ", buflen);

	l = strlen(buf);
	buf += l;
	buflen -= l;

	if (getnameinfo(sa, salen, NULL, 0, buf, buflen, NI_NUMERICSERV) != 0)
		return NULL;

	return save_buf;
}

static int generate_dh_params(void) {
	int bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, GNUTLS_SEC_PARAM_LEGACY);

	/* Generate Diffie-Hellman parameters - for use with DHE
	 * kx algorithms. When short bit length is used, it might
	 * be wise to regenerate parameters often.
	 */
	gnutls_dh_params_init(&dh_params);
	gnutls_dh_params_generate2(dh_params, bits);

	return 0;
}

static int tls_run_server(struct server_opts *opts) {
	int err, listen_sd;
	int sd, ret;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	socklen_t client_len;
	char topbuf[512];
	gnutls_session_t session;
	gnutls_anon_server_credentials_t anoncred;
	char buffer[opts->mtu + 1];
	int optval = 1;

	// TODO: review printing

	if (gnutls_check_version("3.1.4") == NULL) {
		print_error("GnuTLS 3.1.4 or later is required for this example\n");
		return -1;
	}

	/* for backwards compatibility with gnutls < 3.3.0 */
	gnutls_global_init();
	gnutls_anon_allocate_server_credentials(&anoncred);
	generate_dh_params();
	gnutls_anon_set_server_dh_params(anoncred, dh_params);

	/* Socket operations
	 */
	listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	SOCKET_ERR(listen_sd, "socket");

	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(opts->port); /* Server Port number */

	setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (void *) &optval, sizeof(int));

	err = bind(listen_sd, (struct sockaddr *) &sa_serv, sizeof(sa_serv));
	SOCKET_ERR(err, "bind");
	err = listen(listen_sd, 1024);
	SOCKET_ERR(err, "listen");

	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	err = getsockname(listen_sd, (struct sockaddr *)&sin, &len);
	SOCKET_ERR(err, "getsockname")
	print_info("Server ready. Listening to port '%d'.", ntohs(sin.sin_port));

	if (opts->condition_initialized) {
		if (opts->port_mem)
			// TODO: get actual port
			*opts->port_mem = opts->port;
		pthread_cond_broadcast(opts->condition_initialized);
	}

	client_len = sizeof(sa_cli);
	for (;;) {
		gnutls_init(&session, GNUTLS_SERVER);
		gnutls_priority_set_direct(session, "NORMAL:+ANON-DH:+AES-128-GCM", NULL);
		gnutls_credentials_set(session, GNUTLS_CRD_ANON, anoncred);

		sd = accept(listen_sd, (struct sockaddr *) &sa_cli, &client_len);

		print_info("- connection from %s, port %d", inet_ntop(AF_INET, &sa_cli.sin_addr, topbuf,
					sizeof(topbuf)), ntohs(sa_cli.sin_port));

		gnutls_transport_set_int(session, sd);

		do {
			ret = gnutls_handshake(session);
		} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

		if (ret < 0) {
			close(sd);
			gnutls_deinit(session);
			print_error("*** Handshake has failed (%s)", gnutls_strerror(ret));
			continue;
		}
		print_info("- Handshake was completed");

		/* see the Getting peer's information example */
		/* print_info(session); */

		if (opts->ktls) {
			server_ktls_loop(opts, session, sd, (struct sockaddr *)&sa_cli, sizeof(sa_cli), buffer);
		} else {
			server_gnutls_loop(opts, session, buffer, sd);
		}

		/* do not wait for the peer to close the connection.
		 */
		gnutls_bye(session, GNUTLS_SHUT_WR);

		close(sd);
		gnutls_deinit(session);

	}

	close(listen_sd);
	gnutls_anon_free_server_credentials(anoncred);
	gnutls_global_deinit();

	return 0;
}

extern void *run_server(void *arg) {
	int ret;
	struct server_opts *opts = (struct server_opts *) arg;

	if (opts->no_tls) {
		if (opts->tcp) {
			ret = plain_tcp_server(opts);
		} else {
			ret = plain_udp_server(opts);
		}
	} else {
		if (opts->tls) {
			ret = tls_run_server(opts);
		} else {
			ret = dtls_run_server(opts);
		}
	}

	server_err = ret;

	return NULL;
}

