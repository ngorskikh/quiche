// Copyright (C) 2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#include <sys/types.h>
#include <netinet/in.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <ev.h>

#include <quiche.h>

#define LOCAL_CONN_ID_LEN 16

#define MAX_DATAGRAM_SIZE 1350

struct conn_io {
    ev_timer timer;
    const char *target_host;
    int sock;
    quiche_conn *conn;
    quiche_h3_conn *http3;
    ev_io stdin_watcher;
    int64_t stream_id;
};

static void debug_log(const char *line, void *argp) {
    fprintf(stderr, "%s\n", line);
}

static void flush_egress(struct ev_loop *loop, struct conn_io *conn_io) {
    static uint8_t out[MAX_DATAGRAM_SIZE];

    while (1) {
        ssize_t written = quiche_conn_send(conn_io->conn, out, sizeof(out));

        if (written == QUICHE_ERR_DONE) {
            fprintf(stderr, "done writing\n");
            break;
        }

        if (written < 0) {
            fprintf(stderr, "failed to create packet: %zd\n", written);
            return;
        }

        ssize_t sent = send(conn_io->sock, out, written, 0);
        if (sent != written) {
            perror("failed to send");
            return;
        }

        fprintf(stderr, "sent %zd bytes\n", sent);
    }

    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
    conn_io->timer.repeat = t;
    ev_timer_again(loop, &conn_io->timer);
}

static int for_each_header(uint8_t *name, size_t name_len,
                           uint8_t *value, size_t value_len,
                           void *argp) {
    fprintf(stderr, "got HTTP header: %.*s=%.*s\n",
            (int) name_len, name, (int) value_len, value);

    return 0;
}

static void stdin_cb(EV_P_ ev_io *w, int revents) {
    struct conn_io *conn_io = w->data;
    uint8_t buf[4096];
    int r = read(STDIN_FILENO, buf, sizeof(buf));
    if (r < 0) {
        perror("failed to read from stdin");
    }
    bool fin = (r == 0);
    int qr = quiche_h3_send_body(conn_io->http3, conn_io->conn, conn_io->stream_id,
                                 buf, r, fin);
    if (qr != r) {
        fprintf(stderr, "quiche_h3_send_body: %d", qr);
    }
    flush_egress(loop, conn_io);
}

static void recv_cb(EV_P_ ev_io *w, int revents) {
    static bool req_sent = false;

    struct conn_io *conn_io = w->data;

    static uint8_t buf[65535];

    while (1) {
        ssize_t read = recv(conn_io->sock, buf, sizeof(buf), 0);

        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                fprintf(stderr, "recv would block\n");
                break;
            }

            perror("failed to read");
            return;
        }

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read);

        if (done < 0) {
            fprintf(stderr, "failed to process packet: %zd\n", done);
            continue;
        }

        fprintf(stderr, "recv %zd bytes\n", done);
    }

    fprintf(stderr, "done reading\n");

    if (quiche_conn_is_closed(conn_io->conn)) {
        fprintf(stderr, "connection closed\n");

        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }

    if (quiche_conn_is_established(conn_io->conn) && !req_sent) {
        const uint8_t *app_proto;
        size_t app_proto_len;

        quiche_conn_application_proto(conn_io->conn, &app_proto, &app_proto_len);

        fprintf(stderr, "connection established: %.*s\n",
                (int) app_proto_len, app_proto);

        quiche_h3_config *config = quiche_h3_config_new();
        if (config == NULL) {
            fprintf(stderr, "failed to create HTTP/3 config\n");
            return;
        }

        conn_io->http3 = quiche_h3_conn_new_with_transport(conn_io->conn, config);
        if (conn_io->http3 == NULL) {
            fprintf(stderr, "failed to create HTTP/3 connection\n");
            return;
        }

        quiche_h3_config_free(config);

#define CNT(arr_) (sizeof(arr_) / sizeof((arr_)[0]) )
#define MHDR(name_, value_) { .name = (uint8_t *) (name_), .name_len = strlen(name_), \
                              .value = (uint8_t *) (value_), .value_len = strlen(value_), }

        quiche_h3_header headers[] = {
            MHDR(":method", "CONNECT"),
            MHDR(":authority", conn_io->target_host),
            MHDR("user-agent", "quiche"),
        };

        conn_io->stream_id = quiche_h3_send_request(conn_io->http3, conn_io->conn,
                                                    headers, CNT(headers), false);

        fprintf(stderr, "sent HTTP request %" PRId64 "\n", conn_io->stream_id);

        req_sent = true;
    }

    if (quiche_conn_is_established(conn_io->conn)) {
        quiche_h3_event *ev;

        while (1) {
            int64_t s = quiche_h3_conn_poll(conn_io->http3,
                                            conn_io->conn,
                                            &ev);

            if (s < 0) {
                break;
            }

            switch (quiche_h3_event_type(ev)) {
                case QUICHE_H3_EVENT_HEADERS: {
                    int rc = quiche_h3_event_for_each_header(ev, for_each_header,
                                                             NULL);

                    if (rc != 0) {
                        fprintf(stderr, "failed to process headers");
                    }

                    ev_io_init(&conn_io->stdin_watcher, stdin_cb, STDIN_FILENO, EV_READ);
                    ev_io_start(loop, &conn_io->stdin_watcher);
                    conn_io->stdin_watcher.data = conn_io;

                    break;
                }

                case QUICHE_H3_EVENT_DATA: {
                    ssize_t len = quiche_h3_recv_body(conn_io->http3,
                                                      conn_io->conn, s,
                                                      buf, sizeof(buf));
                    if (len <= 0) {
                        break;
                    }

                    printf("got HTTP data: %.*s", (int) len, buf);
                    break;
                }

                case QUICHE_H3_EVENT_FINISHED:
                    if (quiche_conn_close(conn_io->conn, true, 0, NULL, 0) < 0) {
                        fprintf(stderr, "failed to close connection\n");
                    }
                    break;

                case QUICHE_H3_EVENT_DATAGRAM:
                    break;
                    
                case QUICHE_H3_EVENT_GOAWAY: {
                    fprintf(stderr, "got GOAWAY\n");
                    break;
                }
            }

            quiche_h3_event_free(ev);
        }
    }

    flush_egress(loop, conn_io);
}

static void timeout_cb(EV_P_ ev_timer *w, int revents) {
    struct conn_io *conn_io = w->data;
    quiche_conn_on_timeout(conn_io->conn);

    fprintf(stderr, "timeout\n");

    flush_egress(loop, conn_io);

    if (quiche_conn_is_closed(conn_io->conn)) {
        quiche_stats stats;

        quiche_conn_stats(conn_io->conn, &stats);

        fprintf(stderr, "connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns\n",
                stats.recv, stats.sent, stats.lost, stats.rtt);

        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("usage: %s <host> <port> <CONNECT authority>", argv[0]);
        return 0;
    }
    const char *host = argv[1];
    const char *port = argv[2];
    const char *target_host = argv[3];

    const struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP
    };

    quiche_enable_debug_logging(debug_log, NULL);

    struct addrinfo *peer;
    if (getaddrinfo(host, port, &hints, &peer) != 0) {
        perror("failed to resolve host");
        return -1;
    }

    int sock = socket(peer->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("failed to create socket");
        return -1;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        perror("failed to make socket non-blocking");
        return -1;
    }

    if (connect(sock, peer->ai_addr, peer->ai_addrlen) < 0) {
        perror("failed to connect socket");
        return -1;
    }

    quiche_config *config = quiche_config_new(0xbabababa);
    if (config == NULL) {
        fprintf(stderr, "failed to create config\n");
        return -1;
    }

    quiche_config_set_application_protos(config,
        (uint8_t *) QUICHE_H3_APPLICATION_PROTOCOL,
        sizeof(QUICHE_H3_APPLICATION_PROTOCOL) - 1);

    quiche_config_set_max_idle_timeout(config, UINT32_MAX);
// master
//    quiche_config_set_max_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
//    quiche_config_set_max_send_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(config, 10000000);
    quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
    quiche_config_set_initial_max_stream_data_uni(config, 1000000);
    quiche_config_set_initial_max_streams_bidi(config, 100);
    quiche_config_set_initial_max_streams_uni(config, 100);
    quiche_config_set_disable_active_migration(config, true);

    if (getenv("SSLKEYLOGFILE")) {
      quiche_config_log_keys(config);
    }

    // ABC: old config creation here

    uint8_t scid[LOCAL_CONN_ID_LEN];
    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        perror("failed to open /dev/urandom");
        return -1;
    }

    ssize_t rand_len = read(rng, &scid, sizeof(scid));
    if (rand_len < 0) {
        perror("failed to create connection ID");
        return -1;
    }

    quiche_conn *conn = quiche_connect(host, (const uint8_t *) scid,
                                       sizeof(scid), config);
    if (conn == NULL) {
        fprintf(stderr, "failed to create connection\n");
        return -1;
    }

    struct conn_io *conn_io = malloc(sizeof(*conn_io));
    if (conn_io == NULL) {
        fprintf(stderr, "failed to allocate connection IO\n");
        return -1;
    }

    conn_io->sock = sock;
    conn_io->conn = conn;
    conn_io->target_host = target_host;

    ev_io watcher;

    struct ev_loop *loop = ev_default_loop(0);

    ev_io_init(&watcher, recv_cb, conn_io->sock, EV_READ);
    ev_io_start(loop, &watcher);
    watcher.data = conn_io;

    ev_init(&conn_io->timer, timeout_cb);
    conn_io->timer.data = conn_io;

    flush_egress(loop, conn_io);

    ev_loop(loop, 0);

    freeaddrinfo(peer);

    quiche_h3_conn_free(conn_io->http3);

    quiche_conn_free(conn);

    quiche_config_free(config);

    return 0;
}
