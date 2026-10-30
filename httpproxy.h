#ifndef HTTPPROXY_H
#define HTTPPROXY_H

#include <stddef.h>

struct client;

struct http_proxy_config {
	int timeout;
	/* NULL credentials mean no usable Proxy-Authorization was supplied. */
	int (*authorize)(struct client *, const unsigned char *, size_t);
	/* Returns a connected fd, or a negative HTTP error status. */
	int (*connect_target)(struct client *, const char *, unsigned short);
	void (*tunnel)(int, int);
};

/* Serves requests without closing client->fd; the caller owns that fd. */
void http_proxy_serve(struct client *, const struct http_proxy_config *);

#endif
