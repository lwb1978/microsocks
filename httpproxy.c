/* HTTP/1.x forward proxy. Configuration and routing belong to sockssrv.c. */
#define _POSIX_C_SOURCE 200809L
#include "server.h"
#include "httpproxy.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define HEADER_LIMIT (16 * 1024)
#define FIELD_LIMIT 128
#define IO_SIZE 4096
#define EARLY_RESPONSE -3

struct http_context;
struct stream {
	int fd, timeout;
	size_t pos, end;
	unsigned char data[IO_SIZE];
	struct http_context *upload;
};

struct field { char *name, *value; };
struct message {
	char data[HEADER_LIMIT];
	struct field fields[FIELD_LIMIT];
	size_t count;
	char *first, *target, *reason, *host, *authorization, *expect;
	int minor, status, has_length, chunked, close, upgrade;
	uint64_t length;
};

struct http_context {
	struct stream client, remote;
	struct message request, response;
	char output[HEADER_LIMIT + 1024];
	char host[256], connected_host[256];
	unsigned short port, connected_port;
	char *path;
	int prefix_slash, head, connect, keep, early, sent_continue;
	unsigned informational;
	const struct http_proxy_config *config;
};

static int early_response(struct http_context *);

static int poll_timeout(int seconds) {
	return seconds > 0 ? (seconds > INT_MAX/1000 ? INT_MAX : seconds*1000) : -1;
}

/* Uploads watch the origin as well, so an early final response can interrupt
   a client that is still sending its request body. */
static int wait_io(int fd, short events, int timeout, struct http_context *upload) {
	for(;;) {
		struct pollfd fds[2] = {{.fd = fd, .events = events}};
		if(upload) {
			fds[1].fd = upload->remote.fd;
			fds[1].events = POLLIN;
			while(upload->remote.pos < upload->remote.end) {
				int r = early_response(upload);
				if(r) return r;
			}
		}
		int r = poll(fds, upload ? 2 : 1, poll_timeout(timeout));
		if(r < 0 && errno == EINTR) continue;
		if(r <= 0) {
			if(!r) errno = ETIMEDOUT;
			return -1;
		}
		if(upload && fds[1].revents) {
			r = early_response(upload);
			if(r) return r;
		}
		if(fds[0].revents) return 0;
	}
}

static int write_all(int fd, const void *data, size_t len, int timeout,
		struct http_context *upload) {
	const unsigned char *p = data;
	while(len) {
		int r = wait_io(fd, POLLOUT, timeout, upload);
		if(r) return r;
		ssize_t n = write(fd, p, len);
		if(n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
		if(n <= 0) return -1;
		p += n;
		len -= n;
	}
	return 0;
}

static int fill(struct stream *s) {
	if(s->pos < s->end) return 1;
	for(;;) {
		int r = wait_io(s->fd, POLLIN, s->timeout, s->upload);
		if(r) return r;
		ssize_t n = read(s->fd, s->data, sizeof s->data);
		if(n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
		if(n < 0) return -1;
		s->pos = 0;
		s->end = n;
		return n ? 1 : 0;
	}
}

/* Returns 1 for a CRLF-terminated line, 0 for clean EOF, -2 for overlong input. */
static int read_line(struct stream *s, char *line, size_t cap, size_t *length) {
	size_t len = 0;
	for(;;) {
		int r = fill(s);
		if(r <= 0) return r ? r : len ? -1 : 0;
		unsigned char c = s->data[s->pos++];
		if(c == '\n') {
			if(!len || line[len-1] != '\r') return -1;
			line[--len] = 0;
			*length = len;
			return 1;
		}
		if(!c || (c < 32 && c != '\r' && c != '\t') || c == 127) return -1;
		if(len && line[len-1] == '\r') return -1;
		if(len + 1 >= cap) return -2;
		line[len++] = c;
	}
}

static int token_char(unsigned char c) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || (c && strchr("!#$%&'*+-.^_`|~", c));
}

static int split_field(char *line, struct field *f) {
	char *p = line;
	while(token_char(*p)) ++p;
	if(p == line || *p != ':') return -1;
	*p++ = 0;
	f->name = line;
	while(*p == ' ' || *p == '\t') ++p;
	f->value = p;
	p += strlen(p);
	while(p > f->value && (p[-1] == ' ' || p[-1] == '\t')) *--p = 0;
	return 0;
}

static int number(const char *p, unsigned base, uint64_t *out) {
	uint64_t n = 0;
	if(!*p) return -1;
	for(; *p; ++p) {
		unsigned v;
		if(*p >= '0' && *p <= '9') v = *p - '0';
		else if(*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
		else if(*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
		else return -1;
		if(v >= base || n > (UINT64_MAX - v)/base) return -1;
		n = n*base + v;
	}
	*out = n;
	return 0;
}

/* Validates a comma-separated token list, optionally looking for one token. */
static int has_token(const char *p, const char *name) {
	int found = 0;
	for(;;) {
		while(*p == ' ' || *p == '\t') ++p;
		const char *start = p;
		while(token_char(*p)) ++p;
		if(p == start) return -1;
		if(name && strlen(name) == (size_t)(p-start) && !strncasecmp(start, name, p-start))
			found = 1;
		while(*p == ' ' || *p == '\t') ++p;
		if(!*p) return found;
		if(*p++ != ',') return -1;
	}
}

static int connection_token(const struct message *m, const char *name) {
	size_t i;
	for(i=0; i<m->count; ++i)
		if(!strcasecmp(m->fields[i].name, "Connection") &&
		   has_token(m->fields[i].value, name) == 1) return 1;
	return 0;
}

static int hop_field(const struct message *m, const char *name) {
	static const char *const names[] = {"Connection", "Proxy-Connection", "Keep-Alive",
		"Proxy-Authorization", "Proxy-Authenticate", "TE", "Trailer", "Upgrade"};
	size_t i;
	for(i=0; i<sizeof names/sizeof names[0]; ++i)
		if(!strcasecmp(name, names[i])) return 1;
	return connection_token(m, name);
}

static int read_message(struct stream *in, struct message *m) {
	char *line = m->data;
	size_t len, used;
	memset(m, 0, sizeof *m);
	errno = 0;
	int r = read_line(in, line, sizeof m->data, &len);
	if(r <= 0) return r;
	m->first = line;
	used = len + 1;
	for(;;) {
		line = m->data + used;
		r = read_line(in, line, sizeof m->data - used, &len);
		if(r != 1) return r == -2 ? -2 : -1;
		if(!len) return 1;
		if(m->count == FIELD_LIMIT) return -2;
		if(split_field(line, &m->fields[m->count++])) return -1;
		used += len + 1;
	}
}

static int analyse_fields(struct message *m) {
	size_t i;
	for(i=0; i<m->count; ++i) {
		const char *name = m->fields[i].name;
		char *value = m->fields[i].value;
		if(!strcasecmp(name, "Host")) {
			if(m->host) return -1;
			m->host = value;
		} else if(!strcasecmp(name, "Proxy-Authorization")) {
			if(m->authorization) return -1;
			m->authorization = value;
		} else if(!strcasecmp(name, "Content-Length")) {
			if(m->has_length || number(value, 10, &m->length)) return -1;
			m->has_length = 1;
		} else if(!strcasecmp(name, "Transfer-Encoding")) {
			if(m->chunked || strcasecmp(value, "chunked")) return -1;
			m->chunked = 1;
		} else if(!strcasecmp(name, "Expect")) {
			if(m->expect) return -1;
			m->expect = value;
		} else if(!strcasecmp(name, "Connection") || !strcasecmp(name, "Proxy-Connection")) {
			if(has_token(value, NULL) < 0) return -1;
			if(has_token(value, "close") == 1) m->close = 1;
		} else if(!strcasecmp(name, "Upgrade")) m->upgrade = 1;
	}
	if(m->has_length && m->chunked) return -1;
	if(connection_token(m, "Host") || connection_token(m, "Content-Length") ||
	   connection_token(m, "Transfer-Encoding")) return -1;
	return 0;
}

static int parse_version(const char *p) {
	return !strcmp(p, "HTTP/1.1") ? 1 : !strcmp(p, "HTTP/1.0") ? 0 : -1;
}

static int authority(const char *text, size_t len, char *host, unsigned short *port, int fallback) {
	const char *end = text + len, *host_end, *port_text = NULL;
	unsigned char address[16];
	if(!len) return -1;
	int bracketed = *text == '[';
	if(bracketed) {
		++text;
		host_end = memchr(text, ']', end-text);
		if(!host_end) return -1;
		if(host_end + 1 != end) {
			if(host_end[1] != ':') return -1;
			port_text = host_end + 2;
		}
	} else {
		host_end = memchr(text, ':', len);
		if(host_end) port_text = host_end + 1;
		else host_end = end;
	}
	size_t host_len = host_end - text;
	if(!host_len || host_len > 255) return -1;
	memcpy(host, text, host_len);
	host[host_len] = 0;
	if(bracketed) {
		if(inet_pton(AF_INET6, host, address) != 1) return -1;
	} else {
		size_t i;
		for(i=0; i<host_len; ++i)
			if((unsigned char)host[i] <= 32 || (unsigned char)host[i] >= 127 ||
			   strchr("/\\?#@,[]:", host[i])) return -1;
	}
	unsigned value = fallback;
	if(port_text) {
		if(port_text == end) return -1;
		value = 0;
		while(port_text < end) {
			if(*port_text < '0' || *port_text > '9') return -1;
			value = value*10 + (*port_text++ - '0');
			if(value > 65535) return -1;
		}
	}
	if(!value) return -1;
	*port = value;
	return 0;
}

static int parse_request(struct http_context *c) {
	struct message *m = &c->request;
	char *p = strchr(m->first, ' '), *version;
	if(!p || p == m->first) return 400;
	*p++ = 0;
	for(version=m->first; *version; ++version) if(!token_char(*version)) return 400;
	m->target = p;
	if(!(version = strchr(p, ' '))) return 400;
	*version++ = 0;
	if(!*p || strchr(version, ' ') || strchr(p, '\t')) return 400;
	m->minor = parse_version(version);
	if(m->minor < 0) return 505;
	if(analyse_fields(m) || (m->minor == 1 && (!m->host || !*m->host))) return 400;
	if(m->minor == 0 && m->chunked) return 400;
	c->head = !strcmp(m->first, "HEAD");
	c->connect = !strcmp(m->first, "CONNECT");
	c->keep = m->minor == 1 && !m->close;
	c->prefix_slash = 0;
	if(m->upgrade || connection_token(m, "upgrade")) return 501;
	if(m->expect && strcasecmp(m->expect, "100-continue")) return 417;
	if(c->connect) {
		if(m->chunked || (m->has_length && m->length) || m->expect) return 400;
		return authority(p, strlen(p), c->host, &c->port, 0) ? 400 : 0;
	}
	if(strchr(p, '#') || strchr(p, '\\')) return 400;
	if(!strncasecmp(p, "http://", 7)) {
		p += 7;
		char *end = p + strcspn(p, "/?");
		if(authority(p, end-p, c->host, &c->port, 80)) return 400;
		c->path = *end ? end : "/";
		c->prefix_slash = *end == '?';
	} else if(*p == '/' || (!strcmp(p, "*") && !strcmp(m->first, "OPTIONS"))) {
		if(!m->host || authority(m->host, strlen(m->host), c->host, &c->port, 80)) return 400;
		c->path = p;
	} else return 400;
	for(p=c->path; *p; ++p) if((unsigned char)*p <= 32 || (unsigned char)*p == 127) return 400;
	return 0;
}

static int parse_response(struct message *m) {
	char *p = strchr(m->first, ' ');
	if(!p) return -1;
	*p++ = 0;
	m->minor = parse_version(m->first);
	if(m->minor < 0 || strlen(p) < 3 || p[0] < '1' || p[0] > '5' ||
	   p[1] < '0' || p[1] > '9' || p[2] < '0' || p[2] > '9' ||
	   (p[3] && p[3] != ' ')) return -1;
	m->status = (p[0]-'0')*100 + (p[1]-'0')*10 + p[2]-'0';
	m->reason = p[3] ? p + 4 : "";
	if(analyse_fields(m) || m->status == 101 || (m->minor == 0 && m->chunked) ||
	   ((m->status < 200 || m->status == 204) && (m->has_length || m->chunked))) return -1;
	if(m->minor == 0) m->close = 1;
	return 0;
}

static int base64_value(unsigned char c) {
	if(c >= 'A' && c <= 'Z') return c-'A';
	if(c >= 'a' && c <= 'z') return c-'a'+26;
	if(c >= '0' && c <= '9') return c-'0'+52;
	return c == '+' ? 62 : c == '/' ? 63 : -1;
}

static int authorized(struct http_context *c, struct client *client) {
	unsigned char decoded[513];
	const char *p = c->request.authorization;
	size_t len = 0;
	if(!p || strncasecmp(p, "Basic ", 6))
		return c->config->authorize(client, NULL, 0);
	p += 6;
	while(*p == ' ' || *p == '\t') ++p;
	size_t encoded = strlen(p), i;
	if(!encoded || encoded%4 || encoded/4*3 > sizeof decoded)
		return c->config->authorize(client, NULL, 0);
	for(i=0; i<encoded; i+=4) {
		int a = base64_value(p[i]), b = base64_value(p[i+1]);
		int x = p[i+2] == '=' ? 0 : base64_value(p[i+2]);
		int y = p[i+3] == '=' ? 0 : base64_value(p[i+3]);
		if(a < 0 || b < 0 || x < 0 || y < 0 ||
		   (p[i+2] == '=' && (p[i+3] != '=' || (b & 15))) ||
		   (p[i+3] == '=' && p[i+2] != '=' && (x & 3)) ||
		   ((p[i+2] == '=' || p[i+3] == '=') && i+4 != encoded))
			return c->config->authorize(client, NULL, 0);
		decoded[len++] = (a << 2) | (b >> 4);
		if(p[i+2] != '=') decoded[len++] = (b << 4) | (x >> 2);
		if(p[i+3] != '=') decoded[len++] = (x << 6) | y;
	}
	return c->config->authorize(client, decoded, len);
}

static int append(struct http_context *c, size_t *used, const char *text) {
	size_t len = strlen(text);
	if(len > sizeof c->output - *used) return -1;
	memcpy(c->output + *used, text, len);
	*used += len;
	return 0;
}

static int send_headers(struct http_context *c, const struct message *m, int request) {
	size_t used = 0, i;
	char text[320];
	if(request) {
		if(append(c, &used, m->first) || append(c, &used, " ") ||
		   (c->prefix_slash && append(c, &used, "/")) ||
		   append(c, &used, c->path) || append(c, &used, " HTTP/1.1\r\nHost: ")) return -1;
		snprintf(text, sizeof text, strchr(c->host, ':') ? "[%s]:%u\r\n" : "%s:%u\r\n", c->host, c->port);
		if(append(c, &used, text)) return -1;
	} else {
		snprintf(text, sizeof text, "HTTP/1.%d %d ", c->request.minor, m->status);
		if(append(c, &used, text) || append(c, &used, m->reason) || append(c, &used, "\r\n")) return -1;
	}
	for(i=0; i<m->count; ++i) {
		const struct field *f = &m->fields[i];
		if(hop_field(m, f->name) || !strcasecmp(f->name, "Content-Length") ||
		   !strcasecmp(f->name, "Transfer-Encoding") ||
		   (request && (!strcasecmp(f->name, "Host") || !strcasecmp(f->name, "Expect")))) continue;
		if(append(c, &used, f->name) || append(c, &used, ": ") ||
		   append(c, &used, f->value) || append(c, &used, "\r\n")) return -1;
	}
	if(m->has_length) {
		snprintf(text, sizeof text, "Content-Length: %" PRIu64 "\r\n", m->length);
		if(append(c, &used, text)) return -1;
	}
	if(m->chunked && (request || c->request.minor == 1))
		if(append(c, &used, "Transfer-Encoding: chunked\r\n")) return -1;
	if(!c->keep && (request || m->status >= 200))
		if(append(c, &used, "Connection: close\r\n")) return -1;
	if(append(c, &used, "Via: 1.1 microsocks\r\n\r\n")) return -1;
	return write_all(request ? c->remote.fd : c->client.fd, c->output, used, c->config->timeout, NULL);
}

static void send_error(struct http_context *c, int status) {
	const char *reason;
	switch(status) {
		case 400: reason = "Bad Request"; break;
		case 407: reason = "Proxy Authentication Required"; break;
		case 408: reason = "Request Timeout"; break;
		case 417: reason = "Expectation Failed"; break;
		case 431: reason = "Request Header Fields Too Large"; break;
		case 501: reason = "Not Implemented"; break;
		case 503: reason = "Service Unavailable"; break;
		case 504: reason = "Gateway Timeout"; break;
		case 505: reason = "HTTP Version Not Supported"; break;
		default: status = 502; reason = "Bad Gateway"; break;
	}
	char buf[256];
	int len = snprintf(buf, sizeof buf,
		"HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n%s\r\n",
		status, reason, status == 407 ? "Proxy-Authenticate: Basic realm=\"microsocks\"\r\n" : "");
	write_all(c->client.fd, buf, len, c->config->timeout, NULL);
}

static int read_response(struct http_context *c) {
	if(read_message(&c->remote, &c->response) != 1 || parse_response(&c->response)) {
		if(errno != ETIMEDOUT) errno = EPROTO;
		return -1;
	}
	return 0;
}

static int early_response(struct http_context *c) {
	if(read_response(c)) return -1;
	if(c->response.status >= 200) {
		c->early = 1;
		return EARLY_RESPONSE;
	}
	if(++c->informational > 32) return -1;
	if(c->response.status == 100 && c->sent_continue) return 0;
	return send_headers(c, &c->response, 0);
}

static int transfer_length(struct stream *in, int out, uint64_t len) {
	while(len) {
		int r = fill(in);
		if(r <= 0) {
			if(!r) errno = EINVAL;
			return r ? r : -1;
		}
		size_t n = in->end - in->pos;
		if((uint64_t)n > len) n = len;
		r = write_all(out, in->data + in->pos, n, in->timeout, in->upload);
		if(r) return r;
		in->pos += n;
		len -= n;
	}
	return 0;
}

static int chunk_extensions(const char *p) {
	while(*p) {
		if(*p++ != ';') return -1;
		while(*p == ' ' || *p == '\t') ++p;
		const char *start = p;
		while(token_char(*p)) ++p;
		if(p == start) return -1;
		while(*p == ' ' || *p == '\t') ++p;
		if(*p == '=') {
			++p;
			while(*p == ' ' || *p == '\t') ++p;
			if(*p == '"') {
				++p;
				while(*p && *p != '"') {
					if(*p == '\\' && !*++p) return -1;
					++p;
				}
				if(*p++ != '"') return -1;
			} else {
				start = p;
				while(token_char(*p)) ++p;
				if(p == start) return -1;
			}
			while(*p == ' ' || *p == '\t') ++p;
		}
	}
	return 0;
}

/* Chunks are reframed, and proxy credentials never pass through trailers.
   HTTP/1.0 clients receive a decoded, close-delimited response body. */
static int transfer_chunked(struct stream *in, int out, const struct message *m, int encode) {
	char line[1024], size_line[32];
	size_t len, trailers = 0, count = 0;
	for(;;) {
		int r = read_line(in, line, sizeof line, &len);
		if(r != 1) { if(r != EARLY_RESPONSE && errno != ETIMEDOUT) errno = EINVAL; return r == EARLY_RESPONSE ? r : -1; }
		char *ext = strchr(line, ';');
		if(ext) {
			if(chunk_extensions(ext)) { errno = EINVAL; return -1; }
			char *end = ext;
			while(end > line && (end[-1] == ' ' || end[-1] == '\t')) --end;
			*end = 0;
			*ext = 0;
		}
		uint64_t size;
		if(number(line, 16, &size)) { errno = EINVAL; return -1; }
		if(encode) {
			int n = snprintf(size_line, sizeof size_line, "%" PRIx64 "\r\n", size);
			r = write_all(out, size_line, n, in->timeout, in->upload);
			if(r) return r;
		}
		if(!size) break;
		r = transfer_length(in, out, size);
		if(r) return r;
		r = read_line(in, line, sizeof line, &len);
		if(r != 1 || len) { if(r != EARLY_RESPONSE && errno != ETIMEDOUT) errno = EINVAL; return r == EARLY_RESPONSE ? r : -1; }
		if(encode && (r = write_all(out, "\r\n", 2, in->timeout, in->upload))) return r;
	}
	for(;;) {
		int r = read_line(in, line, sizeof line, &len);
		if(r != 1) { if(r != EARLY_RESPONSE && errno != ETIMEDOUT) errno = EINVAL; return r == EARLY_RESPONSE ? r : -1; }
		trailers += len + 2;
		if(!len) break;
		struct field f;
		if(trailers > HEADER_LIMIT || ++count > FIELD_LIMIT || split_field(line, &f) ||
		   !strcasecmp(f.name, "Content-Length") || !strcasecmp(f.name, "Transfer-Encoding")) {
			errno = EINVAL;
			return -1;
		}
		if(!encode || hop_field(m, f.name) || !strcasecmp(f.name, "Host")) continue;
		if((r = write_all(out, f.name, strlen(f.name), in->timeout, in->upload)) ||
		   (r = write_all(out, ": ", 2, in->timeout, in->upload)) ||
		   (r = write_all(out, f.value, strlen(f.value), in->timeout, in->upload)) ||
		   (r = write_all(out, "\r\n", 2, in->timeout, in->upload))) return r;
	}
	return encode ? write_all(out, "\r\n", 2, in->timeout, in->upload) : 0;
}

static int transfer_to_eof(struct stream *in, int out) {
	for(;;) {
		int r = fill(in);
		if(r <= 0) return r;
		if(write_all(out, in->data + in->pos, in->end - in->pos, in->timeout, NULL)) return -1;
		in->pos = in->end;
	}
}

static int nonblocking(int fd) {
	int flags = fcntl(fd, F_GETFL);
	if(flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
	return flags;
}

static void close_remote(struct http_context *c) {
	if(c->remote.fd >= 0) close(c->remote.fd);
	c->remote.fd = -1;
	c->remote.pos = c->remote.end = 0;
}

void http_proxy_serve(struct client *client, const struct http_proxy_config *config) {
	/* Keep HTTP buffers off microsocks' deliberately small thread stacks. */
	struct http_context *c = calloc(1, sizeof *c);
	if(!c) {
		static const char unavailable[] = "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
		write_all(client->fd, unavailable, sizeof unavailable-1, config->timeout, NULL);
		return;
	}
	c->config = config;
	c->client.fd = client->fd;
	c->client.timeout = c->remote.timeout = config->timeout;
	c->remote.fd = -1;
	int client_flags = nonblocking(client->fd);
	if(client_flags < 0) goto done;
	for(;;) {
		c->early = c->sent_continue = c->informational = 0;
		int r = read_message(&c->client, &c->request);
		if(!r) break;
		if(r < 0) {
			send_error(c, errno == ETIMEDOUT ? 408 : r == -2 ? 431 : 400);
			break;
		}
		int status = parse_request(c);
		if(status || !authorized(c, client)) {
			send_error(c, status ? status : 407);
			break;
		}
		if(c->connect || c->connected_port != c->port || strcmp(c->connected_host, c->host))
			close_remote(c);
		if(c->remote.fd >= 0) {
			/* A cached connection can close while we await the next request.
			   Unsolicited bytes also make that connection unsafe to reuse. */
			struct pollfd idle = {.fd = c->remote.fd, .events = POLLIN};
			if(poll(&idle, 1, 0) > 0 && idle.revents) close_remote(c);
		}
		if(c->remote.fd < 0) {
			r = config->connect_target(client, c->host, c->port);
			if(r < 0) { send_error(c, -r); break; }
			c->remote.fd = r;
			if(nonblocking(r) < 0) { send_error(c, 502); break; }
			strcpy(c->connected_host, c->host);
			c->connected_port = c->port;
		}
		if(c->connect) {
			static const char established[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
			if(write_all(client->fd, established, sizeof established-1, config->timeout, NULL) ||
			   write_all(c->remote.fd, c->client.data + c->client.pos,
				c->client.end - c->client.pos, config->timeout, NULL)) break;
			int flags = fcntl(c->remote.fd, F_GETFL);
			if(flags >= 0 && !fcntl(c->remote.fd, F_SETFL, flags & ~O_NONBLOCK) &&
			   !fcntl(client->fd, F_SETFL, client_flags)) config->tunnel(client->fd, c->remote.fd);
			break;
		}
		if(send_headers(c, &c->request, 1)) { send_error(c, errno == ETIMEDOUT ? 504 : 502); break; }
		if(c->request.expect && (c->request.chunked || c->request.length)) {
			static const char cont[] = "HTTP/1.1 100 Continue\r\n\r\n";
			if(write_all(client->fd, cont, sizeof cont-1, config->timeout, NULL)) break;
			c->sent_continue = 1;
		}
		c->client.upload = c;
		r = c->request.chunked ? transfer_chunked(&c->client, c->remote.fd, &c->request, 1) :
			transfer_length(&c->client, c->remote.fd, c->request.length);
		c->client.upload = NULL;
		if(r && r != EARLY_RESPONSE) {
			send_error(c, errno == ETIMEDOUT ? 408 : errno == EINVAL ? 400 : 502);
			break;
		}
		while(!c->early) {
			if(read_response(c)) { send_error(c, errno == ETIMEDOUT ? 504 : 502); goto done; }
			if(c->response.status >= 200) break;
			if(++c->informational > 32) { send_error(c, 502); goto done; }
			if(c->response.status == 100 && c->sent_continue) continue;
			if(send_headers(c, &c->response, 0)) goto done;
		}
		int body = !c->head && c->response.status != 204 && c->response.status != 304;
		int framed = !body || c->response.has_length || c->response.chunked;
		if(!framed || c->early || (c->response.chunked && c->request.minor == 0)) c->keep = 0;
		if(send_headers(c, &c->response, 0)) break;
		if(body) {
			r = c->response.chunked ? transfer_chunked(&c->remote, client->fd, &c->response, c->request.minor == 1) :
				c->response.has_length ? transfer_length(&c->remote, client->fd, c->response.length) :
				transfer_to_eof(&c->remote, client->fd);
			if(r) break;
		}
		if(!c->keep) break;
		if(c->response.close || !framed || c->remote.pos < c->remote.end) close_remote(c);
	}
done:
	close_remote(c);
	free(c);
}
