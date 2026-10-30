/*
   MicroSocks - multithreaded, small, efficient SOCKS5 server.

   Copyright (C) 2017 rofl0r.

   This is the successor of "rocksocks5", and it was written with
   different goals in mind:

   - prefer usage of standard libc functions over homegrown ones
   - no artificial limits
   - do not aim for minimal binary size, but for minimal source code size,
     and maximal readability, reusability, and extensibility.

   as a result of that, ipv4, dns, and ipv6 is supported out of the box
   and can use the same code, while rocksocks5 has several compile time
   defines to bring down the size of the resulting binary to extreme values
   like 10 KB static linked when only ipv4 support is enabled.

   still, if optimized for size, *this* program when static linked against musl
   libc is not even 50 KB. that's easily usable even on the cheapest routers.

*/

#define _GNU_SOURCE
#include <unistd.h>
#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <poll.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <sys/time.h>
#include "server.h"
#include "sblist.h"
#include "httpproxy.h"
#define MICROSOCKS_VERSION "1.0.5-gateway"

/* timeout in microseconds on resource exhaustion to prevent excessive
   cpu usage. */
#ifndef FAILURE_TIMEOUT
#define FAILURE_TIMEOUT 64
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifdef PTHREAD_STACK_MIN
#define THREAD_STACK_SIZE MAX(16*1024, PTHREAD_STACK_MIN)
#else
#define THREAD_STACK_SIZE 64*1024
#endif

#if defined(__APPLE__)
#undef THREAD_STACK_SIZE
#define THREAD_STACK_SIZE 64*1024
#elif defined(__GLIBC__) || defined(__FreeBSD__) || defined(__sun__)
#undef THREAD_STACK_SIZE
#define THREAD_STACK_SIZE 32*1024
#elif defined(__OpenBSD__) && defined(__clang__)
#undef THREAD_STACK_SIZE
#define THREAD_STACK_SIZE 32*1024
#endif

static int quiet, timeout;
static const char* auth_user;
static const char* auth_pass;
static sblist* auth_ips;
static pthread_rwlock_t auth_ips_lock = PTHREAD_RWLOCK_INITIALIZER;
static const struct server* server;
static union sockaddr_union bind_addr = {.v4.sin_family = AF_UNSPEC};
static sblist *fwd_rules;

enum socksstate {
	SS_1_CONNECTED,
	SS_2_NEED_AUTH, /* skipped if NO_AUTH method supported */
	SS_3_AUTHED,
};

enum authmethod {
	AM_NO_AUTH = 0,
	AM_GSSAPI = 1,
	AM_USERNAME = 2,
	AM_INVALID = 0xFF
};

enum errorcode {
	EC_SUCCESS = 0,
	EC_GENERAL_FAILURE = 1,
	EC_NOT_ALLOWED = 2,
	EC_NET_UNREACHABLE = 3,
	EC_HOST_UNREACHABLE = 4,
	EC_CONN_REFUSED = 5,
	EC_TTL_EXPIRED = 6,
	EC_COMMAND_NOT_SUPPORTED = 7,
	EC_ADDRESSTYPE_NOT_SUPPORTED = 8,
};

struct fwd_rule {
	char *match_name;
	unsigned short match_port;
	char *auth_buf; /* Username/Password request buffer (RFC-1929) */
	size_t auth_len;
	char *upstream_name;
	unsigned short upstream_port;
	char *req_buf; /* Client Connection Request buffer to send to upstream */
	size_t req_len;
};

struct thread {
	pthread_t pt;
	struct client client;
	int http;
	enum socksstate state;
	volatile int  done;
};

#ifndef CONFIG_LOG
#define CONFIG_LOG 1
#endif
#if CONFIG_LOG
/* we log to stderr because it's not using line buffering, i.e. malloc which would need
   locking when called from different threads. for the same reason we use dprintf,
   which writes directly to an fd. */
#define dolog(...) do { if(!quiet) dprintf(2, __VA_ARGS__); } while(0)
#else
static void dolog(const char* fmt, ...) { }
#endif

static int fwd_read_all(int fd, unsigned char *buf, size_t len) {
	while(len) {
		ssize_t n = read(fd, buf, len);
		if(n < 0 && errno == EINTR) continue;
		if(n <= 0) return -1;
		buf += n;
		len -= n;
	}
	return 0;
}

static int fwd_write_all(int fd, const unsigned char *buf, size_t len) {
	while(len) {
		ssize_t n = write(fd, buf, len);
		if(n < 0 && errno == EINTR) continue;
		if(n <= 0) return -1;
		buf += n;
		len -= n;
	}
	return 0;
}

/* The caller owns upstream_fd, including on failure. */
static int upstream_handshake(const struct fwd_rule *rule, int client_fd,
		int upstream_fd, unsigned short client_port,
		const unsigned char *payload, size_t payload_len) {
	unsigned char buf[262]; /* largest SOCKS5 domain-name request/reply */
	unsigned char greeting[] = {5, 1, AM_NO_AUTH, AM_USERNAME};
	size_t total = 4, remaining;
	struct timeval tv = {0, 0};
	if(rule->auth_buf) greeting[1] = 2;
	if(fwd_write_all(upstream_fd, greeting, 2 + greeting[1]) ||
	   fwd_read_all(upstream_fd, buf, 2) || buf[0] != 5)
		return -EC_GENERAL_FAILURE;

	if(buf[1] == AM_USERNAME && rule->auth_buf) {
		if(fwd_write_all(upstream_fd, (unsigned char *)rule->auth_buf, rule->auth_len) ||
		   fwd_read_all(upstream_fd, buf, 2) || buf[0] != 1)
			return -EC_GENERAL_FAILURE;
		if(buf[1] != 0) return -EC_NOT_ALLOWED;
	} else if(buf[1] != AM_NO_AUTH) {
		return -EC_NOT_ALLOWED;
	}

	/* Rules are shared by all client threads; patch a private request copy. */
	memcpy(buf, rule->req_buf, rule->req_len);
	if(buf[rule->req_len-2] == 0 && buf[rule->req_len-1] == 0) {
		buf[rule->req_len-2] = client_port >> 8;
		buf[rule->req_len-1] = client_port & 0xff;
	}
	if(fwd_write_all(upstream_fd, buf, rule->req_len) ||
	   fwd_write_all(upstream_fd, payload, payload_len) ||
	   fwd_read_all(upstream_fd, buf, total) || buf[0] != 5 || buf[2] != 0)
		return -EC_GENERAL_FAILURE;
	if(buf[1] != EC_SUCCESS)
		return -(buf[1] <= EC_ADDRESSTYPE_NOT_SUPPORTED ? buf[1] : EC_GENERAL_FAILURE);

	switch(buf[3]) {
		case 1: remaining = 4 + 2; break;
		case 4: remaining = 16 + 2; break;
		case 3:
			if(fwd_read_all(upstream_fd, buf + total, 1) || !buf[total])
				return -EC_GENERAL_FAILURE;
			remaining = buf[total++] + 2;
			break;
		default: return -EC_ADDRESSTYPE_NOT_SUPPORTED;
	}
	if(fwd_read_all(upstream_fd, buf + total, remaining) ||
	   setsockopt(upstream_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) ||
	   setsockopt(upstream_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) ||
	   (client_fd >= 0 && fwd_write_all(client_fd, buf, total + remaining)))
		return -EC_GENERAL_FAILURE;
	return upstream_fd;
}

static struct addrinfo* addr_choose(struct addrinfo* list, union sockaddr_union* bindaddr) {
	int af = SOCKADDR_UNION_AF(bindaddr);
	if(af == AF_UNSPEC) return list;
	struct addrinfo* p;
	for(p=list; p; p=p->ai_next)
		if(p->ai_family == af) return p;
	return list;
}

static int connect_socks_target(unsigned char *buf, size_t n, struct client *client, int *used_rule, int send_reply) {
	*used_rule = 0;

	if(n < 5) return -EC_GENERAL_FAILURE;
	if(buf[0] != 5) return -EC_GENERAL_FAILURE;
	if(buf[1] != 1) return -EC_COMMAND_NOT_SUPPORTED; /* we support only CONNECT method */
	if(buf[2] != 0) return -EC_GENERAL_FAILURE; /* malformed packet */

	int af = AF_INET;
	size_t minlen = 4 + 4 + 2, l;
	char namebuf[256];
	struct addrinfo* remote;

	switch(buf[3]) {
		case 4: /* ipv6 */
			af = AF_INET6;
			minlen = 4 + 2 + 16;
			/* fall through */
		case 1: /* ipv4 */
			if(n < minlen) return -EC_GENERAL_FAILURE;
			if(namebuf != inet_ntop(af, buf+4, namebuf, sizeof namebuf))
				return -EC_GENERAL_FAILURE; /* malformed or too long addr */
			break;
		case 3: /* dns name */
			l = buf[4];
			minlen = 4 + 2 + l + 1;
			if(n < 4 + 2 + l + 1) return -EC_GENERAL_FAILURE;
			memcpy(namebuf, buf+4+1, l);
			namebuf[l] = 0;
			break;
		default:
			return -EC_ADDRESSTYPE_NOT_SUPPORTED;
	}
	unsigned short port;
	port = (buf[minlen-2] << 8) | buf[minlen-1];

	size_t i;
	struct fwd_rule *rule = NULL;
	char original_name[256];
	unsigned short original_port = port;
	strncpy(original_name, namebuf, sizeof(original_name) - 1);
	original_name[sizeof(original_name) - 1] = '\0';
	if(fwd_rules) {
		for(i=0;i<sblist_getsize(fwd_rules);++i) {
			struct fwd_rule* r = (struct fwd_rule*)sblist_get(fwd_rules, i);
			int name_match = (r->match_name[0]=='\0' || strcmp(r->match_name, namebuf) == 0);
			int port_match = (r->match_port == 0 || r->match_port == port);
			if(name_match && port_match) {
				rule = r;
				*used_rule = 1;
				strncpy(namebuf, r->upstream_name, sizeof(namebuf)-1);
				namebuf[sizeof(namebuf)-1] = '\0';
				port = r->upstream_port;
				break;
			}
		}
	}

	/* there's no suitable errorcode in rfc1928 for dns lookup failure */
	if(resolve(namebuf, port, &remote)) return -EC_GENERAL_FAILURE;
	struct addrinfo* raddr = addr_choose(remote, &bind_addr);
	int fd = socket(raddr->ai_family, SOCK_STREAM, 0);
	if(fd == -1) {
		eval_errno:
		if(fd != -1) close(fd);
		freeaddrinfo(remote);
		switch(errno) {
			case ETIMEDOUT:
				return -EC_TTL_EXPIRED;
			case EPROTOTYPE:
			case EPROTONOSUPPORT:
			case EAFNOSUPPORT:
				return -EC_ADDRESSTYPE_NOT_SUPPORTED;
			case ECONNREFUSED:
				return -EC_CONN_REFUSED;
			case ENETDOWN:
			case ENETUNREACH:
				return -EC_NET_UNREACHABLE;
			case EHOSTUNREACH:
				return -EC_HOST_UNREACHABLE;
			case EBADF:
			default:
			perror("socket/connect");
			return -EC_GENERAL_FAILURE;
		}
	}

	if(rule) {
		struct timeval tv = {5, 0};
		if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) ||
		   setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv))
			goto eval_errno;
	}

	if(SOCKADDR_UNION_AF(&bind_addr) == raddr->ai_family &&
	   bindtoip(fd, &bind_addr) == -1)
		goto eval_errno;
	if(connect(fd, raddr->ai_addr, raddr->ai_addrlen) == -1)
		goto eval_errno;

	freeaddrinfo(remote);
	if(CONFIG_LOG) {
		char clientname[256];
		af = SOCKADDR_UNION_AF(&client->addr);
		void *ipdata = SOCKADDR_UNION_ADDRESS(&client->addr);
		inet_ntop(af, ipdata, clientname, sizeof clientname);
		if (rule) {
			dolog("client[%d] %s: %s:%d -> via %s:%d\n", client->fd, clientname, original_name, original_port, rule->upstream_name, rule->upstream_port);
		} else {
			dolog("client[%d] %s: connected to %s:%d\n", client->fd, clientname, namebuf, port);
		}
	}

	if (rule) {
		int result = upstream_handshake(rule, send_reply ? client->fd : -1, fd, original_port,
			buf + minlen, n - minlen);
		if(result < 0) {
			close(fd);
			return result;
		}
		return result;
	}
	return fd;
}

static int is_authed(union sockaddr_union *client, union sockaddr_union *authedip) {
	int af = SOCKADDR_UNION_AF(authedip);
	if(af == SOCKADDR_UNION_AF(client)) {
		size_t cmpbytes = af == AF_INET ? 4 : 16;
		void *cmp1 = SOCKADDR_UNION_ADDRESS(client);
		void *cmp2 = SOCKADDR_UNION_ADDRESS(authedip);
		if(!memcmp(cmp1, cmp2, cmpbytes)) return 1;
	}
	return 0;
}

static int is_in_authed_list(union sockaddr_union *caddr) {
	size_t i;
	for(i=0;i<sblist_getsize(auth_ips);i++)
		if(is_authed(caddr, sblist_get(auth_ips, i)))
			return 1;
	return 0;
}

static void add_auth_ip(union sockaddr_union *caddr) {
	sblist_add(auth_ips, caddr);
}

static enum authmethod check_auth_method(unsigned char *buf, size_t n, struct client*client) {
	if(buf[0] != 5) return AM_INVALID;
	size_t idx = 1;
	if(idx >= n ) return AM_INVALID;
	int n_methods = buf[idx];
	idx++;
	while(idx < n && n_methods > 0) {
		if(buf[idx] == AM_NO_AUTH) {
			if(!auth_user) return AM_NO_AUTH;
			else if(auth_ips) {
				int authed = 0;
				if(pthread_rwlock_rdlock(&auth_ips_lock) == 0) {
					authed = is_in_authed_list(&client->addr);
					pthread_rwlock_unlock(&auth_ips_lock);
				}
				if(authed) return AM_NO_AUTH;
			}
		} else if(buf[idx] == AM_USERNAME) {
			if(auth_user) return AM_USERNAME;
		}
		idx++;
		n_methods--;
	}
	return AM_INVALID;
}

static void send_auth_response(int fd, int version, enum authmethod meth) {
	unsigned char buf[2];
	buf[0] = version;
	buf[1] = meth;
	write(fd, buf, 2);
}

static void send_error(int fd, enum errorcode ec) {
	/* position 4 contains ATYP, the address type, which is the same as used in the connect
	   request. we're lazy and return always IPV4 address type in errors. */
	char buf[10] = { 5, ec, 0, 1 /*AT_IPV4*/, 0,0,0,0, 0,0 };
	write(fd, buf, 10);
}

static void copyloop(int fd1, int fd2) {
	struct pollfd fds[2] = {
		[0] = {.fd = fd1, .events = POLLIN},
		[1] = {.fd = fd2, .events = POLLIN},
	};

	while(1) {
		switch(poll(fds, 2, timeout ? timeout*1000 : -1)) {
			case 0:
				return;
			case -1:
				if(errno == EINTR || errno == EAGAIN) continue;
				else perror("poll");
				return;
		}
		int infd = (fds[0].revents & POLLIN) ? fd1 : fd2;
		int outfd = infd == fd2 ? fd1 : fd2;
		/* since the biggest stack consumer in the entire code is
		   libc's getaddrinfo(), we can safely use at least half the
		   available stacksize to improve throughput. */
		char buf[MIN(16*1024, THREAD_STACK_SIZE/2)];
		ssize_t sent = 0, n = read(infd, buf, sizeof buf);
		if(n <= 0) return;
		while(sent < n) {
			ssize_t m = write(outfd, buf+sent, n-sent);
			if(m < 0) return;
			sent += m;
		}
	}
}

static enum errorcode check_credentials(unsigned char* buf, size_t n) {
	if(n < 5) return EC_GENERAL_FAILURE;
	if(buf[0] != 1) return EC_GENERAL_FAILURE;
	unsigned ulen, plen;
	ulen=buf[1];
	if(n < 2 + ulen + 2) return EC_GENERAL_FAILURE;
	plen=buf[2+ulen];
	if(n < 2 + ulen + 1 + plen) return EC_GENERAL_FAILURE;
	char user[256], pass[256];
	memcpy(user, buf+2, ulen);
	memcpy(pass, buf+2+ulen+1, plen);
	user[ulen] = 0;
	pass[plen] = 0;
	if(!strcmp(user, auth_user) && !strcmp(pass, auth_pass)) return EC_SUCCESS;
	return EC_NOT_ALLOWED;
}

static int handshake(struct thread *t) {
	unsigned char buf[1024];
	ssize_t n;
	int ret;
	enum authmethod am;
	int used_rule = 0;
	t->state = SS_1_CONNECTED;
	while((n = recv(t->client.fd, buf, sizeof buf, 0)) > 0) {
		switch(t->state) {
			case SS_1_CONNECTED:
				am = check_auth_method(buf, n, &t->client);
				if(am == AM_NO_AUTH) t->state = SS_3_AUTHED;
				else if (am == AM_USERNAME) t->state = SS_2_NEED_AUTH;
				send_auth_response(t->client.fd, 5, am);
				if(am == AM_INVALID) return -1;
				break;
			case SS_2_NEED_AUTH:
				ret = check_credentials(buf, n);
				send_auth_response(t->client.fd, 1, ret);
				if(ret != EC_SUCCESS)
					return -1;
				t->state = SS_3_AUTHED;
				if(auth_ips && !pthread_rwlock_wrlock(&auth_ips_lock)) {
					if(!is_in_authed_list(&t->client.addr))
						add_auth_ip(&t->client.addr);
					pthread_rwlock_unlock(&auth_ips_lock);
				}
				break;
			case SS_3_AUTHED:
				ret = connect_socks_target(buf, n, &t->client, &used_rule, 1);
				if(ret < 0) {
					send_error(t->client.fd, ret*-1);
					return -1;
				}
				if (!used_rule) {
					send_error(t->client.fd, EC_SUCCESS);
				}
				return ret;
		}
	}
	return -1;
}

/* HTTP shares the same credentials, whitelist, and outgoing routing. */
static int http_authorize(struct client *client, const unsigned char *credentials, size_t len) {
	int authed = !auth_user;
	if(!authed && auth_ips && !pthread_rwlock_rdlock(&auth_ips_lock)) {
		authed = is_in_authed_list(&client->addr);
		pthread_rwlock_unlock(&auth_ips_lock);
	}
	if(authed) return 1;
	size_t ulen = strlen(auth_user), plen = strlen(auth_pass);
	if(!credentials || len != ulen + 1 + plen ||
	   memcmp(credentials, auth_user, ulen) || credentials[ulen] != ':' ||
	   memcmp(credentials + ulen + 1, auth_pass, plen)) return 0;
	if(auth_ips && !pthread_rwlock_wrlock(&auth_ips_lock)) {
		if(!is_in_authed_list(&client->addr)) add_auth_ip(&client->addr);
		pthread_rwlock_unlock(&auth_ips_lock);
	}
	return 1;
}

static int http_connect_target(struct client *client, const char *host, unsigned short port) {
	unsigned char request[262] = {5, 1, 0, 3};
	size_t len = strlen(host);
	int used_rule, fd;
	if(!len || len > 255) return -502;
	request[4] = len;
	memcpy(request + 5, host, len);
	request[5 + len] = port >> 8;
	request[6 + len] = port & 0xff;
	fd = connect_socks_target(request, 7 + len, client, &used_rule, 0);
	return fd == -EC_TTL_EXPIRED ? -504 : fd < 0 ? -502 : fd;
}

static struct http_proxy_config http_config = {
	.authorize = http_authorize,
	.connect_target = http_connect_target,
	.tunnel = copyloop,
};

static void* clientthread(void *data) {
	struct thread *t = data;
	if(t->http) http_proxy_serve(&t->client, &http_config);
	else {
		int remotefd = handshake(t);
		if(remotefd != -1) {
			copyloop(t->client.fd, remotefd);
			close(remotefd);
		}
	}
	close(t->client.fd);
	t->done = 1;
	return 0;
}

static void collect(sblist *threads) {
	size_t i;
	for(i=0;i<sblist_getsize(threads);) {
		struct thread* thread = *((struct thread**)sblist_get(threads, i));
		if(thread->done) {
			pthread_join(thread->pt, 0);
			sblist_delete(threads, i);
			free(thread);
		} else
			i++;
	}
}

static int host_get_port(char *name) {
	char *c = strrchr(name, ':'), *end;
	unsigned long port;
	if(!c || c[1] < '0' || c[1] > '9') return -1;
	errno = 0;
	port = strtoul(c+1, &end, 10);
	if(errno || *end || port > USHRT_MAX) return -1;
	*c = 0;
	return (int)port;
}

static int fwd_rules_add(char *str) {
	struct fwd_rule rule = {0};
	char *storage = strdup(str), *match, *upstream, *remote, *at, *colon;
	int match_port, upstream_port, remote_port;
	size_t rlen, ulen, plen;
	int result = 1;
	if(!storage) return 1;
	match = storage;
	if(!(upstream = strchr(match, ','))) goto out;
	*upstream++ = 0;
	if(!(remote = strchr(upstream, ','))) goto out;
	*remote++ = 0;
	if(strchr(remote, ',')) goto out;

	match_port = host_get_port(match);
	upstream_port = host_get_port(upstream);
	remote_port = host_get_port(remote);
	if(match_port < 0 || upstream_port <= 0 || remote_port < 0) goto out;
	rlen = strlen(remote);
	if(!rlen || rlen > 255) goto out;

	if(!strcmp(match, "0.0.0.0") || !strcmp(match, "*")) match[0] = 0;
	rule.match_name = strdup(match);
	rule.match_port = match_port;
	rule.upstream_port = upstream_port;
	if((at = strrchr(upstream, '@'))) {
		*at = 0;
		if(!(colon = strchr(upstream, ':'))) goto out;
		*colon++ = 0;
		ulen = strlen(upstream);
		plen = strlen(colon);
		if(!ulen || ulen > 255 || !plen || plen > 255) goto out;
		rule.auth_len = 3 + ulen + plen;
		if(!(rule.auth_buf = malloc(rule.auth_len))) goto out;
		rule.auth_buf[0] = 1;
		rule.auth_buf[1] = ulen;
		memcpy(rule.auth_buf + 2, upstream, ulen);
		rule.auth_buf[2 + ulen] = plen;
		memcpy(rule.auth_buf + 3 + ulen, colon, plen);
		/* Hide credentials in the original argument, not just the copy. */
		memset(str + (upstream - storage), '*', at - upstream);
		upstream = at + 1;
	}
	if(!*upstream || strlen(upstream) > 255) goto out;
	rule.upstream_name = strdup(upstream);
	rule.req_len = 7 + rlen;
	if(!rule.match_name || !rule.upstream_name ||
	   !(rule.req_buf = malloc(rule.req_len))) goto out;
	rule.req_buf[0] = 5;
	rule.req_buf[1] = 1;
	rule.req_buf[2] = 0;
	rule.req_buf[3] = 3;
	rule.req_buf[4] = rlen;
	memcpy(rule.req_buf + 5, remote, rlen);
	rule.req_buf[5 + rlen] = remote_port >> 8;
	rule.req_buf[6 + rlen] = remote_port & 0xff;
	if(!sblist_add(fwd_rules, &rule)) goto out;
	result = 0;
out:
	if(result) {
		free(rule.match_name);
		free(rule.auth_buf);
		free(rule.upstream_name);
		free(rule.req_buf);
	}
	free(storage);
	return result;
}

static int usage(void) {
	dprintf(2,
		"MicroSocks SOCKS5/HTTP Gateway\n"
		"------------------------\n"
		"usage: microsocks -1 -q -t timeout -i listenip -p port -h httpport -u user -P pass -b bindaddr -w ips -f fwdrule -V\n"
		"all arguments are optional.\n"
		"by default listenip is 0.0.0.0 and port 1080.\n\n"
		"-h httpport enables an additional HTTP proxy listener on the same listenip.\n"
		"   HTTP shares authentication, whitelist, forwarding rules, and timeout settings.\n"
		"-q disables logging.\n"
		"-b specifies which ip outgoing connections are bound to\n"
		"-t timeout is specified in seconds, default 0.\n"
		"   if timeout is set to 0, block until the OS signals activity.\n"
		"-w allows to specify a comma-separated whitelist of ip addresses,\n"
		"   that may use the proxy without user/pass authentication.\n"
		"   e.g. -w 127.0.0.1,192.168.1.1,::1 or just -w 10.0.0.1\n"
		"   to allow access ONLY to those ips, choose impossible to guess user/pw combo.\n"
		"-1 activates auth_once mode: once a specific ip address\n"
		"   authed successfully with user/pass, it is added to a whitelist\n"
		"   and may use the proxy without auth.\n"
		"   this is handy for programs like firefox that don't support\n"
		"   user/pass auth. for it to work you'd basically make one connection\n"
		"   with another program that supports it, and then you can use firefox too.\n"
		"-f specifies a forwarding rule of the form\n"
		"   match_name:match_port,[user:password@]upstream_name:upstream_port,remote_name:remote_port\n"
		"   matching requests are renamed to remote and sent through the upstream SOCKS5 proxy.\n"
		"   match_name * or 0.0.0.0 matches any host; match_port 0 matches any port.\n"
		"   remote_port 0 keeps the requested port. The first matching rule wins.\n"
		"   this option may be specified multiple times.\n"
		"-V prints version information and exits.\n"
	);
	return 1;
}

/* prevent username and password from showing up in top. */
static void zero_arg(char *s) {
	size_t i, l = strlen(s);
	for(i=0;i<l;i++) s[i] = 0;
}

int main(int argc, char** argv) {
	int ch;
	const char *listenip = "0.0.0.0";
	char *p, *q;
	unsigned port = 1080, http_port = 0;
	while((ch = getopt(argc, argv, ":1qb:t:i:p:h:u:P:w:f:V")) != -1) {
		switch(ch) {
			case 'w': /* fall-through */
			case '1':
				if(!auth_ips)
					auth_ips = sblist_new(sizeof(union sockaddr_union), 8);
				if(ch == '1') break;
				p = optarg;
				while(1) {
					union sockaddr_union ca;
					if((q = strchr(p, ','))) *q = 0;
					if(resolve_sa(p, 0, &ca)) {
						dprintf(2, "error: failed to resolve %s\n", p);
						return 1;
					}
					add_auth_ip(&ca);
					if(q) *(q++) = ',', p = q;
					else break;
				}
				break;
			case 'q':
				quiet = 1;
				break;
			case 't':
				timeout = atoi(optarg);
				break;
			case 'b':
				resolve_sa(optarg, 0, &bind_addr);
				break;
			case 'u':
				auth_user = strdup(optarg);
				zero_arg(optarg);
				break;
			case 'P':
				auth_pass = strdup(optarg);
				zero_arg(optarg);
				break;
			case 'i':
				listenip = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h': {
				char *end;
				unsigned long value;
				errno = 0;
				value = strtoul(optarg, &end, 10);
				if(errno || optarg[0] < '0' || optarg[0] > '9' || *end ||
				   value == 0 || value > USHRT_MAX)
					return dprintf(2, "error: invalid HTTP listening port\n"), 1;
				http_port = value;
				break;
			}
			case 'f':
				if(!fwd_rules)
					fwd_rules = sblist_new(sizeof(struct fwd_rule), 16);
				if(!fwd_rules || fwd_rules_add(optarg))
					return dprintf(2, "error: invalid forwarding rule or out of memory\n"), 1;
				break;
			case ':':
				dprintf(2, "error: option -%c requires an operand\n", optopt);
				/* fall through */
			case '?':
				return usage();
			case 'V':
				dprintf(1, "MicroSocks %s\n", MICROSOCKS_VERSION);
				return 0;
		}
	}
	if((auth_user && !auth_pass) || (!auth_user && auth_pass)) {
		dprintf(2, "error: user and pass must be used together\n");
		return 1;
	}
	if(auth_ips && !auth_pass) {
		dprintf(2, "error: -1/-w options must be used together with user/pass\n");
		return 1;
	}
	signal(SIGPIPE, SIG_IGN);
	struct server s, http_server;
	sblist *threads = sblist_new(sizeof (struct thread*), 8);
	if(server_setup(&s, listenip, port)) {
		perror("server_setup");
		return 1;
	}
	server = &s;
	if(http_port && server_setup(&http_server, listenip, http_port)) {
		perror("HTTP server_setup");
		close(s.fd);
		return 1;
	}
	http_config.timeout = timeout;
	int next_http = 0;
	while(1) {
		collect(threads);
		int use_http = 0;
		if(http_port) {
			struct pollfd listeners[2] = {
				{.fd = s.fd, .events = POLLIN},
				{.fd = http_server.fd, .events = POLLIN},
			};
			if(poll(listeners, 2, -1) <= 0) {
				if(errno != EINTR) usleep(FAILURE_TIMEOUT);
				continue;
			}
			if(!(listeners[0].revents & POLLIN) && !(listeners[1].revents & POLLIN))
				continue;
			use_http = (listeners[1].revents & POLLIN) &&
				(!(listeners[0].revents & POLLIN) || next_http);
			next_http = !use_http;
		}
		struct client c;
		struct thread *curr = malloc(sizeof (struct thread));
		if(!curr) goto oom;
		curr->done = 0;
		if(server_waitclient(use_http ? &http_server : &s, &c)) {
			dolog("failed to accept connection\n");
			free(curr);
			usleep(FAILURE_TIMEOUT);
			continue;
		}
		curr->client = c;
		curr->http = use_http;
		if(!sblist_add(threads, &curr)) {
			close(curr->client.fd);
			free(curr);
			oom:
			dolog("rejecting connection due to OOM\n");
			usleep(FAILURE_TIMEOUT); /* prevent 100% CPU usage in OOM situation */
			continue;
		}
		pthread_attr_t *a = 0, attr;
		if(pthread_attr_init(&attr) == 0) {
			a = &attr;
			pthread_attr_setstacksize(a, THREAD_STACK_SIZE);
		}
		if(pthread_create(&curr->pt, a, clientthread, curr) != 0) {
			sblist_delete(threads, sblist_getsize(threads)-1);
			close(curr->client.fd);
			free(curr);
			dolog("pthread_create failed. OOM?\n");
			usleep(FAILURE_TIMEOUT);
		}
		if(a) pthread_attr_destroy(&attr);
	}
}
