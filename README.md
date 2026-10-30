MicroSocks - multithreaded, small, efficient SOCKS5 server.
===========================================================

a SOCKS5 service that you can run on your remote boxes to tunnel connections
through them, if for some reason SSH doesn't cut it for you.

It's very lightweight, and very light on resources too:

for every client, a thread with a low stack size is spawned.
the main process basically doesn't consume any resources at all.

the only limits are the amount of file descriptors and the RAM.

It's also designed to be robust: it handles resource exhaustion
gracefully by simply denying new connections, instead of calling abort()
as most other programs do these days.

another plus is ease-of-use: no config file necessary, everything can be
done from the command line and doesn't even need any parameters for quick
setup.

History
-------

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

compilation/installation
------------------------

    make && sudo make install

if you want to override variables used in the Makefile, such as CC, CFLAGS, LDFLAGS,
prefix: do so in config.mak:

    printf 'CC=i686-musl-linux-gcc\nprefix=/usr\n' > config.mak
    make

command line options
--------------------

    microsocks -1 -q -t timeout -i listenip -p port -h httpport -u user -P passw -b bindaddr -w wl -f fwdrule

```
all arguments are optional.
by default listenip is 0.0.0.0 and port 1080.

-h httpport enables an additional HTTP proxy listener on the same listenip.
   without -h, only the SOCKS5 listener is enabled.
-q disables logging.
-b specifies which ip outgoing connections are bound to
-t timeout is specified in seconds, default 0.
   if timeout is set to 0, block until the OS signals activity.
-w allows to specify a comma-separated whitelist of ip addresses,
   that may use the proxy without user/pass authentication.
   e.g. -w 127.0.0.1,192.168.1.1,::1 or just -w 10.0.0.1
   to allow access ONLY to those ips, choose impossible to guess user/pw combo.
-1 activates auth_once mode: once a specific ip address
   authed successfully with user/pass, it is added to a whitelist
   and may use the proxy without auth.
   this is handy for programs like firefox that don't support
   user/pass auth. for it to work you'd basically make one connection
   with another program that supports it, and then you can use firefox too.
```

for example, authenticate once using curl:

    curl --socks5 user:password@listenip:port anyurl


Supported SOCKS5 Features
-------------------------
- authentication: none, password, one-time
- IPv4, IPv6, DNS
- TCP (no UDP at this time)

HTTP gateway
------------

The gateway variant adds an optional HTTP/1.0 and HTTP/1.1 forward proxy.
The SOCKS5 listener remains available at the same time:

    microsocks -i 127.0.0.1 -p 1080 -h 8080 -u user -P password

Both listeners share `-u`/`-P` credentials, `-w` whitelists, `-1` authentication
results, `-b` outgoing bind address, `-f` forwarding rules, `-t` idle timeout,
and `-q` logging settings. With `-1`, successful authentication on either
listener allows that client IP to use both listeners without authentication.
HTTP uses Basic proxy authentication and returns 407 when authentication is
required.

    curl --proxy http://127.0.0.1:8080 --proxy-user user:password http://example.com/
    curl --proxy http://127.0.0.1:8080 --proxy-user user:password https://example.com/

HTTPS destinations use CONNECT tunnels. Ordinary HTTP requests support
persistent client connections, sequential pipelined requests, Content-Length,
chunked bodies and trailers, and Expect: 100-continue. Each request is checked
for authentication and routed independently. Connections to the same target
are reused when possible; a later request on the same client connection may
also use a different target or forwarding rule. Close-delimited responses
close the client connection after the response body.

Forwarding rules have the format:

    -f 'match_name:match_port,[user:password@]upstream_name:upstream_port,remote_name:remote_port'

The first matching rule wins. `*` or `0.0.0.0` matches any host, match port 0
matches any port, and remote port 0 preserves the requested port. Rules route
connections through an upstream SOCKS5 proxy. HTTP Host and tunneled TLS
traffic retain the client's original destination name.

The HTTP listener accepts plaintext HTTP/1.x; TLS to the proxy itself and
ordinary HTTP Upgrade requests are not implemented. HTTPS traffic can still
pass through CONNECT. The supported transfer coding is chunked. Headers are
limited to approximately 16 KiB and 128 fields; individual chunk-size and
trailer lines are limited to 1023 bytes. HTTP buffers are allocated on the
heap to preserve the small thread stack.

Troubleshooting
---------------

if you experience segfaults, try raising the `THREAD_STACK_SIZE` in sockssrv.c
for your platform in steps of 4KB.

if this fixes your issue please file a pull request.

microsocks uses the smallest safe thread stack size to minimize overall memory
usage.
