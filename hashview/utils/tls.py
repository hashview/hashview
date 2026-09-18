"""A TLS context whose handshake cannot stall the server's accept loop.

Werkzeug wraps the LISTENING socket in TLS (serving.py: ``self.socket =
ssl_context.wrap_socket(self.socket, server_side=True)``), so ``accept()``
returns an already-wrapped SSLSocket and performs the TLS handshake inline --
blocking, with no deadline, on the single ``serve_forever`` thread.
``threaded=True`` does not help: it only threads what happens AFTER accept
returns.

One client that completes the TCP handshake and then never sends a ClientHello
therefore stops the server accepting anything, permanently. The process stays
alive, CPU sits at zero, memory is flat, and the database goes quiet -- which is
what makes it so hard to read from the outside. Agents are a ready source: their
HTTP client sets no timeout and retries up to 100 times, so a suspended or
partitioned agent leaves exactly this kind of half-open connection behind.

The fix is a deadline on the handshake, and only on the handshake. It cannot
go on the listening socket -- a timeout there bounds the accept() syscall, not
the TLS negotiation, because accept() returns a BLOCKING socket that does not
inherit the listener's timeout. It goes on that accepted socket instead, and is
lifted the moment the handshake completes: leaving it in place would bound every
later read and write, cutting off an agent pulling a multi-gigabyte wordlist over
a slow link. SO_ACCEPTCONN tells the two sockets apart.

The real fix for a production deployment is to terminate TLS in front of
Hashview (nginx, caddy) and let it serve plain HTTP on localhost. This makes the
built-in server survivable for the deployments that do not.
"""

import socket
import ssl

# Generous for a real handshake over a slow link, far below the "forever" this
# replaces. A client that cannot complete a handshake in this long is not
# going to.
DEFAULT_HANDSHAKE_TIMEOUT = 30


def _is_listening(sock):
    """True for a listening socket, False for an accepted connection."""
    try:
        return bool(sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN))
    except OSError:
        return False


class HandshakeTimeoutSSLContext(ssl.SSLContext):
    """SSLContext that puts a deadline on the handshake, and only the handshake.

    wrap_socket is called twice per request. Once on the LISTENER, at server
    construction -- left alone, because a timeout there bounds the accept()
    syscall, not the handshake. Once per connection, from inside
    SSLSocket.accept(), on the freshly accepted socket -- and that is where the
    handshake runs, because accept() hands back a blocking socket that does not
    inherit the listener's timeout.

    So the deadline goes on the accepted socket before the handshake and is
    lifted immediately after. Leaving it in place would bound every subsequent
    read and write too, which would cut off exactly the traffic this server
    exists to carry: an agent pulling a multi-gigabyte wordlist over a slow link
    is not a stalled client.
    """

    handshake_timeout = DEFAULT_HANDSHAKE_TIMEOUT

    def wrap_socket(self, sock, *args, **kwargs):
        if _is_listening(sock):
            return super().wrap_socket(sock, *args, **kwargs)

        previous = sock.gettimeout()
        sock.settimeout(self.handshake_timeout)
        try:
            wrapped = super().wrap_socket(sock, *args, **kwargs)
        except BaseException:
            # A timed-out handshake leaves this socket with nothing to close it:
            # SSLSocket.accept() is raising through, so no caller ever sees it.
            # socketserver treats the error as "no request this time" and carries
            # on, which is the whole point -- but it would leak an fd per stalled
            # client, and fd exhaustion would wedge accept() just as thoroughly.
            sock.close()
            raise
        # Back to blocking for the transfer itself.
        wrapped.settimeout(previous)
        return wrapped


def server_ssl_context(certfile, keyfile, handshake_timeout=None):
    """Build the server's TLS context with a bounded handshake."""
    context = HandshakeTimeoutSSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.handshake_timeout = handshake_timeout or DEFAULT_HANDSHAKE_TIMEOUT
    context.load_cert_chain(certfile, keyfile)
    return context
