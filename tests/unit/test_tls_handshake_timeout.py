"""A stalled TLS handshake must not stop the server accepting connections.

Werkzeug wraps the LISTENING socket in TLS, so accept() returns an
already-wrapped SSLSocket and the handshake runs inline on the single
serve_forever thread with no deadline. threaded=True does not help -- it only
threads what happens after accept returns. One client that completes the TCP
handshake and never sends a ClientHello therefore stops the server dead: process
alive, CPU idle, memory flat, database quiet. It was observed in production, and
py-spy showed the accept thread parked in ssl.py do_handshake under get_request.

These tests drive a real werkzeug server over a real socket, because that is the
only way this is observable: nothing about the shape of the code says the
handshake happens inside accept().
"""

import socket
import ssl
import threading
import time

import pytest

from hashview.utils.tls import (
    DEFAULT_HANDSHAKE_TIMEOUT,
    HandshakeTimeoutSSLContext,
    server_ssl_context,
)

pytestmark = pytest.mark.security

CERT = 'hashview/ssl/cert.pem'
KEY = 'hashview/ssl/key.pem'


PAYLOAD_SIZE = 16 * 1024 * 1024      # comfortably larger than any socket buffer


def _app(environ, start_response):
    if environ['PATH_INFO'] == '/big':
        payload = b'x' * PAYLOAD_SIZE
        start_response('200 OK', [('Content-Length', str(len(payload)))])
        return [payload]
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [b'ok']


@pytest.fixture()
def tls_server():
    """A real werkzeug HTTPS server with a short handshake deadline."""
    from werkzeug.serving import make_server

    servers = []

    def _start(ssl_context):
        srv = make_server('127.0.0.1', 0, _app, threaded=True,
                          ssl_context=ssl_context)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        time.sleep(0.3)
        servers.append(srv)
        return srv

    yield _start
    for srv in servers:
        srv.shutdown()


def _get(port, path='/', timeout=8):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sock = context.wrap_socket(
        socket.create_connection(('127.0.0.1', port), timeout=timeout))
    sock.settimeout(timeout)
    sock.sendall(
        f'GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'.encode())
    body = b''
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        body += chunk
    sock.close()
    return body


def test_a_silent_client_does_not_stop_the_server_accepting(tls_server):
    """The regression itself: connect, send nothing, never close."""
    srv = tls_server(server_ssl_context(CERT, KEY, handshake_timeout=2))
    assert _get(srv.port).startswith(b'HTTP/1.1 200'), 'server broken before the test'

    stalled = socket.create_connection(('127.0.0.1', srv.port))
    try:
        time.sleep(0.4)
        # The deadline may make this wait, but it must not fail: before the fix
        # the server never accepted another connection at all.
        assert _get(srv.port, timeout=15).startswith(b'HTTP/1.1 200'), (
            'a single silent TCP connection stopped the server accepting')
    finally:
        stalled.close()


def test_the_server_keeps_working_after_several_stalled_clients(tls_server):
    """Serial stalls must not accumulate into a permanent wedge."""
    srv = tls_server(server_ssl_context(CERT, KEY, handshake_timeout=1))
    stalls = [socket.create_connection(('127.0.0.1', srv.port)) for _ in range(3)]
    try:
        time.sleep(0.3)
        assert _get(srv.port, timeout=20).startswith(b'HTTP/1.1 200')
    finally:
        for s in stalls:
            s.close()


def test_a_stalled_reader_is_not_cut_off_by_the_handshake_deadline(tls_server):
    """The deadline must bound the handshake ONLY.

    Left on the socket it bounds every later write too, and the way that bites
    is not a slow trickle -- a socket timeout is per-operation, and sleeping
    between reads just lets the kernel buffer, so recv returns instantly and
    nothing ever times out. It bites when the SERVER's send() blocks: once the
    socket buffers fill, a client that stops reading for longer than the
    deadline makes send() raise, and the transfer dies mid-stream.

    That is precisely an agent pulling a large wordlist over a congested link,
    so the payload here is big enough to fill the buffers and the pause is
    several times the deadline.
    """
    srv = tls_server(server_ssl_context(CERT, KEY, handshake_timeout=1))

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sock = context.wrap_socket(
        socket.create_connection(('127.0.0.1', srv.port), timeout=10))
    sock.settimeout(30)
    sock.sendall(b'GET /big HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')

    received = len(sock.recv(4096))
    # Stop reading for well over the deadline, so the server's send() blocks on
    # a full window for longer than the handshake timeout would allow.
    time.sleep(4)

    while True:
        try:
            chunk = sock.recv(65536)
        except OSError:
            break
        if not chunk:
            break
        received += len(chunk)
    sock.close()

    assert received >= PAYLOAD_SIZE, (
        f'the transfer died at {received:,} of {PAYLOAD_SIZE:,} bytes -- the '
        'handshake deadline is still on the socket and is bounding the whole '
        'connection, so a client that pauses loses its download')


def test_the_listening_socket_itself_is_left_blocking(tls_server):
    """A timeout on the LISTENER bounds accept(), not the handshake.

    Putting it there instead looks equivalent and fixes nothing: accept()
    returns a blocking socket that does not inherit the listener's timeout, so
    the handshake stays unbounded. Pinning this stops the fix being "simplified"
    back into the broken shape.
    """
    srv = tls_server(server_ssl_context(CERT, KEY, handshake_timeout=5))
    assert srv.socket.gettimeout() is None, (
        'the listening socket has a timeout; that bounds accept(), not the '
        'handshake, and would leave the wedge in place')


def test_the_context_is_what_the_entry_point_installs():
    """hashview.py must pass this context, not a (cert, key) tuple.

    Werkzeug builds its own plain SSLContext from a tuple, and the wedge comes
    straight back.
    """
    source = open('hashview.py', encoding='utf-8').read()
    assert 'server_ssl_context(' in source, (
        'hashview.py no longer builds a bounded TLS context')
    assert "ssl_context=('./hashview/ssl/cert.pem'" not in source, (
        'hashview.py is back to the (cert, key) tuple, which werkzeug wraps '
        'into an unbounded context')


def test_a_default_deadline_applies_when_none_is_given():
    context = server_ssl_context(CERT, KEY)
    assert context.handshake_timeout == DEFAULT_HANDSHAKE_TIMEOUT
    assert context.handshake_timeout, 'a falsy deadline means block forever'
    assert isinstance(context, HandshakeTimeoutSSLContext)
