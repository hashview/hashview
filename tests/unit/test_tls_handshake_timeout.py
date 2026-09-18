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

import datetime
import ipaddress
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


@pytest.fixture(scope='module')
def tls_cert(tmp_path_factory):
    """An ephemeral self-signed cert, generated here rather than read from disk.

    These tests originally used hashview/ssl/cert.pem. That works on a machine
    where the app has been installed and nowhere else: setup.py mints that pair
    with openssl at install time and .gitignore excludes `hashview/ssl/*`, so a
    fresh checkout -- CI, or any developer who has not run setup -- has no such
    file and every test in this module died with FileNotFoundError.

    cryptography is safe to depend on here: Authlib is pinned in
    requirements.txt, requires it, and the app refuses to start without Authlib.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    # 2048, not the 4096 setup.py uses: this key protects nothing, lives only
    # for the module, and 4096 costs seconds on every run.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.ip_address('127.0.0.1')),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    directory = tmp_path_factory.mktemp('tls')
    certfile = directory / 'cert.pem'
    keyfile = directory / 'key.pem'
    certfile.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    return str(certfile), str(keyfile)


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


def test_a_silent_client_does_not_stop_the_server_accepting(tls_server, tls_cert):
    """The regression itself: connect, send nothing, never close."""
    srv = tls_server(server_ssl_context(*tls_cert, handshake_timeout=2))
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


def test_the_server_keeps_working_after_several_stalled_clients(tls_server, tls_cert):
    """Serial stalls must not accumulate into a permanent wedge."""
    srv = tls_server(server_ssl_context(*tls_cert, handshake_timeout=1))
    stalls = [socket.create_connection(('127.0.0.1', srv.port)) for _ in range(3)]
    try:
        time.sleep(0.3)
        assert _get(srv.port, timeout=20).startswith(b'HTTP/1.1 200')
    finally:
        for s in stalls:
            s.close()


def test_a_stalled_reader_is_not_cut_off_by_the_handshake_deadline(
        tls_server, tls_cert):
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
    srv = tls_server(server_ssl_context(*tls_cert, handshake_timeout=1))

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


def test_the_listening_socket_itself_is_left_blocking(tls_server, tls_cert):
    """A timeout on the LISTENER bounds accept(), not the handshake.

    Putting it there instead looks equivalent and fixes nothing: accept()
    returns a blocking socket that does not inherit the listener's timeout, so
    the handshake stays unbounded. Pinning this stops the fix being "simplified"
    back into the broken shape.
    """
    srv = tls_server(server_ssl_context(*tls_cert, handshake_timeout=5))
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


def test_a_default_deadline_applies_when_none_is_given(tls_cert):
    context = server_ssl_context(*tls_cert)
    assert context.handshake_timeout == DEFAULT_HANDSHAKE_TIMEOUT
    assert context.handshake_timeout, 'a falsy deadline means block forever'
    assert isinstance(context, HandshakeTimeoutSSLContext)
