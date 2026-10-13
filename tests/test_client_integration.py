#!/usr/bin/env python3
"""Local TLS contract fixtures, plus PTY tests of the actual client executable.
Usage: python3 tests/test_client_integration.py CLIENT COMMAND_TEST_RUNNER
Requires openssl CLI, Python 3, loopback sockets and POSIX pseudo-terminals.
All keys, certificates, configs, payloads and destinations live in TemporaryDirectory.
"""
import contextlib
import os
from pathlib import Path
import pty
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

CLIENT, RUNNER = map(os.path.abspath, sys.argv[1:3])
PASSWORD = b'q' * 8
USER = b'alice'
CHUNK = bytes(range(256)) * 4096
COUNT = 0


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def exact(connection, count):
    data = bytearray()
    while len(data) < count:
        piece = connection.recv(count - len(data))
        require(piece, 'unexpected request EOF')
        data.extend(piece)
    return bytes(data)


def header(command, size=0):
    result = command.upper().encode() + USER + b'\0' + PASSWORD + b'\0'
    if command == 'upload':
        result += struct.pack('!I', size)
    if command != 'list':
        result += b'remote.bin\0'
    return result


def listener():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    sock.listen(8)
    sock.settimeout(10)
    return sock


def no_connection(sock):
    require(not select.select([sock], [], [], 0)[0], 'unexpected retry/failover/network operation')


def run_process(args, environment, interactive):
    if not interactive:
        p = subprocess.run(args, capture_output=True, env=environment, timeout=15)
        require(b'CLEANSED' in p.stderr, 'command runner did not verify password erasure')
        return p.returncode, p.stdout, p.stderr
    master, slave = pty.openpty()
    process = None
    try:
        process = subprocess.Popen(args, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        os.close(slave)
        slave = -1
        prompt = bytearray()
        deadline = time.monotonic() + 10
        while b'Password: ' not in prompt:
            require(time.monotonic() < deadline, 'password prompt timed out')
            ready = select.select([process.stderr], [], [], 0.1)[0]
            if ready:
                piece = os.read(process.stderr.fileno(), 1024)
                require(piece, 'client exited before prompting')
                prompt.extend(piece)
        password = b'q' * (65 if environment.get('CS469_TEST_LONG_PASSWORD') else 8)
        os.write(master, password + b'\n')
        out, err = process.communicate(timeout=15)
        require(password not in out + err + prompt, 'password leaked to output')
        # Terminal stdin is separate from stderr, so any echo would appear here.
        if select.select([master], [], [], 0)[0]:
            try:
                echoed = os.read(master, 4096)
            except OSError:
                echoed = b''
            require(password not in echoed, 'password was echoed')
        return process.returncode, out, bytes(prompt) + err
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        if slave >= 0:
            os.close(slave)


with tempfile.TemporaryDirectory(prefix='cs469-codec-') as root:
    root = Path(root)
    openssl = os.environ.get('OPENSSL', shutil.which('openssl'))
    require(openssl is not None, 'openssl CLI is required')

    def openssl_run(*args):
        subprocess.run([openssl, *map(str, args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    ca, key, cert = root/'ca.pem', root/'server.key', root/'server.pem'
    openssl_run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Fixture CA', '-keyout', root/'ca.key', '-out', ca)
    openssl_run('req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
                '-keyout', key, '-out', root/'server.csr')
    (root/'extensions').write_text('subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n')
    openssl_run('x509', '-req', '-in', root/'server.csr', '-CA', ca, '-CAkey', root/'ca.key',
                '-CAcreateserial', '-days', '1', '-extfile', root/'extensions', '-out', cert)
    openssl_run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Untrusted CA', '-keyout', root/'other.key', '-out', root/'other.pem')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)

    def case(name, command, handler=None, *, payload=b'', ok=True, message=b'', expected_output=None,
             existing=None, disk_fault=False, read_fault=False, long_password=False,
             refused=False, bad_cert=False, interactive=False, expect_file=None, truncate=False,
             race=False, source_directory=False, huge=False, symlink=False):
        global COUNT
        COUNT += 1
        folder = root/str(COUNT)
        folder.mkdir()
        source, destination = folder/'source', folder/'destination'
        if source_directory:
            source.mkdir()
        else:
            source.write_bytes(payload)
            if huge:
                with source.open('r+b') as file:
                    file.truncate(2**32)
        if existing is not None:
            destination.write_bytes(existing)
        if symlink:
            destination.symlink_to(source)
        with contextlib.ExitStack() as stack:
            primary = stack.enter_context(listener())
            replica = stack.enter_context(listener())
            port = primary.getsockname()[1]
            if refused:
                primary.close()
            config = folder/'client.conf'
            config.write_text(f'primary_host=127.0.0.1\nprimary_port={port}\n'
                              f'replica_host=127.0.0.1\nreplica_port={replica.getsockname()[1]}\n'
                              f'ca_file={root/"other.pem" if bad_cert else ca}\n')
            failures = []

            def serve():
                try:
                    raw, _ = primary.accept()
                    raw.settimeout(8)
                    with raw:
                        try:
                            connection = context.wrap_socket(raw, server_side=True)
                        except ssl.SSLError:
                            if bad_cert:
                                return
                            raise
                        with connection:
                            require(not bad_cert, 'untrusted server was accepted')
                            expected = header(command, len(payload))
                            require(exact(connection, len(expected)) == expected, 'wire request differs from frozen contract')
                            if truncate:
                                source.write_bytes(b'')
                            if race:
                                destination.write_bytes(b'racing file')
                            handler(connection)
                except BaseException as exc:
                    failures.append(exc)

            thread = None
            if handler is not None or bad_cert:
                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
            arguments = [CLIENT if interactive else RUNNER, '--config', str(config), '--username', 'alice', command]
            if command == 'upload':
                arguments += [str(source), 'remote.bin']
            elif command == 'download':
                arguments += ['remote.bin', str(destination)]
            elif command == 'delete':
                arguments += ['remote.bin']
            environment = os.environ.copy()
            for setting, value in [('CS469_TEST_READ_FAIL', read_fault), ('CS469_TEST_WRITE_FAIL', disk_fault),
                                   ('CS469_TEST_LONG_PASSWORD', long_password)]:
                environment.pop(setting, None)
                if value:
                    environment[setting] = '1'
            rc, out, err = run_process(arguments, environment, interactive)
            if thread:
                thread.join(10)
                require(not thread.is_alive(), 'mock server did not finish')
            if failures:
                raise failures[0]
            require(rc == (0 if ok else 1), f'{name}: unexpected exit {rc}: {err.decode(errors="replace")}')
            require(message in err, f'{name}: missing diagnostic')
            require(b'AddressSanitizer' not in err and b'runtime error:' not in err, 'sanitizer diagnostics')
            if expected_output is not None:
                require(out == expected_output, f'{name}: unexpected stdout')
            require(PASSWORD not in out + err, 'password leaked')
            if not refused:
                no_connection(primary)
            no_connection(replica)
            require(not list(folder.glob('.cs469-download-*')), f'{name}: staging file remains')
            if command == 'download':
                if symlink:
                    require(destination.is_symlink() and destination.read_bytes() == payload, 'existing symlink changed')
                elif existing is not None or race:
                    require(destination.read_bytes() == (existing if existing is not None else b'racing file'), 'existing destination changed')
                elif expect_file is not None:
                    require(destination.read_bytes() == expect_file, 'download contents differ')
                    require(destination.stat().st_mode & 0o777 == 0o600, 'download permissions are not private')
                else:
                    require(not destination.exists(), 'failed download exposed final file')
            if command == 'upload' and not source_directory and not huge and not truncate:
                require(source.read_bytes() == payload, 'upload modified source')
        print('PASS:', name)

    def reply(data, fragmented=False):
        def send(connection):
            if fragmented:
                for byte in data:
                    connection.sendall(bytes([byte]))
                    time.sleep(0.001)
            else:
                connection.sendall(data)
        return send

    def upload(payload, preliminary=0, final=0):
        def serve(connection):
            connection.sendall(bytes([preliminary]))
            if preliminary:
                require(connection.recv(1) == b'', 'payload sent after preliminary rejection')
                return
            require(exact(connection, len(payload)) == payload, 'upload data mismatch')
            connection.sendall(bytes([final]))
        return serve

    def upload_loss(connection):
        connection.sendall(b'\0')
        exact(connection, 1)
        # Abrupt transport close after body starts. No second accept is performed;
        # pending connections and replica listener are checked after the process.

    def local_read_failure(connection):
        connection.sendall(b'\0')
        require(connection.recv(1) == b'', 'unexpected body after local read failure')

    for interactive in (False, True):
        suffix = ' executable/PTY' if interactive else ' command API/cleanup'
        case('LIST coalesced'+suffix, 'list', reply(b'\0'+struct.pack('!I', 2)+b'a.txt\0b.txt\0'),
             expected_output=b'a.txt\nb.txt\n', interactive=interactive)
        case('UPLOAD'+suffix, 'upload', upload(CHUNK), payload=CHUNK, interactive=interactive, expected_output=b'Upload complete.\n' if interactive else b'')
        case('DOWNLOAD'+suffix, 'download', reply(b'\0'+struct.pack('!I', len(CHUNK))+CHUNK),
             expect_file=CHUNK, interactive=interactive, expected_output=b'Download complete.\n' if interactive else b'')
        case('DELETE'+suffix, 'delete', reply(b'\0'), interactive=interactive, expected_output=b'Delete complete.\n' if interactive else b'')

    case('empty list', 'list', reply(b'\0\0\0\0\0'), expected_output=b'')
    case('fragmented list', 'list', reply(b'\0\0\0\0\2one\0two\0', True), expected_output=b'one\ntwo\n')
    case('unterminated list name', 'list', reply(b'\0\0\0\0\1'+b'a'*257), ok=False, message=b'Protocol error')
    case('control in list name', 'list', reply(b'\0\0\0\0\1evil\n\0'), ok=False, message=b'Protocol error')
    case('excessive count', 'list', reply(b'\0'+struct.pack('!I', 10001)), ok=False, message=b'Protocol error')
    case('truncated count', 'list', reply(b'\0\0\0'), ok=False)
    case('list authentication failure', 'list', reply(b'\1'), ok=False, message=b'Authentication failed')
    for status, text in [(1, b'Authentication failed'), (3, b'already exists')]:
        case('upload preliminary rejection '+str(status), 'upload', upload(CHUNK, preliminary=status),
             payload=CHUNK, ok=False, message=text)
    case('upload final replication failure', 'upload', upload(CHUNK, final=6), payload=CHUNK, ok=False, message=b'Replication failed')
    case('zero upload', 'upload', upload(b''))
    case('local source read failure', 'upload', local_read_failure, payload=CHUNK, read_fault=True, ok=False, message=b'Unable to read')
    case('source shrinks after header', 'upload', local_read_failure, payload=CHUNK, truncate=True, ok=False, message=b'Unable to read')
    case('upload body connection loss, no retry', 'upload', upload_loss, payload=CHUNK, ok=False)
    case('source directory rejected before connect', 'upload', source_directory=True, ok=False, message=b'regular local')
    case('oversize source rejected before connect', 'upload', huge=True, ok=False, message=b'uint32')
    case('zero download', 'download', reply(b'\0\0\0\0\0'), expect_file=b'')
    case('download not found creates nothing', 'download', reply(b'\2'), ok=False, message=b'File not found')
    case('partial download removes staged file', 'download', reply(b'\0'+struct.pack('!I', len(CHUNK))+CHUNK[:17000]), ok=False)
    case('existing destination rejected', 'download', existing=b'keep me', ok=False, message=b'already exists')
    case('existing symlink rejected', 'download', payload=b'keep me', symlink=True, ok=False, message=b'already exists')
    case('destination appears during download', 'download', reply(b'\0\0\0\0\3new'), race=True, ok=False, message=b'already exists')
    case('disk write failure removes staging', 'download', reply(b'\0\0\0\0\3new'), disk_fault=True, ok=False, message=b'Unable to write temporary')
    for status, text in [(1, b'Authentication failed'), (2, b'File not found'), (4, b'malformed'),
                         (5, b'File exceeds'), (6, b'Replication failed'), (7, b'internal error')]:
        case('delete status '+str(status), 'delete', reply(bytes([status])), ok=False, message=text)
    case('unknown status rejected', 'delete', reply(b'\xff'), ok=False, message=b'Protocol error')
    case('certificate failure distinct', 'list', bad_cert=True, ok=False, message=b'verification failed')
    case('connection refused, no failover', 'list', refused=True, ok=False, message=b'TCP connection failed')
    case('wire-overlong password before connect', 'list', long_password=True, ok=False, message=b'printable ASCII')
    case('wire-overlong password executable', 'list', long_password=True, interactive=True, ok=False, message=b'printable ASCII')
    case('executable application error', 'delete', reply(b'\1'), interactive=True, ok=False, message=b'Authentication failed')
    case('executable partial download cleanup', 'download', reply(b'\0\0\0\0\4xx'), interactive=True, ok=False)
    print(f'All {COUNT} TLS command/executable cases passed; temporary fixtures removed on exit.')
