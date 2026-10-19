#!/usr/bin/env python3
"""Production executable tests; writes assert only the existing local behavior."""
import concurrent.futures
import contextlib
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import tempfile
import time

SERVER, CLIENT, PROVISION = map(os.path.abspath, sys.argv[1:4])
COUNT = 0

def check(ok, message):
    if not ok:
        raise AssertionError(message)

def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

with tempfile.TemporaryDirectory(prefix='cs469-production-') as directory:
    root = Path(directory)
    data = root/'data'
    data.mkdir()
    db = root/'users.db'
    subprocess.run([PROVISION, '--init', str(db)], check=True, timeout=15)
    cert, key = root/'cert.pem', root/'key.pem'
    conf = root/'cert.cnf'
    conf.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n'
                    '[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n'
                    'basicConstraints=critical,CA:TRUE\nextendedKeyUsage=serverAuth\n')
    subprocess.run([os.environ.get('OPENSSL', shutil.which('openssl')), 'req', '-x509',
                    '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-config', str(conf),
                    '-keyout', str(key), '-out', str(cert)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tls = ssl.create_default_context(cafile=str(cert))

    def args(port, database=db):
        return [SERVER, '-p', str(port), '-c', str(cert), '-k', str(key), '-d', str(data),
                '--timeout', '3', '--auth-db', str(database)]

    def startup_failure(arguments, text):
        global COUNT
        p = subprocess.run(arguments, capture_output=True, timeout=10)
        check(p.returncode > 0 and text in p.stderr, f'expected clean startup failure: {p.returncode}: {p.stderr!r}')
        check(b'Sanitizer' not in p.stderr and b'runtime error:' not in p.stderr, str(p.stderr))
        COUNT += 1

    startup_failure(args(free_port())[:-2], b'--auth-db')
    startup_failure(args(free_port(), ''), b'--auth-db')
    absent = root/'absent.db'
    startup_failure(args(free_port(), absent), b'preflight failed')
    check(not absent.exists(), 'missing DB created')
    for label, content in [('empty', b''), ('corrupt', b'not a database')]:
        path = root/(label+'.db')
        path.write_bytes(content)
        startup_failure(args(free_port(), path), b'preflight failed')
        check(path.read_bytes() == content, 'preflight modified invalid DB')
    bad_schema = root/'bad-schema.db'
    with sqlite3.connect(bad_schema) as connection:
        connection.execute('CREATE TABLE users (username TEXT)')
    startup_failure(args(free_port(), bad_schema), b'preflight failed')
    startup_failure(args(free_port(), data), b'preflight failed')
    for value in ['0', '-1', '2147483648', '3x']:
        startup_failure(args(free_port()) + ['--timeout', value], b'Usage:')
    startup_failure(args(free_port()) + ['-p', '65536'], b'Usage:')

    @contextlib.contextmanager
    def server(database=db):
        port = free_port()
        p = subprocess.Popen(args(port, database), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            check(select.select([p.stdout], [], [], 10)[0], 'startup timeout')
            check(p.stdout.readline().startswith(b'Server listening'), 'server did not start')
            yield port, p
        finally:
            if p.poll() is None:
                p.send_signal(signal.SIGTERM)
            try:
                p.wait(timeout=12)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
                raise
            errors = p.stderr.read()
            check(p.returncode == 0, f'server exit {p.returncode}: {errors!r}')
            check(b'Sanitizer' not in errors and b'runtime error:' not in errors, str(errors))
            p.stdout.close()
            p.stderr.close()

    def connect(port):
        return tls.wrap_socket(socket.create_connection(('127.0.0.1', port), timeout=8),
                               server_hostname='localhost')

    def collect(connection):
        result = bytearray()
        while True:
            part = connection.recv(65536)
            if not part:
                return bytes(result)
            result.extend(part)

    def request(verb=b'LIST', user=b'alice', password=b'secret', name=b'file', size=0):
        message = verb + user + b'\0' + password + b'\0'
        if verb == b'UPLOAD':
            message += struct.pack('!I', size)
        if verb != b'LIST':
            message += name + b'\0'
        return message

    def exchange(port, message, fragmented=False):
        with connect(port) as connection:
            if fragmented:
                for b in message:
                    connection.sendall(bytes([b]))
                    time.sleep(.001)
            else:
                connection.sendall(message)
            return collect(connection)

    def expect(port, message, expected, fragmented=False):
        global COUNT
        got = exchange(port, message, fragmented)
        check(got == expected, f'wire mismatch case {COUNT}: {got[:40]!r} vs {expected[:40]!r}')
        COUNT += 1

    def run_client(port, command, password=b'secret'):
        config = root/'client.conf'
        config.write_text(f'primary_host=localhost\nprimary_port={port}\nreplica_host=localhost\n'
                          f'replica_port={port}\nca_file={cert}\n')
        master, slave = pty.openpty()
        p = subprocess.Popen([CLIENT, '--config', str(config), '--username', 'alice', *command],
                             stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.close(slave)
        try:
            prompt = bytearray()
            deadline = time.monotonic() + 10
            while b'Password: ' not in prompt:
                check(time.monotonic() < deadline, 'prompt timeout')
                if select.select([p.stderr], [], [], .1)[0]:
                    piece = os.read(p.stderr.fileno(), 1024)
                    check(piece, 'client quit before prompting')
                    prompt.extend(piece)
            os.write(master, password + b'\n')
            out, err = p.communicate(timeout=15)
            err = bytes(prompt) + err
            check(err.count(b'Password: ') == 1 and password not in out + err, 'password prompt/leak')
            if select.select([master], [], [], 0)[0]:
                try:
                    echo = os.read(master, 4096)
                except OSError:
                    echo = b''
                check(password not in echo, 'password echoed')
            return p.returncode, out, err
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
            os.close(master)

    before = db.read_bytes()
    with server() as (port, process):
        expect(port, request(), b'\0\0\0\0\0')
        (data/'alice').mkdir()
        payload = bytes(range(256))*300
        (data/'alice'/'file').write_bytes(payload)
        listing = b'\0\0\0\0\1file\0'
        download = b'\0'+struct.pack('!I', len(payload))+payload
        expect(port, request(), listing)
        expect(port, request(), listing, True)
        expect(port, request(b'DOWNLOAD'), download)
        expect(port, request(b'DOWNLOAD'), download, True)
        expect(port, request(b'DOWNLOAD', name=b'absent'), b'\2')
        for command in [b'LIST', b'DOWNLOAD', b'UPLOAD', b'DELETE']:
            expect(port, request(command, password=b'wrong'), b'\1')
            expect(port, request(command, user=b'unknown'), b'\1')
            expect(port, request(command, user=b'../alice'), b'\4')
            expect(port, request(command, password=b'p'*65), b'\4')
            expect(port, request(command, password=b'bad\n'), b'\4')
        for command in [b'NOPE', b'DOWNX', b'UPLOXD', b'DELX', b'LIST\0secret\0']:
            expect(port, command, b'\4')
        # No delimiter exists after a verb: this is LIST for username Xalice,
        # not an extended LISTX command. Reject at authentication, not misdispatch.
        expect(port, b'LISTXalice\0secret\0', b'\1')
        expect(port, request(user=b'u'*64, password=b'p'*64), b'\0\0\0\0\0')
        expect(port, request(user=b'u'*65), b'\4')
        expect(port, request(b'DELETE', name=b'absent'), b'\2', True)
        # Local write regression only. No peer, commit or replicated-success claim.
        expect(port, request(b'UPLOAD', name=b'uploaded', size=4)+b'data', b'\0\6', True)
        check(not (data/'alice'/'uploaded').exists(), 'no local mutation on replication failure')
        expect(port, request(b'DELETE', name=b'uploaded'), b'\2')
        check(not (data/'alice'/'uploaded').exists(), 'local delete regression')

        jobs = [(request(), listing), (request(b'DOWNLOAD'), download)]*6
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            responses = list(pool.map(lambda item: exchange(port, item[0]), jobs))
        check(all(got == job[1] for got, job in zip(responses, jobs)), 'concurrent reads')
        COUNT += len(jobs)
        rc, out, err = run_client(port, ['list'])
        check(rc == 0 and out == b'file\n', f'client LIST: {err!r}')
        destination = root/'downloaded'
        rc, out, err = run_client(port, ['download', 'file', str(destination)])
        check(rc == 0 and destination.read_bytes() == payload, f'client DOWNLOAD: {err!r}')
        for command in [['list'], ['download', 'file', str(root/'denied')]]:
            rc, out, err = run_client(port, command, b'wrong')
            check(rc != 0 and b'Authentication failed' in err, 'real client auth failure')
        rc, out, err = run_client(port, ['download', 'absent', str(root/'absent')])
        check(rc != 0 and b'File not found' in err and not (root/'absent').exists(), 'real client missing file')
        
        process.send_signal(signal.SIGTERM)
        time.sleep(.7)
        try: 
            unexpected = socket.create_connection(('127.0.0.1', port), timeout=1)
        except OSError:
            pass
        else:
            unexpected.close()
            raise AssertionError('listener still open after shutdown')
        process.wait(timeout=8)
    check(db.read_bytes() == before, 'production startup/auth modified DB')
    # Valid but empty provisioned database must be accepted.
    empty_db = root/'valid-empty.db'
    shutil.copyfile(db, empty_db)
    with sqlite3.connect(empty_db) as connection:
        connection.execute('DELETE FROM users')
    with server(empty_db) as (port, process):
        expect(port, request(), b'\1')
    print(f'PASS: {COUNT} production startup/wire checks; 5 actual client PTY cases; '
          'legacy local-write framing, no preliminary OK, 12 concurrent reads and active-worker shutdown')
