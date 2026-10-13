#!/usr/bin/env python3
"""Real isolated C handlers over TLS, plus actual client via a hidden PTY prompt."""
import concurrent.futures
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
import time

FIXTURE, CLIENT = map(os.path.abspath, sys.argv[1:3])
COUNT = 0

def check(value, message):
    if not value:
        raise AssertionError(message)

with tempfile.TemporaryDirectory(prefix='cs469-server-reads-') as temporary:
    root = Path(temporary)
    data = root / 'data'
    data.mkdir()
    db = root / 'users.db'
    subprocess.run([FIXTURE, '--init', str(db)], check=True, timeout=15)
    cert, key = root / 'cert.pem', root / 'key.pem'
    openssl = os.environ.get('OPENSSL', shutil.which('openssl'))
    # A private test CA/leaf in one self-signed certificate, trusted only here.
    config = root / 'cert.cnf'
    config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n'
                      '[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n'
                      'basicConstraints=critical,CA:TRUE\nextendedKeyUsage=serverAuth\n')
    subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-config', str(config), '-keyout', str(key), '-out', str(cert)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tls = ssl.create_default_context(cafile=str(cert))

    @contextlib.contextmanager
    def server(database=db, directory=data):
        p = subprocess.Popen([FIXTURE, str(cert), str(key), str(directory), str(database)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            check(select.select([p.stdout], [], [], 10)[0], 'fixture startup timeout')
            line = p.stdout.readline()
            check(line.strip().isdigit(), 'fixture startup failed: ' + str(p.stderr.read() if p.poll() is not None else line))
            yield int(line)
        finally:
            p.stdin.close()
            try:
                p.wait(timeout=15)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
                raise
            errors = p.stderr.read()
            check(p.returncode == 0, f'fixture exit {p.returncode}: {errors!r}')
            check(b'Sanitizer' not in errors and b'runtime error:' not in errors, str(errors))
            p.stdout.close()
            p.stderr.close()

    def request(verb=b'LIST', user=b'alice', password=b'secret', name=b'file.txt'):
        return verb + user + b'\0' + password + b'\0' + (name + b'\0' if verb == b'DOWNLOAD' else b'')

    def exchange(port, message, fragment=False):
        with socket.create_connection(('127.0.0.1', port), timeout=7) as raw:
            with tls.wrap_socket(raw, server_hostname='localhost') as connection:
                if fragment:
                    for byte in message:
                        connection.sendall(bytes([byte]))
                        time.sleep(.001)
                else:
                    connection.sendall(message)
                output = bytearray()
                while True:
                    part = connection.recv(65536)
                    if not part:
                        return bytes(output)
                    output.extend(part)

    def expect(port, message, expected, fragment=False):
        global COUNT
        got = exchange(port, message, fragment)
        check(got == expected, f'wire mismatch case {COUNT}: {got[:40]!r} vs {expected[:40]!r}')
        COUNT += 1

    def listed(*names):
        return b'\0' + struct.pack('!I', len(names)) + b''.join(name + b'\0' for name in names)

    def downloaded(content):
        return b'\0' + struct.pack('!I', len(content)) + content

    def client(port, args, password=b'secret'):
        conf = root / 'client.conf'
        conf.write_text(f'primary_host=localhost\nprimary_port={port}\nreplica_host=localhost\n'
                        f'replica_port={port}\nca_file={cert}\n')
        master, slave = pty.openpty()
        p = subprocess.Popen([CLIENT, '--config', str(conf), '--username', 'alice', *args],
                             stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.close(slave)
        try:
            prompt = bytearray()
            deadline = time.monotonic() + 10
            while b'Password: ' not in prompt:
                check(time.monotonic() < deadline, 'client prompt timeout')
                if select.select([p.stderr], [], [], .1)[0]:
                    part = os.read(p.stderr.fileno(), 1024)
                    check(part, 'client exited before prompt')
                    prompt.extend(part)
            os.write(master, password + b'\n')
            out, err = p.communicate(timeout=15)
            err = bytes(prompt) + err
            check(err.count(b'Password: ') == 1 and password not in out + err, 'prompt/password leak')
            if select.select([master], [], [], 0)[0]:
                try:
                    echo = os.read(master, 4096)
                except OSError:
                    echo = b''
                check(password not in echo, 'echoed password')
            return p.returncode, out, err
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
            os.close(master)

    with server() as port:
        expect(port, request(), listed())  # missing user directory
        expect(port, request(b'DOWNLOAD'), b'\2')
        alice, bob = data / 'alice', data / 'bob'
        alice.mkdir()
        bob.mkdir()
        expect(port, request(), listed())
        payload = bytes(range(256)) * 300  # multiple bounded chunks, nontrivial BE size
        (alice / 'file.txt').write_bytes(payload)
        expect(port, request(), listed(b'file.txt'))
        expect(port, request(b'DOWNLOAD'), downloaded(payload))
        (alice / 'empty').touch()
        expect(port, request(b'DOWNLOAD', name=b'empty'), downloaded(b''))
        (alice / 'Z').write_text('z')
        (alice / '.visible').write_text('dotfile')
        (alice / '.temp_pending').write_text('uncommitted')
        (alice / 'subdir').mkdir()
        (alice / 'link').symlink_to('file.txt')
        (bob / 'bob-only').write_text('private')
        (alice / 'escape').symlink_to(bob / 'bob-only')
        os.mkfifo(alice / 'fifo')
        (alice / 'bad\nname').touch()
        expected = listed(b'.visible', b'Z', b'empty', b'file.txt')
        expect(port, request(), expected)
        expect(port, request(), expected, True)
        expect(port, request(b'DOWNLOAD'), downloaded(payload), True)
        expect(port, request(b'DOWNLOAD', name=b'.visible'), downloaded(b'dotfile'))
        for name in [b'missing', b'subdir', b'link', b'escape', b'fifo', b'.temp_pending', b'bob-only']:
            expect(port, request(b'DOWNLOAD', name=name), b'\2')
        for name in [b'', b'.', b'..', b'../bob/bob-only', b'a/b', b'a\\b', b'bad\nname', b'\x7f', b'\xff', b'x'*257]:
            expect(port, request(b'DOWNLOAD', name=name), b'\4')
        for user in [b'', b'../bob', b'a/b', b'a\\b', b'u'*65, b'\xff']:
            expect(port, request(user=user), b'\4')
        for password in [b'', b'p'*65, b'\n', b'\xff']:
            expect(port, request(password=password), b'\4')
        expect(port, b'LIST' + b'u'*65, b'\4')
        expect(port, b'LISTalice\0' + b'p'*65, b'\4')
        expect(port, request(password=b'wrong'), b'\1')
        expect(port, request(user=b'unknown'), b'\1')
        expect(port, request(user=b'u'*64, password=b'p'*64), listed())
        expect(port, request(user=b'bob'), listed(b'bob-only'))
        expect(port, request(b'DOWNLOAD', user=b'bob', name=b'bob-only'), downloaded(b'private'))
        with (alice / 'huge').open('wb') as f:
            f.truncate(2**32)
        expect(port, request(b'DOWNLOAD', name=b'huge'), b'\5')
        (alice / 'huge').unlink()
        if os.geteuid() != 0:
            alice.chmod(0)
            try:
                expect(port, request(), b'\7')
                expect(port, request(b'DOWNLOAD'), b'\7')
            finally:
                alice.chmod(0o700)
            (alice / 'file.txt').chmod(0)
            try:
                expect(port, request(b'DOWNLOAD'), b'\7')
            finally:
                (alice / 'file.txt').chmod(0o600)
        else:
            print('SKIP: permission denials when running as root')
        maxdir = data / ('u'*64)
        maxdir.symlink_to(bob, target_is_directory=True)
        expect(port, request(user=b'u'*64, password=b'p'*64), b'\7')
        expect(port, request(b'DOWNLOAD', user=b'u'*64, password=b'p'*64, name=b'bob-only'), b'\7')
        maxdir.unlink()
        # LIST count bytes tested with a count >255, then the actual limit boundary.
        for i in range(10000):
            (bob / f'x{i:05}').touch()
        expect(port, request(user=b'bob'), b'\7')  # 10001, includes bob-only
        (bob / 'bob-only').unlink()
        expect(port, request(user=b'bob'), listed(*(f'x{i:05}'.encode() for i in range(10000))))
        # Independent per-thread SSL, DB, iteration and file state, mixed operations.
        jobs = [(request(), expected), (request(b'DOWNLOAD'), downloaded(payload))] * 6
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda item: exchange(port, item[0]), jobs))
        check(all(got == item[1] for got, item in zip(results, jobs)), 'concurrent handler result')
        COUNT += len(jobs)
        rc, out, err = client(port, ['list'])
        check(rc == 0 and out == b'.visible\nZ\nempty\nfile.txt\n', f'actual client LIST: {err!r}')
        destination = root / 'received.bin'
        rc, out, err = client(port, ['download', 'file.txt', str(destination)])
        check(rc == 0 and destination.read_bytes() == payload, f'actual client DOWNLOAD: {err!r}')
        for args in [['list'], ['download', 'file.txt', str(root/'denied')]]:
            rc, out, err = client(port, args, b'wrong')
            check(rc != 0 and b'Authentication failed' in err, 'actual client auth failure')
        rc, out, err = client(port, ['download', 'missing', str(root/'missing')])
        check(rc != 0 and b'File not found' in err and not (root/'missing').exists(), 'actual client missing')
        # Real transport stall is bounded by the adapter's request deadline.
        started = time.monotonic()
        expect(port, b'LISTalice\0part', b'')
        check(time.monotonic() - started < 6, 'request deadline not enforced')
        # Reset during a large response: fixture must survive and service next call.
        with (alice/'large').open('wb') as f:
            f.truncate(32*1024*1024)
        raw = socket.create_connection(('127.0.0.1', port), timeout=5)
        conn = tls.wrap_socket(raw, server_hostname='localhost')
        conn.sendall(request(b'DOWNLOAD', name=b'large'))
        check(conn.recv(1) == b'\0', 'reset test initial status')
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        conn.close()
        (alice/'large').unlink()
        expect(port, request(), expected)
    with server(database=root/'absent.db') as port:
        expect(port, request(), b'\7')
        check(not (root/'absent.db').exists(), 'auth created DB')
    with server(directory=root/'absent-root') as port:
        expect(port, request(), b'\7')
    print(f'PASS: {COUNT} TLS read checks including 12 concurrent operations; 5 actual client/PTY cases')
