#!/usr/bin/env python3
"""Focused production ownership, keyed serialization and write-I/O regressions."""
import concurrent.futures
import os
from pathlib import Path
import resource
import socket
import ssl
import struct
import subprocess
import sys
import threading
import unittest

sys.dont_write_bytecode = True
from two_node_fixture import Materials, Pair, PASSWORD

SERVER, CLIENT, ADMIN, FAULT_SERVER = map(lambda p: str(Path(p).resolve()), sys.argv[1:5])
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def exact(connection, size):
    result = b''
    while len(result) < size:
        data = connection.recv(size - len(result))
        if not data:
            raise EOFError('short peer message')
        result += data
    return result


def field(connection):
    result = b''
    while True:
        byte = exact(connection, 1)
        if byte == b'\0':
            return result
        result += byte


class Peer:
    """Trusted scripted participant; only the first target transaction is gated/faulted."""
    def __init__(self, pair, mode):
        self.mode = mode
        self.arrived = threading.Event()
        self.release = threading.Event()
        self.stop = threading.Event()
        self.errors = []
        self.decisions = []
        self.threads = []
        self.mutex = threading.Lock()
        self.claimed = False
        pair.reservations.pop('replication').close()
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', pair.ports['replication']))
        self.listener.listen()
        self.listener.settimeout(.1)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(pair.root/'replica/cert.pem', pair.root/'replica/key.pem')
        self.context.load_verify_locations(pair.root/'primary/cert.pem')
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.thread = threading.Thread(target=self.accept)
        self.thread.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            connection.settimeout(8)
            thread = threading.Thread(target=self.handle, args=(connection,))
            self.threads.append(thread)
            thread.start()

    def handle(self, raw):
        try:
            with self.context.wrap_socket(raw, server_side=True) as connection:
                command = exact(connection, 6)
                field(connection)
                size = struct.unpack('!I', exact(connection, 4))[0] if command == b'UPLOAD' else 0
                name = field(connection)
                with self.mutex:
                    first = name == b'target' and not self.claimed
                    if first:
                        self.claimed = True
                mode = self.mode if first else 'normal'
                if mode == 'drop_body':
                    connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                    return
                exact(connection, size)
                self.arrived.set()
                if mode == 'gate':
                    if not self.release.wait(5):
                        raise AssertionError('test did not release prepared transaction')
                if mode == 'drop_ready':
                    return
                connection.sendall(b'\0')
                decision = exact(connection, 1)
                self.decisions.append(decision)
                if mode == 'drop_confirm':
                    return
                if decision not in (b'\0', b'\1'):
                    raise AssertionError('invalid commit/abort byte')
                connection.sendall(b'\0')
        except BaseException as error:
            self.errors.append(error)
            raw.close()

    def close(self):
        self.release.set()
        self.stop.set()
        self.thread.join(2)
        self.listener.close()
        for thread in self.threads:
            thread.join(10)


class Correctness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.materials = Materials(ADMIN, os.environ.get('OPENSSL', 'openssl'))
        cls.addClassCleanup(cls.materials.close)

    def pair(self, fault=None):
        pair = Pair(self.materials, FAULT_SERVER if fault else SERVER, CLIENT)
        self.addCleanup(pair.close)
        if fault:
            old = os.environ.get('CS469_WRITE_FAULT')
            os.environ['CS469_WRITE_FAULT'] = fault
            try:
                pair.start_both()
            finally:
                if old is None:
                    del os.environ['CS469_WRITE_FAULT']
                else:
                    os.environ['CS469_WRITE_FAULT'] = old
        return pair

    def connect(self, pair):
        raw = socket.create_connection(('127.0.0.1', pair.ports['primary']), timeout=8)
        return pair.tls.wrap_socket(raw, server_hostname='localhost')

    def header(self, verb, name='target', size=0):
        result = verb.encode() + b'alice\0' + PASSWORD + b'\0'
        if verb == 'UPLOAD':
            result += struct.pack('!I', size)
        return result + name.encode() + b'\0'

    def operation(self, pair, verb, name='target', body=b'payload', sent=None, responded=None):
        with self.connect(pair) as connection:
            connection.sendall(self.header(verb, name, len(body)))
            if sent:
                sent.set()
            status = exact(connection, 1)
            if responded:
                responded.set()
            if verb == 'UPLOAD' and status == b'\0':
                connection.sendall(body)
                status = exact(connection, 1)
            return status

    def test_startup_errors_exit_cleanly(self):
        root = self.materials.root
        base = [SERVER, '-p', '4433', '-c', str(root/'primary/cert.pem'),
                '-k', str(root/'primary/key.pem'), '-d', str(root),
                '--auth-db', str(root/'primary/users.db')]
        with socket.socket() as occupied:
            occupied.bind(('0.0.0.0', 0))
            occupied.listen()
            port = str(occupied.getsockname()[1])
            cases = [base[:-2], base + ['--auth-db', '/dev/null'],
                     base + ['--auth-db', str(root/'missing.db')],
                     base + ['-c', str(root/'missing.pem')],
                     base + ['--role', 'invalid'], base + ['--bad-option'],
                     base + ['-p', port],
                     base + ['--role', 'replica'],
                     base + ['--role', 'replica', '--peer-cert', str(root/'missing.pem')],
                     base + ['--role', 'replica', '--peer-cert', str(root/'primary/cert.pem'),
                             '--replication-port', port]]
            for argv in cases:
                with self.subTest(options=argv[1:]):
                    result = subprocess.run(argv, capture_output=True, timeout=10)
                    self.assertGreater(result.returncode, 0, result.stderr)
                    self.assertNotIn(b'Sanitizer', result.stderr)
                    self.assertNotIn(b'runtime error:', result.stderr)

    def test_four_conflicting_write_orders(self):
        for first, second in [('UPLOAD', 'UPLOAD'), ('UPLOAD', 'DELETE'),
                              ('DELETE', 'UPLOAD'), ('DELETE', 'DELETE')]:
            with self.subTest(first=first, second=second):
                pair = self.pair()
                if first == 'DELETE':
                    pair.file('primary', 'target').write_bytes(b'old')
                peer = Peer(pair, 'gate')
                self.addCleanup(peer.close)
                pair.primary = pair.start('primary')
                with concurrent.futures.ThreadPoolExecutor(3) as pool:
                    one = pool.submit(self.operation, pair, first)
                    self.assertTrue(peer.arrived.wait(3))
                    sent, responded = threading.Event(), threading.Event()
                    two = pool.submit(self.operation, pair, second, 'target', b'second', sent, responded)
                    self.assertTrue(sent.wait(3))
                    try:
                        self.assertFalse(responded.wait(.2), 'conflicting request escaped keyed lock')
                        # A different filename must complete while target is held.
                        self.assertEqual(self.operation(pair, 'UPLOAD', 'independent'), b'\0')
                        self.assertFalse(responded.is_set())
                    finally:
                        peer.release.set()
                    self.assertEqual(one.result(timeout=5), b'\0')
                    self.assertEqual(two.result(timeout=5), b'\2' if first == second == 'DELETE' else b'\0')
                pair.alive('serialized write order')
                self.assertFalse(list((pair.root/'primary/data/alice').glob('.temp_*')))
                peer.close()
                self.assertFalse(peer.errors, peer.errors)
                pair.close()

    def test_peer_disconnect_cleanup_and_lock_release(self):
        for mode in ('drop_body', 'drop_ready', 'drop_confirm'):
            with self.subTest(mode=mode):
                pair = self.pair()
                peer = Peer(pair, mode)
                self.addCleanup(peer.close)
                pair.primary = pair.start('primary')
                body = b'x' * (4 * 1024 * 1024) if mode == 'drop_body' else b'payload'
                self.assertEqual(self.operation(pair, 'UPLOAD', body=body), b'\6')
                pair.alive(mode)
                # Acknowledgement loss can follow local commit; no rollback claim.
                self.assertEqual(pair.file('primary', 'target').exists(), mode == 'drop_confirm')
                self.assertEqual(self.operation(pair, 'UPLOAD'), b'\0')
                pair.alive('same key reused after peer failure')
                self.assertFalse(list((pair.root/'primary/data/alice').glob('.temp_*')))
                peer.close()
                self.assertFalse(peer.errors, peer.errors)
                pair.close()

    def test_delete_disconnect_cleanup(self):
        for mode in ('drop_ready', 'drop_confirm'):
            with self.subTest(mode=mode):
                pair = self.pair()
                pair.file('primary', 'target').write_bytes(b'old')
                peer = Peer(pair, mode)
                self.addCleanup(peer.close)
                pair.primary = pair.start('primary')
                self.assertEqual(self.operation(pair, 'DELETE'), b'\6')
                self.assertEqual(pair.file('primary', 'target').exists(), mode == 'drop_ready')
                pair.file('primary', 'target').write_bytes(b'retry')
                self.assertEqual(self.operation(pair, 'DELETE'), b'\0')
                pair.alive('delete disconnect then same-key reuse')
                peer.close()
                self.assertFalse(peer.errors, peer.errors)
                pair.close()

    def test_local_commit_failure_aborts_and_cleans_up(self):
        for verb in ('UPLOAD', 'DELETE'):
            with self.subTest(verb=verb):
                pair = self.pair()
                target = pair.file('primary', 'target')
                if verb == 'DELETE':
                    target.write_bytes(b'old')
                peer = Peer(pair, 'gate')
                self.addCleanup(peer.close)
                pair.primary = pair.start('primary')
                with concurrent.futures.ThreadPoolExecutor(1) as pool:
                    pending = pool.submit(self.operation, pair, verb)
                    try:
                        self.assertTrue(peer.arrived.wait(3))
                        if target.exists():
                            target.unlink()
                        target.mkdir()  # force rename/unlink failure after prepare
                    finally:
                        peer.release.set()
                    self.assertEqual(pending.result(timeout=5), b'\7')
                peer.close()
                self.assertIn(b'\1', peer.decisions)
                self.assertFalse(list(target.parent.glob('.temp_*')))
                pair.alive('local commit failure/abort')
                pair.close()

    def test_local_write_faults(self):
        for fault in ('fwrite_short', 'fwrite_zero', 'fwrite_error', 'fclose_error',
                      'write_short', 'write_eintr', 'write_zero', 'write_error'):
            with self.subTest(fault=fault):
                pair = self.pair(fault)
                successful = fault in ('fwrite_short', 'write_short', 'write_eintr')
                status = self.operation(pair, 'UPLOAD', body=b'abcdefghij' * 20)
                self.assertEqual(status, b'\0' if successful else
                                 b'\6' if fault.startswith('write_') else b'\7')
                pair.alive(fault)
                for node in ('primary', 'replica'):
                    path = pair.file(node, 'target')
                    self.assertEqual(path.exists(), successful)
                    if successful:
                        self.assertEqual(path.read_bytes(), b'abcdefghij' * 20)
                    self.assertFalse(list(path.parent.glob('.temp_*')))
                pair.close()

    def test_partial_payload_cleanup_and_lock_release(self):
        pair = self.pair()
        pair.start_both()
        with self.connect(pair) as connection:
            connection.sendall(self.header('UPLOAD', size=100))
            self.assertEqual(exact(connection, 1), b'\0')
            connection.sendall(b'partial')
        # The next same-key request can proceed only after failed upload cleanup.
        self.assertEqual(self.operation(pair, 'UPLOAD'), b'\0')
        pair.alive('partial upload then same-key retry')
        for node in ('primary', 'replica'):
            self.assertEqual(pair.file(node, 'target').read_bytes(), b'payload')
            self.assertFalse(list(pair.file(node).parent.glob('.temp_*')))


unittest.main(argv=[sys.argv[0]], verbosity=2)
