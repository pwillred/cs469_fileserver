#!/usr/bin/env python3
"""Frozen wire boundaries and cross-user write independence; failures are not xfails."""
import argparse
import os
from pathlib import Path
import resource
import socket
import ssl
import struct
import sys
import unittest

sys.dont_write_bytecode = True
from two_node_fixture import Materials, Pair, PASSWORD, run_password_program

# Literal contract limits deliberately do not inherit implementation mistakes.
USERNAME_MAX = 64
FILENAME_MAX = 256
MAX_USER = 'u' * USERNAME_MAX
CONTENT = b'boundary data\x00\xff'


def exact(connection, count):
    result = bytearray()
    while len(result) < count:
        chunk = connection.recv(count - len(result))
        if not chunk:
            raise AssertionError('connection closed before complete response')
        result.extend(chunk)
    return bytes(result)


class ContractBoundaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.materials = Materials(cls.admin, os.environ.get('OPENSSL', 'openssl'))
        cls.addClassCleanup(cls.materials.close)
        for node in ('primary', 'replica'):
            for user in (MAX_USER, 'bob'):
                result = run_password_program(
                    [cls.admin, str(cls.materials.root/node/'users.db'), 'add', user],
                    cls.materials.root, [b'Password: ', b'Confirm password: '])
                if result[0]:
                    raise AssertionError('fixture account creation failed: ' + result[2])

    def setUp(self):
        self.pair = Pair(self.materials, self.server, self.client_binary)
        self.addCleanup(self.pair.close)
        for node in ('primary', 'replica'):
            for user in (MAX_USER, 'bob'):
                directory = self.pair.root/node/'data'/user
                directory.mkdir()
                (directory/'boundary.bin').write_bytes(CONTENT)
        self.pair.replica = self.pair.start('replica')
        # A paused user-A payload must remain pending during user B's client call.
        self.pair.primary = self.pair.start('primary', timeout=15)
        self.addCleanup(self.pair.alive, self._testMethodName)

    def path(self, node, user, name):
        return self.pair.root/node/'data'/user/name

    def connect(self, node):
        raw = socket.create_connection(('127.0.0.1', self.pair.ports[node]), timeout=5)
        return self.pair.tls.wrap_socket(raw, server_hostname='localhost')

    def peer(self):
        context = ssl.create_default_context(cafile=str(self.pair.root/'replica/cert.pem'))
        context.load_cert_chain(self.pair.root/'primary/cert.pem', self.pair.root/'primary/key.pem')
        raw = socket.create_connection(('127.0.0.1', self.pair.ports['replication']), timeout=5)
        return context.wrap_socket(raw, server_hostname='localhost')

    def request(self, verb, user='alice', name=None, size=0):
        data = verb.encode() + user.encode() + b'\0' + PASSWORD + b'\0'
        if verb == 'UPLOAD':
            data += struct.pack('!I', size)
        if name is not None:
            data += name.encode() + b'\0'
        return data

    def peer_delete_status(self, user, name):
        with self.peer() as connection:
            connection.sendall(b'DELETE' + user.encode() + b'\0' + name.encode() + b'\0')
            status = exact(connection, 1)
            if status == b'\0':
                connection.sendall(b'\1')  # ABORT even if an incorrect truncation prepared a sentinel.
                self.assertEqual(exact(connection, 1), b'\0')
            return status

    def test_max_username_actual_client_reads_both_nodes(self):
        for node in ('primary', 'replica'):
            with self.subTest(node=node):
                result = self.pair.client(['list'], node, username=MAX_USER)
                self.assertEqual(result[0], 0, result[2])
                self.assertEqual(result[1], 'boundary.bin\n')
                destination = self.pair.root/('download-' + node)
                result = self.pair.client(['download', 'boundary.bin', destination], node, username=MAX_USER)
                self.assertEqual(result[0], 0, result[2])
                self.assertEqual(destination.read_bytes(), CONTENT)

    def test_over_username_rejected_by_both_client_listeners(self):
        for node in ('primary', 'replica'):
            with self.subTest(node=node), self.connect(node) as connection:
                connection.sendall(self.request('LIST', MAX_USER + 'x'))
                self.assertEqual(exact(connection, 1), b'\4')

    def test_max_filename_read_boundary_and_filesystem_limit(self):
        for node in ('primary', 'replica'):
            with self.subTest(node=node):
                directory = self.path(node, 'alice', '')
                fs_max = os.pathconf(directory, 'PC_NAME_MAX')
                supported = min(FILENAME_MAX, fs_max) if fs_max > 0 else FILENAME_MAX
                sentinel = 'f' * supported
                self.path(node, 'alice', sentinel).write_bytes(CONTENT)
                destination = self.pair.root/('name-download-' + node)
                result = self.pair.client(['download', sentinel, destination], node)
                self.assertEqual(result[0], 0, result[2])
                self.assertEqual(destination.read_bytes(), CONTENT)
                if supported < FILENAME_MAX:
                    # Wire-valid 256 bytes cannot name a file on a NAME_MAX=255
                    # filesystem. Expect filesystem INTERNAL, never BAD_REQUEST
                    # or a successful truncated lookup of the existing sentinel.
                    with self.connect(node) as connection:
                        connection.sendall(self.request('DOWNLOAD', name='f' * FILENAME_MAX))
                        self.assertEqual(exact(connection, 1), b'\7')
                self.assertEqual(self.path(node, 'alice', sentinel).read_bytes(), CONTENT)

    def test_over_filename_rejected_by_both_read_listeners(self):
        for node in ('primary', 'replica'):
            with self.subTest(node=node), self.connect(node) as connection:
                connection.sendall(self.request('DOWNLOAD', name='f' * (FILENAME_MAX + 1)))
                self.assertEqual(exact(connection, 1), b'\4')

    def test_over_filename_rejected_before_primary_upload_payload(self):
        with self.connect('primary') as connection:
            connection.sendall(self.request('UPLOAD', name='f' * (FILENAME_MAX + 1), size=1))
            self.assertEqual(exact(connection, 1), b'\4')
        for node in ('primary', 'replica'):
            self.assertEqual([p.name for p in self.path(node, 'alice', '').iterdir()], ['seed.bin'])

    def test_peer_max_username_prepares_without_truncation(self):
        self.assertEqual(self.peer_delete_status(MAX_USER, 'boundary.bin'), b'\0')
        self.assertEqual(self.path('replica', MAX_USER, 'boundary.bin').read_bytes(), CONTENT)

    def test_peer_over_username_rejected(self):
        self.assertEqual(self.peer_delete_status(MAX_USER + 'x', 'boundary.bin'), b'\4')
        self.assertEqual(self.path('replica', MAX_USER, 'boundary.bin').read_bytes(), CONTENT)

    def test_peer_max_filename_is_parsed_not_rejected(self):
        # DELETE of an absent valid name returns NOT_FOUND even if the host's
        # filesystem cannot represent its full length. No upload staging involved.
        fs_max = os.pathconf(self.path('replica', 'alice', ''), 'PC_NAME_MAX')
        length = min(FILENAME_MAX - 1, fs_max) if fs_max > 0 else FILENAME_MAX - 1
        sentinel = self.path('replica', 'alice', 'f' * length)
        sentinel.write_bytes(CONTENT)
        status = self.peer_delete_status('alice', 'f' * FILENAME_MAX)
        self.assertEqual(sentinel.read_bytes(), CONTENT)
        self.assertEqual(status, b'\2')

    def test_peer_over_filename_rejected(self):
        self.assertEqual(self.peer_delete_status('alice', 'f' * (FILENAME_MAX + 1)), b'\4')

    def test_max_username_actual_replicated_upload(self):
        source = self.pair.root/'source'
        source.write_bytes(CONTENT)
        result = self.pair.client(['upload', source, 'uploaded.bin'], username=MAX_USER)
        self.assertEqual(result[0], 0, result[2])
        for node in ('primary', 'replica'):
            self.assertEqual(self.path(node, MAX_USER, 'uploaded.bin').read_bytes(), CONTENT)

    def test_max_username_actual_replicated_delete(self):
        result = self.pair.client(['delete', 'boundary.bin'], username=MAX_USER)
        self.assertEqual(result[0], 0, result[2])
        for node in ('primary', 'replica'):
            self.assertFalse(self.path(node, MAX_USER, 'boundary.bin').exists())

    def test_filesystem_max_filename_actual_replicated_upload(self):
        limits = [os.pathconf(self.path(node, 'alice', ''), 'PC_NAME_MAX')
                  for node in ('primary', 'replica')]
        supported = min([FILENAME_MAX] + [limit for limit in limits if limit > 0])
        source = self.pair.root/'source'
        source.write_bytes(CONTENT)
        result = self.pair.client(['upload', source, 'f' * supported])
        self.assertEqual(result[0], 0, result[2])
        for node in ('primary', 'replica'):
            self.assertEqual(self.path(node, 'alice', 'f' * supported).read_bytes(), CONTENT)

    def test_different_users_same_filename_progress_independently(self):
        a_bytes, b_bytes = b'alice contents', b'bob contents'
        source = self.pair.root/'bob-source'
        source.write_bytes(b_bytes)
        with self.connect('primary') as alice:
            alice.sendall(self.request('UPLOAD', name='shared.dat', size=len(a_bytes)))
            self.assertEqual(exact(alice, 1), b'\0')
            # Alice owns the key but has not sent payload. Bob must finish,
            # including real replication, before Alice is allowed to continue.
            result = self.pair.client(['upload', source, 'shared.dat'], username='bob')
            self.assertEqual(result[0], 0, result[2])
            for node in ('primary', 'replica'):
                self.assertFalse(self.path(node, 'alice', 'shared.dat').exists())
                self.assertEqual(self.path(node, 'bob', 'shared.dat').read_bytes(), b_bytes)
            alice.sendall(a_bytes)
            self.assertEqual(exact(alice, 1), b'\0')
        for node in ('primary', 'replica'):
            for user, content in (('alice', a_bytes), ('bob', b_bytes)):
                self.assertEqual(self.path(node, user, 'shared.dat').read_bytes(), content)
                self.assertFalse(list(self.path(node, user, '').glob('.temp_*')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('server')
    parser.add_argument('client')
    parser.add_argument('admin')
    parser.add_argument('--match', default='')
    args = parser.parse_args()
    ContractBoundaries.server = str(Path(args.server).resolve())
    ContractBoundaries.client_binary = str(Path(args.client).resolve())
    ContractBoundaries.admin = str(Path(args.admin).resolve())
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    names = [name for name in unittest.defaultTestLoader.getTestCaseNames(ContractBoundaries)
             if args.match in name]
    if not names:
        parser.error('--match selected no tests')
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.TestSuite(ContractBoundaries(name) for name in names))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
