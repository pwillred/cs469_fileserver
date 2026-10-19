#!/usr/bin/env python3
"""Opt-in distributed acceptance tests against production binaries.

Usage: python3 tests/test_two_node_integration.py SERVER CLIENT ADMIN [--match TEXT]
Requires POSIX PTYs, loopback sockets and an OpenSSL CLI (override with OPENSSL).
"""
import argparse
import os
from pathlib import Path
import resource
import signal
import socket
import ssl
import struct
import sys
import unittest

sys.dont_write_bytecode = True
from two_node_fixture import Materials, Pair, PASSWORD, WRONG_PASSWORD, SEED

REPLICATION_ERROR = 'Replication failed; write was not completed.'


class DiagnosticResult(unittest.TextTestResult):
    def _exc_info_to_string(self, err, test):
        text = super()._exc_info_to_string(err, test)
        case = getattr(test, 'test_case', test)
        if hasattr(case, 'pair'):
            text += '\nCaptured node/client diagnostics:\n' + case.pair.diagnostics() + '\n'
        return text


class TwoNodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.materials = Materials(cls.admin, os.environ.get('OPENSSL', 'openssl'))
        cls.addClassCleanup(cls.materials.close)

    def setUp(self):
        self.pair = Pair(self.materials, self.server, self.client_binary)
        self.addCleanup(self.pair.close)
        # No-peer policy test deliberately controls its own startup.
        if self._testMethodName != 'test_19_missing_peer_fails_closed':
            self.pair.start_both()

    def alive(self, scenario):
        self.pair.alive(scenario)

    def expect_client(self, result, status=0, text=None, scenario='client request'):
        # Check cleanup even if the response itself is wrong. Captured client
        # output in the failure report still records the wire-visible symptom.
        self.alive(scenario)
        self.assertEqual(result[0], status, f'{scenario}: unexpected client exit status')
        if text is not None:
            self.assertIn(text, result[1] + result[2], f'{scenario}: wrong response')

    def read_list(self, direct='primary'):
        result = self.pair.client(['list'], direct)
        self.expect_client(result, scenario=f'{direct} LIST response')
        self.assertEqual(result[1], 'seed.bin\n', 'LIST must contain exactly the seeded file')

    def download(self, direct='primary', suffix=''):
        destination = self.pair.root / ('download' + suffix)
        result = self.pair.client(['download', 'seed.bin', destination], direct)
        self.expect_client(result, scenario=f'{direct} DOWNLOAD response')
        self.assertEqual(destination.read_bytes(), SEED, 'Downloaded bytes differ from seed')

    def rejected_write(self, verb):
        source = self.pair.root / 'input'
        source.write_bytes(b'rejected payload')
        args = ['upload', source, 'rejected.bin'] if verb == 'upload' else ['delete', 'seed.bin']
        result = self.pair.client(args, 'replica')
        self.expect_client(result, 1, REPLICATION_ERROR, f'replica rejected {verb.upper()}')
        self.assertEqual(self.pair.file('replica').read_bytes(), SEED)
        self.assertFalse(self.pair.file('replica', 'rejected.bin').exists())

    def test_01_primary_list(self):
        self.read_list()

    def test_02_primary_download(self):
        self.download()

    def test_03_replica_list_survives(self):
        self.read_list('replica')

    def test_04_replica_download_survives(self):
        self.download('replica')

    def test_05_replica_auth_failure_survives(self):
        result = self.pair.client(['list'], 'replica', WRONG_PASSWORD)
        self.expect_client(result, 1, 'Authentication failed.', 'replica AUTH_FAILED response')

    def test_06_replica_rejects_upload_survives(self):
        self.rejected_write('upload')

    def test_07_replica_rejects_delete_survives(self):
        self.rejected_write('delete')

    def test_08_primary_reads_without_replica(self):
        self.pair.replica.stop()
        self.read_list()
        self.download()

    def test_09_actual_client_read_failover(self):
        self.pair.primary.stop()
        result = self.pair.client(['list'])
        self.expect_client(result, 0, 'trying replica', 'primary-down LIST failover')
        self.assertEqual(result[1], 'seed.bin\n')
        self.download(suffix='-failover')

    def replication_connection(self, certificate=None):
        context = ssl.create_default_context(cafile=str(self.pair.root / 'replica/cert.pem'))
        if certificate:
            context.load_cert_chain(self.pair.root / certificate / 'cert.pem',
                                    self.pair.root / certificate / 'key.pem')
        raw = socket.create_connection(('127.0.0.1', self.pair.ports['replication']), timeout=3)
        try:
            return context.wrap_socket(raw, server_hostname='localhost')
        except BaseException:
            raw.close()
            raise

    def test_10_replication_tcp_disconnect_survives(self):
        failure = None
        with socket.create_connection(('127.0.0.1', self.pair.ports['replication']), timeout=3) as connection:
            connection.shutdown(socket.SHUT_WR)
            try:
                # Wait for server-side handling, not merely TCP backlog entry.
                connection.recv(1)
            except ConnectionResetError:
                pass
            except TimeoutError:
                failure = 'Replication listener did not close an incomplete TLS connection within its timeout'
        self.alive('replication TCP connection/disconnect before TLS')
        self.assertIsNone(failure, failure)

    def test_11_valid_replication_tls_survives(self):
        failure = None
        try:
            with self.replication_connection('primary') as connection:
                # Exercise authenticated prepare and a non-destructive abort.
                connection.sendall(b'DELETEalice\0seed.bin\0')
                ready = connection.recv(1)
                if ready != b'\0':
                    failure = f'Expected replica prepare OK, received {ready.hex() or "EOF"}'
                else:
                    connection.sendall(b'\1')  # ABORT; closing also releases the channel.
        except (OSError, ssl.SSLError) as error:
            failure = f'Valid replication TLS/prepare failed: {type(error).__name__}: {error}'
        self.alive('valid replication TLS connection')
        self.assertIsNone(failure, failure)
        self.assertEqual(self.pair.file('replica').read_bytes(), SEED, 'ABORT deleted replica file')

    def test_12_untrusted_replication_peer_rejected_survives(self):
        rejected = False
        try:
            with self.replication_connection('untrusted') as connection:
                # TLS 1.3 may surface client-certificate rejection on the first
                # read rather than wrap_socket. A prepared response is forbidden.
                connection.sendall(b'DELETEalice\0seed.bin\0')
                rejected = connection.recv(1) == b''
        except ssl.SSLError:
            rejected = True
        except ConnectionResetError:
            # A TLS server may reject by closing/resetting the channel. This is
            # acceptable only if it remains alive; test_11 separately requires
            # the trusted peer to complete prepare successfully.
            rejected = True
        except OSError as error:
            self.pair.events.append(f'Untrusted peer socket error: {error}')
        self.alive('untrusted replication peer attempt')
        self.assertTrue(rejected, 'Untrusted peer must be rejected by TLS, not accepted or timed out')
        self.assertEqual(self.pair.file('replica').read_bytes(), SEED)

    def upload(self, content, name, expected_status=0):
        source = self.pair.root / 'upload-source'
        source.write_bytes(content)
        result = self.pair.client(['upload', source, name])
        states = {node: self.pair.file(node, name).exists() for node in ('primary', 'replica')}
        self.pair.events.append(f'UPLOAD final-path existence: {states}')
        if result[0] and any(states.values()):
            self.pair.events.append('Remote state mutation despite client failure')
        if result[0] != expected_status or (expected_status and REPLICATION_ERROR not in result[2]):
            # Diagnostic only: never send body without preliminary acceptance.
            # The actual-client result above remains the acceptance criterion.
            try:
                with self.pair.tls.wrap_socket(socket.create_connection(
                        ('127.0.0.1', self.pair.ports['primary']), timeout=1),
                        server_hostname='localhost') as connection:
                    connection.sendall(b'UPLOADalice\0' + PASSWORD + b'\0' +
                                       struct.pack('!I', 1) + b'header-probe.bin\0')
                    status = connection.recv(1)
                    self.pair.events.append(f'Header-only preliminary status: {status.hex() or "EOF"}')
            except TimeoutError:
                self.pair.events.append('UPLOAD timed out waiting for preliminary status (1s probe; no payload sent)')
            except OSError as error:
                self.pair.events.append(f'UPLOAD preliminary-status probe: {type(error).__name__}: {error}')
        self.expect_client(result, expected_status,
                           REPLICATION_ERROR if expected_status else 'Upload complete.',
                           'UPLOAD preliminary/final status contract')
        if expected_status:
            self.assertFalse(any(states.values()), 'Rejected upload published a final file')
        else:
            for node in ('primary', 'replica'):
                self.assertTrue(states[node], f'Successful UPLOAD absent on {node}')
                self.assertEqual(self.pair.file(node, name).read_bytes(), content,
                                 f'Uploaded bytes differ on {node}')

    def test_13_nonempty_upload_contract(self):
        self.upload(b'upload payload\0\xff', 'uploaded.bin')

    def test_14_zero_byte_upload_contract(self):
        self.upload(b'', 'zero.bin')

    def test_15_upload_replica_unavailable(self):
        self.pair.replica.stop()
        self.upload(b'offline payload', 'offline.bin', expected_status=1)

    def test_16_replicated_delete(self):
        result = self.pair.client(['delete', 'seed.bin'])
        self.expect_client(result, scenario='replicated DELETE')
        for node in ('primary', 'replica'):
            self.assertFalse(self.pair.file(node).exists(), f'DELETE left file on {node}')

    def test_17_delete_replica_unavailable(self):
        self.pair.replica.stop()
        result = self.pair.client(['delete', 'seed.bin'])
        self.expect_client(result, 1, REPLICATION_ERROR, 'DELETE with replica unavailable')
        self.assertEqual(self.pair.file('primary').read_bytes(), SEED, 'Rejected DELETE changed primary')

    def test_18_delete_divergent_replica(self):
        self.pair.file('replica').unlink()
        result = self.pair.client(['delete', 'seed.bin'])
        self.expect_client(result, 1, REPLICATION_ERROR, 'DELETE with missing replica file')
        self.assertEqual(self.pair.file('primary').read_bytes(), SEED, 'Prepare rejection deleted primary')

    def test_19_missing_peer_fails_closed(self):
        # Normal replicated-primary mode must reject startup or reject writes.
        # No invented standalone option and no requirement to add such a mode.
        node = self.pair.start('primary', peer=False, allow_rejection=True)
        if node.process.poll() is not None:
            self.assertGreater(node.process.returncode, 0, 'Missing peer must not crash or exit successfully')
            self.assertRegex(node.stderr_path.read_text(errors='replace'), '(?i)peer|replica',
                             'Startup rejection should explain missing peer configuration')
            return
        result = self.pair.client(['delete', 'seed.bin'])
        self.alive('write with missing peer configuration')
        self.assertNotEqual(result[0], 0,
                            'Distributed write succeeded locally without required peer configuration')
        self.assertIn(REPLICATION_ERROR, result[2])
        self.assertEqual(self.pair.file('primary').read_bytes(), SEED)

    def test_20_ten_replica_lists(self):
        for index in range(10):
            with self.subTest(request=index + 1):
                self.read_list('replica')
            if self.pair.replica.process.poll() is not None:
                break  # Failure already recorded; do not generate nine refused connections.

    def test_21_ten_replica_downloads(self):
        for index in range(10):
            with self.subTest(request=index + 1):
                self.download('replica', suffix=str(index))
            if self.pair.replica.process.poll() is not None:
                break

    def test_22_mixed_replica_requests(self):
        for index in range(3):
            self.read_list('replica')
            result = self.pair.client(['list'], 'replica', WRONG_PASSWORD)
            self.expect_client(result, 1, 'Authentication failed.', f'mixed auth failure {index}')
            self.rejected_write('upload')
            self.rejected_write('delete')
            self.download('replica', suffix=str(index))

    def test_23_repeated_failover_cycles(self):
        for index in range(3):
            self.read_list()
            self.pair.primary.stop()
            result = self.pair.client(['list'])
            self.expect_client(result, 0, 'trying replica', f'failover cycle {index + 1}')
            self.assertEqual(result[1], 'seed.bin\n')
            self.download(suffix=f'-cycle-{index}')
            self.pair.primary = self.pair.start('primary')
            self.alive(f'primary restart cycle {index + 1}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('server')
    parser.add_argument('client')
    parser.add_argument('admin')
    parser.add_argument('--match', default='', help='Run test names containing this text')
    args = parser.parse_args()
    for name in ('server', 'client', 'admin'):
        path = Path(getattr(args, name)).resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            parser.error(f'{name} executable not available: {path}')
        setattr(TwoNodeTests, 'client_binary' if name == 'client' else name, str(path))
    # Unexpected crashes must not leave core files in fixture/repo directories.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    def interrupted(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    names = [name for name in unittest.defaultTestLoader.getTestCaseNames(TwoNodeTests)
             if args.match in name]
    if not names:
        parser.error('--match selected no tests')
    cases = [TwoNodeTests(name) for name in names]
    try:
        result = unittest.TextTestRunner(verbosity=2, resultclass=DiagnosticResult).run(unittest.TestSuite(cases))
        # Count scenarios, not individual subTest failures.
        failed = {getattr(test, 'test_case', test).id() for test, _ in result.failures}
        errors = {getattr(test, 'test_case', test).id() for test, _ in result.errors}
        passed = max(0, result.testsRun - len(failed | errors) - len(result.skipped))
        print(f'TWO-NODE RESULT: {passed} passed, {len(failed)} failed, '
              f'{len(errors)} errors, {len(result.skipped)} skipped; {result.testsRun} scenarios', flush=True)
        return 0 if result.wasSuccessful() else 1
    finally:
        for case in cases:
            if hasattr(case, 'pair'):
                case.pair.close()
        if hasattr(TwoNodeTests, 'materials'):
            TwoNodeTests.materials.close()


if __name__ == '__main__':
    sys.exit(main())
