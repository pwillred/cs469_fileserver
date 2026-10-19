"""POSIX production-binary fixtures for the opt-in two-node acceptance suite."""
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import time

USER = 'alice'
PASSWORD = b'two-node-test-password'
WRONG_PASSWORD = b'wrong-test-password'
SEED = b'two-node seed\x00\xff\n'
CLIENT_TIMEOUT = 15


def safe_text(data):
    if isinstance(data, (bytes, bytearray)):
        data = data.decode(errors='replace')
    return data.replace(PASSWORD.decode(), '<redacted>').replace(
        WRONG_PASSWORD.decode(), '<redacted>')


def exit_description(code):
    if code is None:
        return 'running'
    if code < 0:
        try:
            return f'{code} ({signal.Signals(-code).name})'
        except ValueError:
            pass
    return str(code)


def wait_for_exit(process, timeout):
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        if wait_for_exit(process, 5) is None:
            process.kill()
            process.wait(timeout=5)


def run_password_program(argv, cwd, prompts, password=PASSWORD):
    """Wait for each hidden-input prompt before writing to its PTY; always reap."""
    master, slave = pty.openpty()
    process = None
    seen = bytearray()
    try:
        process = subprocess.Popen(argv, cwd=cwd, stdin=slave,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.close(slave)
        slave = None
        for prompt in prompts:
            deadline = time.monotonic() + CLIENT_TIMEOUT
            while prompt not in seen:
                if time.monotonic() >= deadline:
                    raise AssertionError(f'Timed out waiting for {prompt.decode().strip()}')
                if select.select([process.stderr], [], [], .05)[0]:
                    chunk = os.read(process.stderr.fileno(), 4096)
                    if not chunk:
                        raise AssertionError('Program exited before password prompt: ' + safe_text(seen))
                    seen.extend(chunk)
            os.write(master, password + b'\n')
        try:
            stdout, stderr = process.communicate(timeout=CLIENT_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise AssertionError('Actual executable timed out; operation did not complete') from None
        stderr = bytes(seen) + stderr
        if password in stdout + stderr:
            raise AssertionError('Executable leaked the fixture password (output suppressed)')
        return process.returncode, safe_text(stdout), safe_text(stderr)
    finally:
        if process is not None:
            stop_process(process)
            process.stdout.close()
            process.stderr.close()
        if slave is not None:
            os.close(slave)
        os.close(master)


class Materials:
    """Generate credentials independently with admin; reuse immutable templates."""
    def __init__(self, admin, openssl):
        self.temporary = tempfile.TemporaryDirectory(prefix='cs469-two-node-materials-')
        self.root = Path(self.temporary.name)
        try:
            executable = shutil.which(openssl)
            if executable is None:
                raise AssertionError(f'OpenSSL CLI unavailable: {openssl}; set OPENSSL')
            for name in ('primary', 'replica', 'untrusted'):
                directory = self.root / name
                directory.mkdir(mode=0o700)
                config = directory / 'openssl.cnf'
                config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n'
                                  f'[dn]\nCN={name}.localhost\n[ext]\n'
                                  'subjectAltName=DNS:localhost,IP:127.0.0.1\n'
                                  'basicConstraints=critical,CA:TRUE\n'
                                  'extendedKeyUsage=serverAuth,clientAuth\n')
                result = subprocess.run([executable, 'req', '-x509', '-newkey', 'rsa:2048',
                                         '-nodes', '-days', '1', '-config', str(config),
                                         '-keyout', str(directory / 'key.pem'),
                                         '-out', str(directory / 'cert.pem')],
                                        capture_output=True, timeout=30)
                if result.returncode:
                    raise AssertionError('OpenSSL could not generate temporary dual-purpose certificates: '
                                         + safe_text(result.stderr)[-2000:])
                (directory / 'key.pem').chmod(0o600)
                if name == 'untrusted':
                    continue
                db = directory / 'users.db'
                result = subprocess.run([admin, str(db), 'init'], capture_output=True, timeout=15)
                if result.returncode:
                    raise AssertionError('Admin init failed: ' + safe_text(result.stderr))
                result = run_password_program([admin, str(db), 'add', USER], self.root,
                                              [b'Password: ', b'Confirm password: '])
                if result[0]:
                    raise AssertionError('Admin add failed: ' + result[2])
            (self.root / 'trust.pem').write_bytes(
                (self.root / 'primary/cert.pem').read_bytes() +
                (self.root / 'replica/cert.pem').read_bytes())
            # Distinct issuer names avoid ambiguous same-subject self-signed
            # roots. Validate trust/identity before attributing failures to C.
            for name in ('primary', 'replica'):
                result = subprocess.run([executable, 'verify', '-CAfile',
                                         str(self.root / 'trust.pem'), '-verify_ip', '127.0.0.1',
                                         str(self.root / name / 'cert.pem')],
                                        capture_output=True, timeout=10)
                if result.returncode:
                    raise AssertionError('Fixture certificate verification failed: ' + safe_text(result.stderr))
        except BaseException:
            self.close()
            raise

    def close(self):
        self.temporary.cleanup()


class Node:
    def __init__(self, name, argv, root):
        self.name = name
        self.stdout_path = root / f'{name}.stdout'
        self.stderr_path = root / f'{name}.stderr'
        with self.stdout_path.open('wb') as out, self.stderr_path.open('wb') as err:
            self.process = subprocess.Popen(argv, cwd=root, stdout=out, stderr=err)
        self.stopped = False

    def diagnostic(self):
        return (f'{self.name} exit={exit_description(self.process.poll())}\n'
                f'  stdout: {safe_text(self.stdout_path.read_bytes())[-4000:] or "<empty>"}\n'
                f'  stderr: {safe_text(self.stderr_path.read_bytes())[-10000:] or "<empty>"}')

    def stop(self):
        self.stopped = True
        stop_process(self.process)


def wait_for_port(node, ports, timeout=8):
    """Use the post-bind/listen banner, not a destructive TCP readiness probe.

    The production banner is flushed after all requested listeners are bound.
    Using it avoids introducing an extra worker into the scenario under test.
    Actual TCP/TLS connections are made by the test under examination.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if node.process.poll() is not None:
            raise AssertionError('Server exited before listener readiness\n' + node.diagnostic())
        output = node.stdout_path.read_text(errors='replace')
        if 'Server listening on port' in output and all(str(port) in output for port in ports):
            return
        time.sleep(.02)
    raise AssertionError('Timed out waiting for listener readiness\n' + node.diagnostic())


def assert_process_alive(node, scenario):
    # Bounded wait observes asynchronous worker cleanup after the response. A
    # mere poll immediately after recv can miss a fatal free in that worker.
    code = wait_for_exit(node.process, .3)
    if code is not None:
        raise AssertionError(f'{node.name} exited with {exit_description(code)} after {scenario}')
    errors = node.stderr_path.read_text(errors='replace')
    if 'Sanitizer' in errors or 'runtime error:' in errors:
        raise AssertionError(f'{node.name} reported sanitizer diagnostics after {scenario}')


class Pair:
    def __init__(self, materials, server, client):
        self.temporary = tempfile.TemporaryDirectory(prefix='cs469-two-node-case-')
        self.root = Path(self.temporary.name)
        self.server, self.client_binary = server, client
        self.nodes = []
        self.events = []
        self.reservations = {}
        try:
            for name in ('primary', 'replica'):
                shutil.copytree(materials.root / name, self.root / name)
                directory = self.root / name / 'data' / USER
                directory.mkdir(parents=True)
                (directory / 'seed.bin').write_bytes(SEED)
            shutil.copytree(materials.root / 'untrusted', self.root / 'untrusted')
            shutil.copyfile(materials.root / 'trust.pem', self.root / 'trust.pem')
            # Reserve all three distinct ephemeral ports until their node starts.
            self.ports = {}
            for name in ('primary', 'replica', 'replication'):
                sock = socket.socket()
                self.reservations[name] = sock
                sock.bind(('127.0.0.1', 0))
                self.ports[name] = sock.getsockname()[1]
            self.tls = ssl.create_default_context(cafile=str(self.root / 'trust.pem'))
        except BaseException:
            self.close()
            raise

    def start(self, name, peer=True, allow_rejection=False, timeout=2):
        for key in ([name, 'replication'] if name == 'replica' else [name]):
            reservation = self.reservations.pop(key, None)
            if reservation:
                reservation.close()
        directory = self.root / name
        argv = [self.server, '-p', str(self.ports[name]), '-c', str(directory / 'cert.pem'),
                '-k', str(directory / 'key.pem'), '-d', str(directory / 'data'),
                '--auth-db', str(directory / 'users.db'), '--role', name,
                '--replication-port', str(self.ports['replication']),
                '--coordinator-name', '127.0.0.1', '--timeout', str(timeout)]
        if peer:
            other = 'replica' if name == 'primary' else 'primary'
            argv += ['--peer-cert', str(self.root / other / 'cert.pem')]
        node = Node(name, argv, self.root)
        self.nodes.append(node)
        if allow_rejection and wait_for_exit(node.process, .3) is not None:
            return node
        ports = [self.ports[name]] + ([self.ports['replication']] if name == 'replica' else [])
        wait_for_port(node, ports)
        return node

    def start_both(self):
        self.replica = self.start('replica')
        self.primary = self.start('primary')

    def file(self, node, name='seed.bin'):
        return self.root / node / 'data' / USER / name

    def client(self, args, direct='primary', password=PASSWORD, username=USER):
        config = self.root / 'client.conf'
        # Direct replica tests use replica for both endpoints: no primary can mask
        # a failed replica request. Failover tests retain the normal topology.
        config.write_text(f'primary_host=127.0.0.1\nprimary_port={self.ports[direct]}\n'
                          f'replica_host=127.0.0.1\nreplica_port={self.ports["replica"]}\n'
                          f'ca_file={self.root / "trust.pem"}\n')
        result = run_password_program([self.client_binary, '--config', str(config),
                                       '--username', username, *map(str, args)], self.root,
                                      [b'Password: '], password)
        self.events.append(f'client {args[0]} exit={result[0]} stdout={result[1]!r} stderr={result[2]!r}')
        return result

    def alive(self, scenario):
        for node in self.nodes:
            if not node.stopped:
                assert_process_alive(node, scenario)

    def diagnostics(self):
        return '\n'.join(self.events + [node.diagnostic() for node in self.nodes])

    def close(self):
        for node in self.nodes:
            node.stop()
        for sock in self.reservations.values():
            sock.close()
        self.temporary.cleanup()
