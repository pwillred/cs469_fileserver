# Secure Replicated File Service

CS469 Distributed Systems, Regis University — Fedil Grogan and Brian Leake.
A command-line file service with one primary and one read-only replica.

## Project Status

Implemented within the course project's single-primary/single-replica scope.
The normal and ASan/UBSan suites pass, including 23 two-node scenarios,
13 boundary/concurrency tests and seven write-correctness groups in each mode.

| Area | Status |
| --- | --- |
| Client and verified TLS | Complete |
| SQLite credentials, admin CLI and authentication | Complete |
| LIST / DOWNLOAD | Complete on both nodes |
| Read failover | Complete |
| Primary/replica roles | Complete |
| Replicated UPLOAD / DELETE | Complete |
| mTLS replication | Complete with explicit peer trust |
| Same-file serialization | Complete |
| Boundary handling | Complete; host filesystem limits still apply |
| Automated acceptance | Passing |
| Build | Zero compiler warnings in validated macOS build |

## Architecture

Current topology:

```text
Client
  +--> Primary
  |      - client reads/writes
  |      - local users DB and per-user storage
  |      - write coordinator -- mTLS --> Replica
  +--> Replica
         - read-only client service
         - local users DB and per-user storage
         - replication participant
```

The user addresses one logical service. Topology comes from client configuration.
LIST/DOWNLOAD use primary first and can fail over once to replica. Writes remain
primary-only with no automatic retry. Write success requires replica participation
and commit confirmation.
Reads use local disk/DB without consulting the peer.

## Build and Test

Requirements: POSIX C11 compiler, GNU Make, pthreads, OpenSSL and SQLite development
libraries; Python 3, POSIX PTYs/libutil and an OpenSSL CLI for integration tests.
macOS requires Command Line Tools and, for these examples, Homebrew OpenSSL 3.
Run from the repository root:

```sh
make OPENSSL_PREFIX="$(brew --prefix openssl@3)"
make OPENSSL_PREFIX="$(brew --prefix openssl@3)" test
make OPENSSL_PREFIX="$(brew --prefix openssl@3)" sanitize
```

On a system with the dependencies in standard compiler paths, use `make`,
`make test`, and `make sanitize` without the prefix. POSIX portability is intended;
current validation is on macOS, not a claim of tested Linux deployment.

| Target | Purpose |
| --- | --- |
| `make` / `make all` | Build root `server`, `client`, `admin` |
| `make test` / `make check` | Existing stable C, mock-TLS and production primary/read suites |
| `make sanitize` | Same stable suites with ASan/UBSan |
| `make test-two-node` | 23 production two-node scenarios |
| `make sanitize-two-node` | Distributed suite with ASan/UBSan |
| `make test-contract-boundaries` | 13 wire/filesystem/concurrency tests |
| `make test-server-write-correctness` | Seven startup/write/fault groups |
| `make acceptance` / `make acceptance-sanitize` | All four suites, normal / ASan/UBSan |
| `make clean` | Remove generated binaries, object/dependency trees and debug bundles |
| `make help` | Target summary |

Normal and sanitizer products use `build/normal` and `build/sanitize`; sanitizer
runs do not replace root binaries. Keep runtime DBs/certificates/data outside
`build/`. Use `make clean` when changing compiler or custom flags. `CC`, `CFLAGS`,
`CPPFLAGS`, `LDFLAGS`, `LDLIBS`, `PYTHON` and library variables are overridable.
Pass `OPENSSL_PREFIX` on each invocation when required.

### Distributed acceptance harness

```sh
make OPENSSL_PREFIX="$(brew --prefix openssl@3)" test-two-node
make OPENSSL_PREFIX="$(brew --prefix openssl@3)" sanitize-two-node
```

The 23 scenarios launch actual primary/replica binaries and the actual client.
Fixtures use dynamic loopback ports, isolated data, independently admin-provisioned
DBs, temporary certificates/keys and PTY password input. Processes and temporary
secrets are cleaned up after success or failure; passwords are redacted from
failure reports. Reports include stdout/stderr and exit signals. Core dumps are
disabled. Startup uses the flushed listener banner rather than a probe connection
that would add a worker unrelated to the test scenario. Port reservations must
be released before server bind; an occasional `Address already in use` during
fixture startup is possible. Inspect the diagnostic and rerun the unchanged
target after the port is released; do not count that failed run as a pass.

`OPENSSL` overrides the harness CLI executable; Make otherwise uses
`OPENSSL_PREFIX/bin/openssl` or `openssl` from PATH. Select one scenario after
building:

```sh
python3 tests/test_two_node_integration.py ./server ./client ./admin --match test_03
python3 tests/test_two_node_integration.py ./build/sanitize/server ./build/sanitize/client ./build/sanitize/admin --match test_10
```

The distributed, boundary and write-correctness suites remain independently
runnable; `make test` alone does not include them. Full validation is available as:

```sh
make OPENSSL_PREFIX="$(brew --prefix openssl@3)" acceptance
make OPENSSL_PREFIX="$(brew --prefix openssl@3)" acceptance-sanitize
```

These compose the existing targets without changing test instrumentation.
The focused commands are:

```sh
make OPENSSL_PREFIX="$(brew --prefix openssl@3)" test-contract-boundaries
make OPENSSL_PREFIX="$(brew --prefix openssl@3)" SANITIZE=1 test-contract-boundaries
make OPENSSL_PREFIX="$(brew --prefix openssl@3)" test-server-write-correctness
make OPENSSL_PREFIX="$(brew --prefix openssl@3)" SANITIZE=1 test-server-write-correctness
```

## Client Usage

```text
client [--config FILE] --username USER COMMAND ...
  list
  upload LOCAL_FILE REMOTE_NAME
  download REMOTE_NAME LOCAL_FILE
  delete REMOTE_NAME
```

Options precede the command. Default config is `client.conf` in the working
directory. All five keys are required; see `client.conf.example`:

```ini
primary_host=primary.example
primary_port=4433
replica_host=replica.example
replica_port=4434
ca_file=certs/trust.pem
```

Relative CA paths are relative to the process working directory, not the config
file. Unknown/duplicate/missing keys and invalid ports fail validation. Config
values have no shell expansion or inline-comment syntax. Passwords are prompted
once from a terminal with echo disabled; there is no password command-line option.
Use admin-compatible usernames (`[A-Za-z0-9_-]`, 1–64 characters) and printable
ASCII passwords of 1–64 characters for network use. Admin/local prompting accepts
longer passwords, but the client rejects values exceeding wire limits before
connecting. Remote filenames are 1–256 printable ASCII characters, excluding `/`,
`\`, `.` and `..`; avoid the internal `.temp_` prefix.

```sh
./client --config client.conf --username alice list
./client --config client.conf --username alice download hello.txt downloaded.txt
./client --config client.conf --username alice upload local.txt remote.txt
./client --config client.conf --username alice delete remote.txt
```

LIST prints one name per line. DOWNLOAD refuses an existing destination, stages
privately, and publishes after receiving all advertised bytes; publication needs
hard-link support. Handled failures remove staging; process crashes can leave a
staging file. UPLOAD waits for preliminary OK before sending bytes and requires
final OK. Zero-length uploads and downloads are supported. Errors exit nonzero.

Read failover occurs only for eligible transport failures **before any valid
application status**. Certificate/identity failures, application errors, malformed
responses and failures after OK do not fail over. Writes never retry or fail over,
even when connection loss leaves the remote outcome unknown. See the precise
boundary in [INTEGRATION_ASSUMPTIONS.md](INTEGRATION_ASSUMPTIONS.md).

## Server Usage

Actual current options; replace placeholders before running:

```text
./server -p <primary-client-port> -c <primary-cert> -k <primary-key> \
  -d <primary-data-dir> --auth-db <primary-users.db> --role primary \
  --replication-port <replica-replication-port> \
  --coordinator-name <replica-host> --peer-cert <replica-trust-file> --timeout 3

./server -p <replica-client-port> -c <replica-cert> -k <replica-key> \
  -d <replica-data-dir> --auth-db <replica-users.db> --role replica \
  --replication-port <replication-listen-port> --peer-cert <primary-trust-file> --timeout 3
```

`--coordinator-name` confusingly means the **replica destination on the primary**;
its default is `primary.localhost`, so set it explicitly. `--replication-port`
(default 8081) is the destination port on primary and listening port on replica.
The default role is primary. `--timeout` defaults to 15 seconds; it does not bound
all outbound peer setup. Replica requires `--peer-cert`; primary currently does
not require it at startup, but writes fail closed without usable peer trust.
There is no local-only write fallback or standalone mode.
The server binds IPv4 listeners on all interfaces, even for a local demo.

`--auth-db` is mandatory. Startup opens it read-only, runs SQLite `quick_check`
and checks required columns without creating/migrating schema. An empty but
provisioned users table is valid; a missing/unprovisioned/corrupt DB fails startup.

## Account Provisioning

Each node has its own local DB. Provision the same logical credentials separately:

```sh
./admin primary-users.db init
./admin replica-users.db init
./admin primary-users.db add alice
./admin replica-users.db add alice
```

Enter the same network-compatible password at both hidden prompts. Salts/hashes
need not match byte-for-byte. `admin DATABASE passwd USER`, `delete USER`, and
`list` manage local accounts; changes/deletions must be repeated on both nodes.
Admin commands initialize schema idempotently. Neither admin nor server creates
per-user storage directories; create them separately. Credential DBs are never
replication payloads.

## TLS and Storage Security

The client verifies its configured trust material and DNS/IP identity with TLS 1.2
or newer. Server-to-server code uses a separate replication listener/context,
presents certificates and requires a peer certificate on the replica. It reuses
`-c/-k` for both purposes and loads peer trust from `--peer-cert`. Outbound peer
hostname/IP checks and SNI are absent; a broad CA trust file is not an intended-peer
identity check. The local guide uses explicit self-signed peer certificates.
Trusted and untrusted peer cases are covered by two-node acceptance.

Password storage uses PBKDF2-HMAC-SHA256, 600,000 default iterations, 16-byte random
salts and 32-byte derived keys, with stored KDF parameters and constant-time key
comparison. Plaintext passwords are not stored. Authentication uses one read-only
DB handle per call; bounded password buffers are cleansed. Replica client writes
are rejected at the role gate before credential handling.

Read handlers use validated usernames, directory-relative no-follow access and
regular-file checks; `.temp_` entries are hidden. Write paths do not yet have the
same containment guarantees. Root ancestors, credential paths and local filesystem
permissions must be administrator-controlled. `cert_gen.sh` generates two basic
self-signed certificates and unencrypted keys, but does not establish the full
SAN/trust/client-purpose workflow used in the deployment guide and harness.

## Local Two-Node Demo

See [DEPLOYMENT.md](DEPLOYMENT.md) for a copyable temporary setup covering account
provisioning, certificates, replicated upload, primary/replica reads, failover,
coordinated delete and replica-outage rejection.

## Write consistency and boundaries

Primary writes serialize by `(username, filename)`, including conflicting
UPLOAD/DELETE operations. The lock spans coordinated completion and cleanup;
unrelated users/files can proceed concurrently. Both nodes use exclusive short
`.temp_` staging names, hidden from reads, and check local write/close failures.
Writes require the replica; primary reads remain available during replica outage.

Wire limits are 64 username/password bytes and 256 filename bytes, plus a framing
NUL. Exact limits parse without truncation; over-limit fields are rejected. Host
`NAME_MAX` may be smaller (commonly 255): unsupported filenames fail cleanly and
are never shortened. Use new remote names for uploads; see protocol caveats below.

## Known limitations

- An error after the commit decision may mean the client cannot confirm the final
  distributed outcome. There is no commit retry, persistent transaction journal,
  automated reconciliation or full crash recovery. Writes do not fsync file and
  directory state; power-loss durability is not guaranteed.
- Outbound peer DNS/connect/TLS setup lacks a configured application deadline.
  Peer TLS uses explicit peer-certificate trust, without outbound hostname/IP
  verification or SNI. A broad CA is not equivalent to trusting only one peer.
- Writes do not have the read handlers' full directory-relative no-follow
  containment. Administrators must control storage ancestors and permissions.
  Do not use remote names beginning `.temp_`; reads reserve that namespace, but
  writes do not reject it. LIST is not a transactional snapshot.
- Replica UPLOAD rejects an existing regular destination; primary rename can
  replace a primary-only file if the nodes already diverged. This is not a general
  overwrite or reconciliation API.
- Peer fixed-width command/size reads assume complete fields in individual TLS
  reads; some peer error paths append a dispatcher error. General fragmented-peer
  robustness is not established by the current passing suites.

## Source and Integration Guide

| Files | Purpose |
| --- | --- |
| `password_db.*`, `admin.c` | Credentials and local account administration |
| `client*.c/.h`, `client.conf.example` | CLI, configuration, prompt, verified TLS, codec, commands and read failover |
| `server.c/.h`, `server_ops.c`, `server_util.c` | Startup/roles, dispatch, primary writes and peer helpers |
| `server_replication.c/.h` | Replica mTLS endpoint and prepare/commit transactions |
| `server_auth.*`, `server_read_ops.*` | Production authentication and safe local reads |
| `server_protocol_io.*`, `server_protocol_fields.h` | TLS adapter, bounded fields and explicit statuses |
| `protocol.h`, `protocol.md` | Constants and wire specification with implementation caveats |
| `INTEGRATION_ASSUMPTIONS.md` | Working integration contract and module ownership |
| `tests/` | Unit/fault tests, mock TLS, production integration and two-node acceptance |

Client/DB/admin/auth/read work belongs to Fedil; roles, peer protocol and replicated
writes belong to Brian. Deployment, end-to-end testing and final docs are shared.
