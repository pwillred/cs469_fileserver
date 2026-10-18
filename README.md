# Secure Replicated File Service

CS469 Distributed Systems, Regis University — Fedil Grogan and Brian Leake.
A CLI file service intended to run one primary and one read-only replica.
**The distributed service is not yet submission-ready.**

## Current Status

Status reflects source at `7c96481` (two-node acceptance harness included).
“Working” describes the stated component, not successful replicated writes.

| Area | Status |
| --- | --- |
| SQLite password DB and admin CLI | COMPLETE / WORKING — local account administration |
| Client configuration, prompting, codec and all four commands | COMPLETE / WORKING against the working client contract |
| Client TLS | COMPLETE / WORKING — trust and DNS/IP identity verification |
| Production authentication | COMPLETE / WORKING — local read-only DB, startup preflight |
| Production LIST / DOWNLOAD | COMPLETE / WORKING on primary; replica responses are affected by worker cleanup crashes |
| Client read failover | COMPLETE / WORKING routing; replica can return a response and then crash |
| Build and normal test workflow | COMPLETE / WORKING; normal tests pass, existing server warnings remain |
| Primary/replica roles | IMPLEMENTED / INTEGRATION IN PROGRESS — write gate exists, replica lifetime is broken |
| Replication mTLS | IMPLEMENTED / INTEGRATION IN PROGRESS — mutual verification configured, endpoint fails |
| UPLOAD replication | IMPLEMENTED / INTEGRATION IN PROGRESS — partial coordinator/participant flow; preliminary status missing |
| DELETE replication | IMPLEMENTED / INTEGRATION IN PROGRESS — partial prepare/commit flow; peer endpoint fails |
| Two-node acceptance suite | IMPLEMENTED — deliberately reports current integration failures |

## Architecture

Intended final behavior:

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
primary-only with no automatic retry. Intended write success requires both nodes
and their commit acknowledgements; current implementation gaps are listed below.
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
| `make test-two-node` | Separate distributed acceptance suite; currently exposes known failures |
| `make sanitize-two-node` | Distributed suite with ASan/UBSan |
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
that could itself trigger the known replica crash.

`OPENSSL` overrides the harness CLI executable; Make otherwise uses
`OPENSSL_PREFIX/bin/openssl` or `openssl` from PATH. Select one scenario after
building:

```sh
python3 tests/test_two_node_integration.py ./server ./client ./admin --match test_03
python3 tests/test_two_node_integration.py ./build/sanitize/server ./build/sanitize/client ./build/sanitize/admin --match test_10
```

Known defects are failures, not skips/xfails. Normal crash manifestations can vary;
sanitizers expose the memory errors. This suite is **not part of `make test`**.
Promote it only after acceptance criteria pass. Green normal tests do not prove
replication: their production-write checks still cover the legacy one-status flow.

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
# Intended write usage; currently blocked by server integration defects:
./client --config client.conf --username alice upload local.txt remote.txt
./client --config client.conf --username alice delete remote.txt
```

LIST prints one name per line. DOWNLOAD refuses an existing destination, stages
privately, and publishes after receiving all advertised bytes; publication needs
hard-link support. Handled failures remove staging; process crashes can leave a
staging file. UPLOAD waits for preliminary OK before sending bytes and requires
final OK. Zero-length transfers are supported by the client contract; production
zero-byte UPLOAD is not currently working. Errors exit nonzero.

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
not. **Omitting it enables the known local-only write bypass; do not use omission
as a distributed deployment configuration.** No explicit standalone option exists.
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
Operational mTLS validation remains blocked by replication worker defects.

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

See [DEPLOYMENT.md](DEPLOYMENT.md) for a reproducible temporary setup: build,
provision both accounts/directories, generate test trust material, start replica
then primary, create client config, seed/read files, and exercise read failover.
Replicated UPLOAD/DELETE steps are explicitly gated on fixes; current replica
lifecycle failures are expected reproductions, not successful demo outcomes.

## Known Issues / Work Remaining

Reproduce with `make test-two-node`; use `make sanitize-two-node` for memory diagnostics.

- Replica client-worker cleanup can crash after a correct response (invalid free).
- Replication worker alignment/ownership/socket lifetime defects can crash or reset
  the peer connection before meaningful TLS/protocol validation.
- UPLOAD never sends the preliminary status required by the client.
- Missing primary peer configuration silently permits local-only writes.
- Same-user/filename serialization is absent. Write containment, staging namespace,
  path bounds, checked I/O and cleanup remain incomplete; peer framing/error
  handling and setup deadlines also need correction.

Commit acknowledgement loss may follow a local mutation; neither status 6 nor a
connection error guarantees rollback. No crash reconciliation is implemented.
Filesystem crash durability and recovery scope require agreement, not a claim of
perfect distributed atomicity.

## Source and Integration Guide

| Files | Purpose |
| --- | --- |
| `password_db.*`, `admin.c` | Credentials and local account administration |
| `client*.c/.h`, `client.conf.example` | CLI, configuration, prompt, verified TLS, codec, commands and read failover |
| `server.c/.h`, `server_ops.c`, `server_util.c` | Startup/roles, dispatch, primary writes and peer helpers |
| `server_replication.c/.h` | Replica mTLS endpoint and partial transactions |
| `server_auth.*`, `server_read_ops.*` | Production authentication and safe local reads |
| `server_protocol_io.*`, `server_protocol_fields.h` | TLS adapter, bounded fields and explicit statuses |
| `protocol.h`, `protocol.md` | Constants and wire specification with implementation caveats |
| `INTEGRATION_ASSUMPTIONS.md` | Working integration contract and module ownership |
| `tests/` | Unit/fault tests, mock TLS, production integration and two-node acceptance |

Client/DB/admin/auth/read work belongs to Fedil; roles, peer protocol and replicated
writes belong to Brian. Deployment, end-to-end testing and final docs are shared.
