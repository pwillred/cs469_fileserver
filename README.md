# Secure Replicated File Service

A CS469 Distributed Systems project at Regis University by Fedil Grogan and
Brian Leake. The target is a secure file service with a CLI client, a primary
server, and a read-only replica. **The distributed service is not complete:**
local credential administration, client commands/read failover, production server
SQLite authentication, and production LIST/DOWNLOAD are implemented and tested.
Reads interoperate with the completed client over verified TLS. Replication,
server roles, mTLS between peers, and the UPLOAD acceptance/commit workflow remain
pending. Current write success reflects local filesystem changes only.

## Project Overview

The intended operations are LIST, UPLOAD, DOWNLOAD, and DELETE, with per-user
storage, TLS client connections, mTLS replication, SQLite credentials,
coordinated synchronous writes, and read failover. The current server provides
inbound TLS, authenticated local reads, and authenticated legacy local upload/delete
paths. The write paths still await the partner-owned replication workflow.

## Architecture

Intended architecture (not the current implemented deployment):

```text
Client
  +--> Primary Server
  |      +--> Local user files
  |      +--> Local users.db
  |      +-- mTLS replicated writes --> Replica Server
  +--> Replica Server (read failover)
         +--> Local user files
         +--> Local users.db
```

The primary serves all operations and coordinates replicated writes. The replica
serves read-only client operations and receives writes from the primary. Both
nodes will authenticate clients against their own local SQLite database.

Accounts are to be administratively provisioned on each node; credential databases
are **not part of the file replication protocol**. Matching usernames/passwords
must be maintained on both nodes, including changes and deletions. Independent
random salts mean their stored hashes need not be byte-for-byte identical.
Each running server authenticates against its configured local existing DB.

## Consistency / Fault Tolerance

The planned design sends writes only to the primary. UPLOAD/DELETE succeed only
after coordinated replica participation; an unavailable replica causes writes
to fail. The client now tries reads on the primary, then the replica once only
for eligible transport failure before an application status. Writes never fail
over. Server-side replication remains incomplete: the current
server scaffold's upload/delete success reflects local filesystem changes only.

## Security

Implemented local credential storage uses PBKDF2-HMAC-SHA256 with 600,000 default
iterations, independent 16-byte random salts, 32-byte derived keys, stored KDF
parameters, and constant-time hash comparison. Plaintext passwords are not stored.
The admin CLI and client prompt hide input and cleanse temporary password buffers;
password command-line arguments are deliberately prohibited.

The server loads a TLS certificate/key and requires a provisioned authentication
DB. Reads use directory-relative no-follow access within the authenticated user
directory; legacy write filesystem hardening remains with write integration. The reusable client transport verifies CA trust
and DNS/IP identity with TLS 1.2 or newer. Primary-to-replica mTLS remains planned.
The configuration loader records the CA path; command execution loads that CA
and verifies each endpoint before transmitting credentials. Certificate/identity
failures never trigger failover. There is no insecure client mode or general retry.

## Repository Layout

| Files | Purpose |
| --- | --- |
| `admin.c` | Local account administration |
| `password_db.c`, `password_db.h` | SQLite lifecycle, hashing, verification, account management |
| `client.c` | CLI orchestration, secure prompt, command results |
| `client_config.c`, `client_config.h` | CLI parsing and deployment configuration loading |
| `client.conf.example` | Placeholder topology and CA configuration |
| `client_password.c`, `client_password.h` | Secure single-password terminal input |
| `client_protocol.c`, `client_protocol.h` | Independent client wire codec, validation and status decoding |
| `client_commands.c`, `client_commands.h` | Read failover, primary-only writes, safe streaming and password cleanup |
| `client_transport.c`, `client_transport.h` | Verified TCP/TLS connection and exact I/O primitives |
| `INTEGRATION_ASSUMPTIONS.md` | Working wire contract and current scaffold conflicts |
| `server.c`, `server.h` | TLS/TCP startup, configuration, detached connection threads |
| `server_ops.c` | Exact-verb dispatch, authenticated local writes and read-handler integration |
| `server_auth.c`, `server_auth.h` | Decoded-credential validation, DB verification and error mapping, used by isolated read handlers |
| `server_read_ops.c`, `server_read_ops.h` | Isolated authenticated LIST/DOWNLOAD with bounded callback I/O and directory-relative access |
| `server_protocol_io.c`, `server_protocol_io.h` | Nonblocking production TLS adapter with a request deadline |
| `server_protocol_fields.h` | Shared bounded NUL reader and explicit status encoding |
| `tests/test_server_fields.c`, `tests/test_server_credentials.c`, `tests/test_server_production_integration.py` | Status/field boundaries and actual production-server/client integration |
| `tests/test_server_read_ops.c`, `tests/server_read_faults.h` | Deterministic local read/output faults and full password-cleanup checks |
| `tests/server_read_fixture.c`, `tests/test_server_read_integration.py` | Concurrent isolated TLS read server, wire checks and actual-client PTY interoperability |
| `server_util.c` | TLS I/O and filesystem-path helpers |
| `protocol.h`, `password.h` | Scaffold protocol constants and legacy verifier declaration |
| `cert_gen.sh` | Generates a self-signed primary test certificate/key |
| `tests/test_password_db.c` | Database and account-management tests |
| `tests/test_server_auth.c` | Temporary DB authentication, concurrency, cleanup and fault-mapping tests |
| `tests/test_client_config.c` | CLI and configuration-file tests |
| `tests/test_client_password.c` | Pseudo-terminal password/cleanup tests |
| `tests/test_client_transport.c` | Loopback TLS, trust, identity, I/O and cleanup tests |
| `tests/test_client_protocol.c` | Exact wire bytes and boundary tests using an in-memory transport |
| `tests/test_client_commands.c`, `tests/client_io_faults.h` | Password-erasure runner and test-only local I/O fault injection |
| `tests/test_client_integration.py` | Primary/replica TLS mock servers and executable/PTY tests |
| `tests/test_client_failover.c` | Deterministic transport failures, routing policy and attempt counts |
| `Makefile`, `.gitignore` | Server build and C artifact ignores |

## Dependencies

Use a C compiler, a POSIX environment, pthreads, OpenSSL development headers and
libraries, SQLite3 development headers/libraries, and GNU Make. Password terminal
tests also use `openpty`/libutil. macOS needs Command Line Tools; Homebrew OpenSSL
may require explicit include/library paths. The Makefile workflow below was checked
on macOS; Linux requires the corresponding development packages. The command
integration suite additionally requires Python 3 and the `openssl` CLI.

## Building

Run from the repository root. With system OpenSSL/SQLite development packages
(for example on Linux):

```sh
make
make test
```

On macOS/Homebrew, `openssl@3` is the locally verified formula:

```sh
make OPENSSL_PREFIX="$(brew --prefix openssl@3)"
make OPENSSL_PREFIX="$(brew --prefix openssl@3)" test
make OPENSSL_PREFIX="$(brew --prefix openssl@3)" sanitize
```

| Command | Purpose |
| --- | --- |
| `make` / `make all` | Build `server`, `client`, and `admin` at the repository root |
| `make server`, `make client`, `make admin` | Build just that executable |
| `make test` / `make check` | Run every current C suite and Python command integration suite |
| `make sanitize` | Run the same suites with AddressSanitizer and UndefinedBehaviorSanitizer |
| `make clean` | Remove generated programs, objects, dependency files and build directories |
| `make help` | Show a short target summary |

Pass `OPENSSL_PREFIX` to each build/test invocation when needed. It adds include
and library search paths without hard-coding Homebrew or a user directory.
`CC`, `CFLAGS`, `CPPFLAGS`, `LDFLAGS`, `LDLIBS`, `PYTHON` (default `python3`), and
library variables (`SSL_LIBS`, `CRYPTO_LIBS`, `SQLITE_LIBS`, `THREAD_LIBS`, `PTY_LIBS`)
can be overridden. Defaults use C11, `-Wall -Wextra -Wpedantic`, and POSIX.1-2008
interface declarations. Run `make clean` before switching compilers, prefixes or
custom flags; normal and sanitizer modes already have separate object trees.

Normal objects, generated header dependencies and test binaries live under
`build/normal/`; sanitizer objects, tests and the integration-test client live
under `build/sanitize/`. Sanitizer tests do not replace the normal root programs.
The special fault-injection test objects are separate from production objects.
`build/` is reserved for generated artifacts: do not store databases, certificates
or other runtime data there. Clean also removes the original server's root objects
and generated debug bundles; it does not remove source, configuration, databases
or certificates outside those generated paths.

Server linkage includes SQLite, OpenSSL and pthreads. The production executable
links authentication, read handlers and the TLS adapter. The client uses OpenSSL
and pthreads; admin uses SQLite and OpenSSL crypto.

Current server invocation:

```sh
./server -p 8443 -c primary_cert.pem -k primary_key.pem -d data --auth-db users.db --timeout 15
```

The `--timeout` argument is optional and defaults to 15 seconds. Supply an
existing data directory, certificate/key, and provisioned `--auth-db` path.
Startup opens the DB read-only, runs SQLite quick_check and checks required users
columns. Missing, empty/unprovisioned, corrupt or incompatible DBs fail startup;
no DB/schema is created or migrated. An empty provisioned users table is valid.
Stored credential/KDF records are validated during authentication. `bash cert_gen.sh`
generates a self-signed primary test certificate and an unencrypted private key;
keep the key private. The script does not provision mTLS or a trusted client CA.
The server currently has no role or replica-endpoint option.

## Administrative User Management

```text
admin <database> init
admin <database> add <username>
admin <database> passwd <username>
admin <database> delete <username>
admin <database> list
```

Every command opens the database and initializes its schema idempotently. Add
and passwd prompt twice with echo disabled. Usernames are 1–64 ASCII letters,
digits, underscores, or hyphens. Passwords are 1–4096 bytes as C strings; embedded
NULs are unsupported. List prints usernames only.

Provision the same account separately on the respective nodes, for example:

```sh
# On the primary host:
./admin primary-users.db add alice
# Separately, on the replica host:
./admin replica-users.db add alice
```

These are local administration commands, not remote synchronization. User file
directories are not created by the admin tool. The server consumes these
credentials through its required `--auth-db` configuration.

## Client Usage

```sh
./client --username alice list
# Or select a deployment configuration explicitly:
./client --config custom-client.conf --username alice list
```

The user addresses one logical file service, not an individual physical server.
Deployment topology belongs in configuration. Copy `client.conf.example` to
`client.conf` and supply deployment-appropriate values. The default `client.conf`
is relative to the client's current working directory; `--config FILE` overrides
it. An example (placeholder names only):

```ini
primary_host=server1.example
primary_port=4433
replica_host=server2.example
replica_port=4433
ca_file=certs/ca.pem
```

All five keys are required. Blank lines and lines beginning with `#` after trimming
are allowed; whitespace around keys/values is trimmed. Unknown/duplicate/missing
keys, empty values, malformed lines and invalid ports are errors. Ports are decimal
1–65535. Hosts are limited to 255 bytes without whitespace/control characters,
other values to 1023 bytes, and lines to 2048 bytes excluding newline. There is no
quoting, escaping, inline-comment or environment-substitution syntax; each data
line must have exactly one `=`. Relative CA paths are relative to the working
directory, not the configuration file. The loader does not open the CA file.

`--username` is required; options precede the lowercase command. The old
`--primary-host`, `--primary-port`, `--replica-host`, `--replica-port`, and `--ca`
CLI options are rejected, as are password options. The client internally retains
both endpoints. LIST/DOWNLOAD attempt the primary first, then the replica at most
once for an eligible transport failure **before a valid status byte is received**.
UPLOAD/DELETE always use the primary once; writes never retry or fail over.

Eligible transport results are RESOLVE_ERROR, CONNECT_ERROR, TIMEOUT, IO_ERROR,
and EOF during connect, request transmission, or the initial status read.
Certificate/identity errors, invalid CA/configuration, TLS negotiation errors,
protocol errors (including unknown status), local errors and every application
status are excluded. Once OK arrives, even a truncated length/count before file
bytes arrive is final: neither LIST nor DOWNLOAD consults the replica afterward.
Downloads retain their staging-file cleanup on these failures.

On failover, stderr reports `Primary server unavailable; trying replica...`.
The password is prompted once and reused transiently until the overall operation
finishes, then cleansed. Replica success produces normal output; replica failure
reports that the read could not be completed, followed by its specific error.
There are no retry loops or backoff. Endpoint resolution may still try multiple
addresses internally within one transport open call.
Command operands are:

```text
list
upload LOCAL_FILE REMOTE_NAME
download REMOTE_NAME LOCAL_FILE
delete REMOTE_NAME
```

Local paths must be nonempty. Username/password must contain 1–64 printable ASCII
characters. Remote names must contain 1–256 printable ASCII characters, cannot
contain either path separator, and cannot be `.` or `..`. Invalid values are
rejected locally, never truncated. Use `client --help` for usage.

After valid parsing and configuration loading, the client prompts **once** using
terminal stdin, without confirmation or echo. The local prompt permits up to
4096 bytes, but command execution rejects passwords over the 64-character wire
limit **before connecting**. The entire password buffer is cleansed after every
command result and every prompt failure. Help, invalid arguments, and invalid
configuration never prompt. Noninteractive password input is rejected.

LIST prints one filename per line; an empty list prints nothing. Response counts
are capped at 10,000 entries, and each name must terminate within 257 bytes and
pass filename validation. A malformed later entry can leave earlier entries on
stdout; the command still exits unsuccessfully.

UPLOAD opens a regular local file read-only, rejects sizes above UINT32_MAX,
waits for preliminary OK, streams exactly the measured size in chunks of at most
16 KiB, and succeeds only on final OK. A shrinking file fails; growth beyond the
measured size is not transmitted. No snapshot of concurrent source edits is made.
DOWNLOAD streams to a private (0600), randomly named temporary sibling, then
fsyncs/closes it and publishes only after receiving all advertised bytes. Existing
destinations, including symlinks and files created during transfer, are rejected.
Publication uses atomic POSIX `linkat` followed by removal of the staging name:
unlike ordinary `rename`, this cannot overwrite a destination. The destination
filesystem must support hard links. Handled failures remove staging files; process
crashes or filesystem cleanup failures can leave a staging file, never a partial
final file. Directory entries are not fsynced for crash durability.
Zero-byte uploads/downloads work. Successful writes/downloads print a concise
completion message; errors go to stderr with a nonzero exit code. An interrupted
upload/delete can have an unknown remote outcome and is never automatically retried.

## Isolated Server Authentication

`server_auth_verify(db_path, username, username_size, password, password_size)`
accepts decoded spans whose sizes include exactly one final NUL. It requires
1–64 username characters from ASCII letters/digits/underscore/hyphen (the DB
policy), and 1–64 printable ASCII password characters. Unterminated, embedded-NUL,
padded and overlong fields return BAD_REQUEST without truncation. Password storage
is borrowed and cleansed across the entire supplied span on every return; the
caller must clear any remaining capacity and buffers on earlier parsing failures.

Each call opens its own DB with `password_db_open_existing`, verifies, and closes.
The new API opens read-only without CREATE, rejecting missing/non-regular files
and memory/URI paths; it never initializes schema. This avoids the creation race
of an existence check followed by the admin API's CREATE open. Missing/unusable
DBs and missing schemas fail INTERNAL. Existing admin create/mutation behavior is
unchanged. Provision accounts locally on both nodes using the admin CLI.

Only PASSWORD_DB_OK authenticates. Missing user and wrong password both return
SERVER_AUTH_FAILED / ERR_AUTH_FAILED. Database, crypto, unsupported algorithm,
corrupt record, allocation and unexpected errors map to INTERNAL. Malformed
credentials map to BAD_REQUEST before opening the DB; an unexpected DB
INVALID_ARGUMENT after successful validation maps to INTERNAL. Result codes
conceal account existence, but the underlying DB verification does not equalize
lookup/KDF timing. Authentication creates no shared handles or mutable global state.

**Active in production:** `--auth-db` is required and preflighted before listening.
Every operation parses bounded NUL credentials and authenticates locally. Full
password capacity is cleansed, including parse failures. Workers own config/path
copies and TLS-context references, so acceptor shutdown cannot free their state.
The legacy two-argument verifier symbol remains for source compatibility but is
unused and always rejects; active callers use `server_auth_verify`.

## Current Implementation Status

| Area | Status in this checkout |
| --- | --- |
| Password DB and account APIs | Implemented and tested locally |
| Admin CLI | Implemented; local administration only |
| Client CLI/configuration | Implemented and tested |
| Client secure password input | Implemented; credentials sent only inside verified TLS |
| Server TLS/thread scaffold | Detached workers with owned config paths/TLS references; bounded read I/O |
| Isolated server authentication | Implemented/tested; read-only per-call DB ownership |
| Server request authentication | Implemented for all four commands; required existing DB |
| Isolated server LIST / DOWNLOAD | Implemented/tested; local auth, sorted listing, safe streaming |
| Production server LIST / DOWNLOAD | Implemented; actual-client TLS/PTY interoperability tested |
| Server UPLOAD / DELETE | Local filesystem paths only |
| Replication / prepare-commit / mTLS | Not implemented in this checkout |
| Primary/replica role enforcement | Pending |
| Client TLS transport primitives | Implemented separately; verified connections and exact I/O |
| Client codec and LIST / UPLOAD / DOWNLOAD / DELETE | Implemented against frozen contract; local TLS mock tests |
| Client LIST / DOWNLOAD failover | Implemented before initial status only; verified with mocks |

## Testing

Run `make test` (with `OPENSSL_PREFIX` where required). Individual targets are:

```text
test-password-db          test-client-config
test-client-password      test-client-transport
test-client-protocol      test-client-commands
test-client-failover       test-server-auth
test-server-auth-faults    test-server-read
test-server-production
```

For example, `make test-server-auth`. `test-client-commands` runs the Python TLS
harness with both the compiled command runner and actual client executable;
`test-client-integration` is an alias. `test-server-auth-faults` compiles the existing
fault-mapping mode separately. Each target builds what it needs and propagates
failures. Plain `make test` stops at the first failure; with `-j`, already-running
independent tests may finish before Make exits unsuccessfully.

Tests need POSIX pseudo-terminals and permission to bind loopback ports. The Python
suite requires `python3` and the `openssl` CLI on PATH (or its existing `OPENSSL`
environment override). No external service or partner server is required.

The database and authentication suites create and remove temporary databases.
Auth tests cover invalid spans, missing/schema/corrupt/unreadable DBs, a real
5-second lock timeout, read-only behavior, independent concurrent calls, password
erasure and secret-free diagnostics. Permission-denial testing is skipped when
running as root. Fault mode checks open/verify return mappings, including rare
crypto/allocation errors and unexpected values. Configuration tests
create and remove a temporary config file; pure CLI parsing requires no files.
Neither test path uses DNS or a server. Password tests create pseudo-terminals
and verify hidden
input, bounds, failure clearing, and terminal restoration after success, EOF and
SIGINT/SIGTERM/SIGHUP/SIGQUIT. They emit no plaintext test passwords.
Transport tests need permission to bind loopback sockets; they generate ephemeral
keys/certificates, remove temporary CA
files, and require no external server. They exercise certificate trust, DNS/IP
identity, SNI, buffered/fragmented reads, large writes, EOF and timeouts. A genuine
partial SSL_write return is not deterministically forced; large multi-write
payloads cover progress. IPv6 support is implemented but the fixture binds IPv4.

The protocol suite checks exact byte layouts and boundaries without a socket.
The integration suite generates temporary CA/server keys and certificates and
checks actual TLS requests, preliminary/final statuses, streaming, malformed
responses, local read/write faults, no-overwrite races and cleanup. Its command
runner verifies the entire password allocation is zero after each case; a PTY
also exercises the actual executable for all four commands and selected failures.
Primary/replica fixtures check failover and detect unwanted additional connections.
PTY failover cases verify a single password prompt. Routing tests inject resolver
and TCP timeout results deterministically; TLS fixtures additionally exercise a
real handshake timeout, pre-status connection loss, certificate/identity failures,
post-status truncation and write guardrails. No external DNS outage or blackholed
TCP route is required for deterministic timeout/resolver policy coverage.
No partner server or external service is needed; temporary fixtures are removed.

### Two-process distributed acceptance tests (work in progress)

```sh
make OPENSSL_PREFIX=/opt/homebrew/opt/openssl@3 test-two-node
make OPENSSL_PREFIX=/opt/homebrew/opt/openssl@3 sanitize-two-node
```

`tests/test_two_node_integration.py` runs 23 acceptance scenarios against the
actual server, client, and admin binaries. Its fixture creates temporary primary
and replica data directories, independently provisioned credential DBs (admin
password prompts use PTYs), dual-purpose TLS certificates with localhost/IP
identities, a client trust bundle, and three dynamic loopback ports. It launches
both roles with explicit peer configuration. Each scenario gets fresh node state;
all processes and temporary material are cleaned up, including after failures.
Python 3, POSIX PTYs, loopback access, and an OpenSSL CLI are required. `OPENSSL`
can override the CLI path; otherwise Make uses `OPENSSL_PREFIX/bin/openssl` when
a prefix is supplied, or `openssl` from PATH.

This suite is deliberately **separate from `make test`**. At the integration
baseline `9cf94e4`, replica request cleanup and replication-port connections can
crash, UPLOAD lacks preliminary acceptance, and missing peer configuration allows
local-only writes. These are real failures, not skips or expected-failure passes.
Tests check process survival after responses, read failover, peer rejection,
upload/delete outcomes, outage rejection, and repeated requests. A primary without
peer configuration must reject startup or reject writes in normal replicated mode;
the harness does not invent a standalone option. No distributed-pass claim is made.

Failure reports include client outcomes and node stdout/stderr plus exit signals,
with fixture passwords redacted. Startup waits for the flushed post-listen banner
instead of opening a probe connection that could itself trigger replica cleanup.
For a focused reproduction (after building), use a test-name substring:

```sh
python3 tests/test_two_node_integration.py ./server ./client ./admin --match test_03
python3 tests/test_two_node_integration.py ./build/sanitize/server ./build/sanitize/client ./build/sanitize/admin --match test_10
```

Promote this suite into the normal aggregate only after the implementation meets
the acceptance criteria. The existing green suites do not establish two-node
correctness.

`make sanitize` applies `-fsanitize=address,undefined -fno-omit-frame-pointer`
and `-fno-sanitize-recover=all` to compilation and linking so detected errors fail
the target. It runs all the same suites, including TLS/PTY
integration. It requires a compiler/runtime with ASan/UBSan support. Build commands
remain visible in Make output for troubleshooting; there is no separate manual
compilation workflow to keep synchronized. macOS is locally tested; the system
OpenSSL path is intended for Linux/POSIX environments but has not been run on Linux
in this checkout.

## Isolated authenticated server reads

`make OPENSSL_PREFIX="$(brew --prefix openssl@3)" test-server-read` runs the
read-handler suite alone; `make test` and `make sanitize` include it automatically.
It runs deterministic callback/fault tests, a temporary concurrent C TLS server,
wire-boundary and filesystem checks, and five actual-client PTY scenarios: LIST,
DOWNLOAD, authentication failures for both, and a missing download. Test fixtures
provision temporary credentials and certificates; production server startup is
not involved. Root runs explicitly skip filesystem permission-denial cases.

`server_handle_list` and `server_handle_download` consume credentials after a
caller has read the literal verb. They authenticate with a private read-only DB
handle per call and own the entire response. The result distinguishes a complete
response from a local/transport failure requiring connection termination. The production
wrapper **does not append another status**. The callback interface supports exact
I/O and abort; `server_protocol_io_init` adapts a completed TLS connection using
nonblocking SSL-first I/O, WANT_READ/WANT_WRITE handling, a monotonic whole-operation
network deadline, and thread-local SIGPIPE protection. It borrows the SSL/socket;
the caller must close/free them after the operation. Disk and DB calls are not
made asynchronous or bounded by that network deadline.

LIST returns sorted regular-file names (maximum 10,000; overflow returns INTERNAL).
An absent user directory is an empty list; DOWNLOAD returns NOT_FOUND for an
absent user directory/file, symlink, directory or FIFO. An inaccessible root/user
folder returns INTERNAL. Names beginning `.temp_` are reserved staging names and
are neither listed nor downloadable; other valid dotfiles remain visible.
Username validation and directory-relative no-follow opens prevent traversal and
user-directory/file symlink escapes. Administrator-controlled root ancestors and
file ownership remain deployment requirements; hard links are not distinguished
from ordinary regular files. Neither reads nor admin create user directories.

DOWNLOAD sends a big-endian 32-bit size and streams exactly that many bytes in
bounded chunks; larger files return TOO_LARGE. Once OK is sent, local read or TLS
failure aborts the connection without an extra status. Committed files should be
published by rename, not modified in place: readers pin an opened inode, but LIST
is not a transactional snapshot of concurrent writes. See
INTEGRATION_ASSUMPTIONS.md for integration ownership and policies.

Production dispatch/startup wiring is complete. `make test-server-production`
runs explicit status/field tests, production credential-buffer erasure tests,
and the actual server executable, including DB
startup failures, all four verb/auth paths, exact read response framing, five real
client/PTY cases, concurrent reads and shutdown during an active request. Both
`make test` and `make sanitize` include it. Local write regressions verify framing
and existing filesystem behavior, not replicated completion.

Dispatch incrementally matches prefix-free verbs without consuming username bytes.
With no verb delimiter, `LISTXalice` means LIST for username `Xalice`; nonexistent
accounts fail authentication. UPLOAD now parses size before its bounded filename,
but still has **no preliminary acceptance status**. The completed client waits
for that status before sending data, so normal client UPLOAD remains incompatible
until partner coordination adds the acceptance/replication workflow. Tests send
payloads explicitly to exercise the existing local handler; no success is fabricated.
DELETE retains its single local final status. Neither operation has role enforcement.

The acceptor polls a nonblocking listener at most 500 ms between shutdown checks;
SIGINT/SIGTERM only set a signal-safe flag. This avoids relying on listener
shutdown to wake accept on macOS. Existing workers finish independently.

## Known Limitations / Work in Progress

- Server replication, role enforcement and peer mTLS remain incomplete.
- UPLOAD's preliminary acceptance and coordinated commit workflow remain pending;
  current write success is local only. Legacy write filesystem/I/O-result handling
  has not been redesigned by the authentication/read integration patch.
- Credential provisioning is manual on each node; no credential replication exists.
- Production LIST/DOWNLOAD interoperate with the completed client; these tests do
  not establish replicated-write correctness or deployed role enforcement.
- Transport uses one 5-second deadline for TCP attempts plus TLS handshake after
  resolution, and one deadline per read/write call; a timeout API permits overrides.
  Synchronous getaddrinfo is not deadline-bounded. Close makes one nonblocking
  close_notify attempt. Callers must discard a connection after transfer failure.
- Client read failover is implemented only before a valid status. There is no
  post-status restart, write failover or general retry. See INTEGRATION_ASSUMPTIONS.md
  for the working contract and scaffold conflicts.
- Password entry uses terminal editing conventions: backspace edits, Ctrl-U clears,
  Ctrl-D cancels. Signal controls and flow control retain terminal meanings.
- Handled termination signals cancel client input after restoration; SIGKILL and
  terminal-device loss cannot guarantee cleanup. Prompting is single-threaded.
- Detached workers retain owned config paths/TLS references through shutdown.
  Handshake socket waits are bounded; shutdown lets active workers finish. There
  is no new worker pool, connection limit, or global shutdown deadline. Read network
  I/O uses one configured operation deadline; legacy writes retain per-call waits
  and their final status uses the default 15-second write timeout.

## Team

Fedil Grogan and Brian Leake

CS469 – Distributed Systems, Regis University
