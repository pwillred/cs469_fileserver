# Secure Replicated File Service

A CS469 Distributed Systems project at Regis University by Fedil Grogan and
Brian Leake. The target is a secure file service with a CLI client, a primary
server, and a read-only replica. **The distributed service is not complete:**
local credential administration and client configuration/password input work;
server authentication, read operations, replication, and client networking are
not integrated in this checkout.

## Project Overview

The intended operations are LIST, UPLOAD, DOWNLOAD, and DELETE, with per-user
storage, TLS client connections, mTLS replication, SQLite credentials,
coordinated synchronous writes, and read failover. The current server provides
an inbound TLS scaffold and local upload/delete paths, but its password verifier
still accepts every credential. Do not treat it as an authenticated service.

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
This is a provisioning policy; current server code does not yet open either DB.

## Consistency / Fault Tolerance

The planned design sends writes only to the primary. UPLOAD/DELETE succeed only
after coordinated replica participation; an unavailable replica causes writes
to fail. Reads normally use the primary; LIST/DOWNLOAD may retry on the replica
for eligible availability failures. There is no write failover, and the service
may degrade to read-only. These guarantees are not implemented yet: current
upload/delete success reflects local filesystem changes only.

## Security

Implemented local credential storage uses PBKDF2-HMAC-SHA256 with 600,000 default
iterations, independent 16-byte random salts, 32-byte derived keys, stored KDF
parameters, and constant-time hash comparison. Plaintext passwords are not stored.
The admin CLI and client prompt hide input and cleanse temporary password buffers;
password command-line arguments are deliberately prohibited.

The server loads a TLS certificate/key, but real user authentication and per-user
isolation still need integration. Client TLS certificate/hostname verification
and primary-to-replica mTLS remain planned. The CA configuration key currently records a path
only; it does not load or trust a certificate. There is no insecure client mode.

## Repository Layout

| Files | Purpose |
| --- | --- |
| `admin.c` | Local account administration |
| `password_db.c`, `password_db.h` | SQLite lifecycle, hashing, verification, account management |
| `client.c` | Local CLI entry point; prompts then discards password |
| `client_config.c`, `client_config.h` | CLI parsing and deployment configuration loading |
| `client.conf.example` | Placeholder topology and CA configuration |
| `client_password.c`, `client_password.h` | Secure single-password terminal input |
| `server.c`, `server.h` | TLS/TCP startup, configuration, detached connection threads |
| `server_ops.c` | Dispatch, local writes, authentication/read stubs |
| `server_util.c` | TLS I/O and filesystem-path helpers |
| `protocol.h`, `password.h` | Scaffold protocol constants and legacy verifier declaration |
| `cert_gen.sh` | Generates a self-signed primary test certificate/key |
| `tests/test_password_db.c` | Database and account-management tests |
| `tests/test_client_config.c` | CLI and configuration-file tests |
| `tests/test_client_password.c` | Pseudo-terminal password/cleanup tests |
| `Makefile`, `.gitignore` | Server build and C artifact ignores |

## Dependencies

Use a C compiler, a POSIX environment, pthreads, OpenSSL development headers and
libraries, SQLite3 development headers/libraries, and `make`. Password terminal
tests also use `openpty`/libutil. macOS needs Command Line Tools; Homebrew OpenSSL
may require explicit include/library paths. The direct builds below were checked
on macOS; Linux requires the corresponding development packages. Python 3 is not
needed for the checked-in C test suites.

## Building

Run these commands from the repository root. Build standalone tools/tests into a
temporary directory, retained for the following examples:

```sh
BUILD_DIR=$(mktemp -d)
OPENSSL_CFLAGS=
OPENSSL_LDFLAGS=
# macOS/Homebrew, if OpenSSL is outside the compiler's default search paths:
OPENSSL_PREFIX=$(brew --prefix openssl)
OPENSSL_CFLAGS="-I$OPENSSL_PREFIX/include"
OPENSSL_LDFLAGS="-L$OPENSSL_PREFIX/lib"
# On systems with OpenSSL in the default paths, omit the three Homebrew lines.
CFLAGS="-std=c11 -Wall -Wextra -Wpedantic"

cc $CFLAGS $OPENSSL_CFLAGS $OPENSSL_LDFLAGS \
  -o "$BUILD_DIR/admin" admin.c password_db.c -lsqlite3 -lcrypto
cc $CFLAGS $OPENSSL_CFLAGS $OPENSSL_LDFLAGS \
  -o "$BUILD_DIR/client" client.c client_config.c client_password.c -lcrypto
cc $CFLAGS $OPENSSL_CFLAGS $OPENSSL_LDFLAGS \
  -o "$BUILD_DIR/test_password_db" tests/test_password_db.c password_db.c -lsqlite3 -lcrypto
cc $CFLAGS -o "$BUILD_DIR/test_client_config" tests/test_client_config.c client_config.c
cc $CFLAGS $OPENSSL_CFLAGS $OPENSSL_LDFLAGS \
  -o "$BUILD_DIR/test_client_password" tests/test_client_password.c client_password.c -lcrypto -lutil
```

The existing Makefile builds **only `server`**; it has no admin, client or test
targets. With dependencies in standard search paths, use `make`. With the variables
above, the equivalent configured build is:

```sh
make CFLAGS="-Wall -Wextra $OPENSSL_CFLAGS" LDFLAGS="$OPENSSL_LDFLAGS"
```

`make clean` removes server objects and the server executable only. It does not
remove the independently built tools/tests.

Current server invocation:

```sh
./server -p 8443 -c primary_cert.pem -k primary_key.pem -d data --timeout 15
```

The `--timeout` argument is optional and defaults to 15 seconds. Supply an
existing data directory and certificate/key. `bash cert_gen.sh`
generates a self-signed primary test certificate and an unencrypted private key;
keep the key private. The script does not provision mTLS or a trusted client CA.
The server currently has no role, replica-endpoint, or database-path option.

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
"$BUILD_DIR/admin" primary-users.db add alice
# Separately, on the replica host:
"$BUILD_DIR/admin" replica-users.db add alice
```

These are local administration commands, not remote synchronization. User file
directories are not created by the admin tool. The server does not consume these
credentials until authentication integration is implemented.

## Client Usage

```sh
"$BUILD_DIR/client" --username alice list
# Or select a deployment configuration explicitly:
"$BUILD_DIR/client" --config custom-client.conf --username alice list
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
both endpoints. Future LIST/DOWNLOAD failover will be automatic for eligible
availability failures; UPLOAD/DELETE remain primary-only. Routing, networking and
failover are still pending. Command operands are:

```text
list
upload LOCAL_FILE REMOTE_NAME
download REMOTE_NAME LOCAL_FILE
delete REMOTE_NAME
```

Local paths must be nonempty; remote names must be nonempty filenames without
path separators and cannot be `.` or `..`. Only the configuration file is read;
no user files are opened or transferred. Use `client --help` for usage.

After valid parsing and configuration loading, the client prompts **once**,
without confirmation, using terminal stdin. It accepts up to 4096 bytes locally, rejects empty/overlong input,
clears the password immediately, and reports that no network operation occurred.
Help, invalid arguments, and missing/invalid configuration never prompt.
Noninteractive password input is rejected.
The final wire password limit remains unresolved; this local limit does not
change the scaffold's 64-byte protocol constant. Input is never silently truncated.

## Current Implementation Status

| Area | Status in this checkout |
| --- | --- |
| Password DB and account APIs | Implemented and tested locally |
| Admin CLI | Implemented; local administration only |
| Client CLI/configuration | Implemented and tested |
| Client secure password input | Implemented and tested; no credentials sent |
| Server TLS/thread scaffold | Present; lifecycle/I/O hardening pending |
| Server authentication | Always-success stub; DB integration pending |
| LIST / DOWNLOAD | Success-returning stubs; no file data returned |
| UPLOAD / DELETE | Local filesystem paths only |
| Replication / prepare-commit / mTLS | Not implemented in this checkout |
| Primary/replica role enforcement | Pending |
| Client TLS/network execution | Pending |
| Read failover | Pending |

## Testing

After the direct builds above:

```sh
"$BUILD_DIR/test_password_db"
"$BUILD_DIR/test_client_config"
"$BUILD_DIR/test_client_password"
```

The database suite creates and removes temporary databases. Configuration tests
create and remove a temporary config file; pure CLI parsing requires no files.
Neither test path uses DNS or a server. Password tests create pseudo-terminals
and verify hidden
input, bounds, failure clearing, and terminal restoration after success, EOF and
SIGINT/SIGTERM/SIGHUP/SIGQUIT. They emit no plaintext test passwords.

For AddressSanitizer/UndefinedBehaviorSanitizer, append
`-fsanitize=address,undefined -fno-omit-frame-pointer` to `CFLAGS`, rebuild the desired
tools/tests with the same commands, and rerun them. No live server is required.

## Known Limitations / Work in Progress

- Final wire framing, string termination and read-response formats need agreement.
- Server credential parsing is not yet safe to connect directly to the database API.
- Replication, role enforcement, final authentication and failover remain incomplete.
- Credential provisioning is manual on each node; no credential replication exists.
- The client verifies neither a server nor a password yet and performs no networking.
- Password entry uses terminal editing conventions: backspace edits, Ctrl-U clears,
  Ctrl-D cancels. Signal controls and flow control retain terminal meanings.
- Handled termination signals cancel client input after restoration; SIGKILL and
  terminal-device loss cannot guarantee cleanup. Prompting is single-threaded.
- The current server shutdown and TLS read helpers still require hardening.

## Team

Fedil Grogan and Brian Leake

CS469 – Distributed Systems, Regis University
