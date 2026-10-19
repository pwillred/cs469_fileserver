# Working integration contract — subject to coordinated changes

This is the team's working client integration contract, not an instructor-provided
specification. Changes require coordination between client/read/authentication
work and server/protocol/replicated-write coordination. The client codec and
commands implement these messages; the transport module remains byte-oriented.

## Transport and authentication

- TCP is immediately followed by TLS; exactly one operation per connection.
- Client verifies the server certificate against its configured CA and checks
  the endpoint's DNS name or IP identity. No plaintext fallback.
- Username/password are sent only inside TLS. No client certificate is required;
  mTLS is reserved for primary-to-replica replication.
- Both nodes authenticate locally on read requests and accepted primary writes. Unknown users and wrong passwords
  both produce AUTH_FAILED.
- Administrators provision accounts on both nodes, including password changes
  and deletions. Credential DBs are not file-replication payloads. Independent
  salts/hashes need not match byte-for-byte.

## Server authentication (production integration complete)

`server_auth.h` exposes `server_auth_verify(db_path, username, username_size,
password, password_size)` and `server_auth_to_error`. Sizes are decoded byte counts
including the final NUL, not padded array capacities. Credentials must be 1–64
characters; usernames follow DB policy `[A-Za-z0-9_-]`, and passwords use printable
ASCII. The module rejects malformed/nonterminated spans and cleanses the supplied
password span even on failure, without copying plaintext. Production callers also
cleanse unused buffer capacity and parsing-error paths.

Each call owns a separate read-only, open-existing DB handle. No authentication
call creates a database or initializes schema. Existing admin behavior is unchanged;
accounts/changes/deletions remain manually provisioned in each node's local DB.

| Verification outcome | Auth result | Network error |
| --- | --- | --- |
| PASSWORD_DB_OK | SERVER_AUTH_OK | ERR_OK |
| USER_NOT_FOUND or PASSWORD_MISMATCH | SERVER_AUTH_FAILED | ERR_AUTH_FAILED |
| Malformed input detected before DB access | SERVER_AUTH_BAD_REQUEST | ERR_BAD_REQUEST |
| Open/schema/SQLite/crypto/memory/algorithm/record failure or unexpected result | SERVER_AUTH_INTERNAL | ERR_INTERNAL |

DB INVALID_ARGUMENT after the module's input validation is an internal contract
failure; malformed client input has already returned BAD_REQUEST. Never apply the
old boolean convention: auth success is zero. Unknown auth enums map to ERR_INTERNAL.

Production startup requires `--auth-db users.db` in `server_config_t.auth_db_path`.
It opens an existing DB read-only, then `password_db_check_schema` checks SQLite
quick_check and required users columns. No creation, schema initialization or
migration occurs. Empty provisioned tables are allowed; credential records/KDF
parameters remain validated per verification. Paths/parent directories must be
administrator-controlled. The preflight handle is closed before accepting clients.

Production read handlers and accepted primary writes authenticate through
`server_auth`; replica client writes are rejected at the role gate without authentication,
after bounded header parsing. The unused legacy verifier definition has been removed from server.c
(the old declaration remains in password.h). Write credentials use bounded NUL
parsing and full-capacity password erasure. No shared DB handle is introduced.

Configuration has static process lifetime so detached workers can safely borrow
it. Each heap connection context owns its socket and retained TLS-context reference;
worker and pthread_create failure cleanup release them once. Peer connection
cleanup saves the descriptor before freeing SSL, then closes it. Startup failures
never free the static configuration object. Normal and sanitizer regressions cover
startup failures and both worker types.

## Encoding

Commands are the ASCII verb bytes shown below, without fixed-width padding.
Other strings are NUL-terminated ASCII: username/password at most 64 characters
plus NUL; filename at most 256 characters plus NUL. Integers are big-endian.
Status occupies exactly one byte. The operation layouts below preserve the
frozen request shapes.

The local password prompt accepts up to 4096 bytes. Client request validation
rejects credentials above the 64-character wire limit before connecting. Client
strings must be nonempty printable ASCII; filenames also exclude path separators,
`.` and `..`. Values are never truncated.

| Byte | Status |
| --- | --- |
| 0 | OK |
| 1 | AUTH_FAILED |
| 2 | NOT_FOUND |
| 3 | EXISTS |
| 4 | BAD_REQUEST |
| 5 | TOO_LARGE |
| 6 | REPLICATION_FAILED |
| 7 | INTERNAL |

Unknown status bytes are client protocol errors, never availability failures. Status decoding is not implemented by the transport module.

## Operation layouts

```text
LIST request:      "LIST" username\0 password\0
LIST response:     status:u8
                   if OK: count:u32BE, then count filename\0 strings

DOWNLOAD request:  "DOWNLOAD" username\0 password\0 filename\0
DOWNLOAD response: status:u8
                   if OK: length:u32BE, exactly length raw file bytes

UPLOAD header:     "UPLOAD" username\0 password\0 size:u32BE filename\0
UPLOAD flow:       send header; read preliminary status
                   if not OK: stop, send no file bytes
                   if OK: send exactly size raw file bytes; read final status

DELETE request:    "DELETE" username\0 password\0 filename\0
DELETE response:   status:u8
```

## Server read handlers (implemented and wired into production)

`server_read_ops.h` exposes `server_read_context_t {data_dir, auth_db_path}`,
`server_read_io_t {state, read_exact, write_all, abort}`, and
`server_handle_list(io, context)` / `server_handle_download(io, context)`.
The dispatcher must consume exactly the literal verb first. Every callback
transfers exactly the requested byte count or returns failure. The handlers parse
bounded NUL fields (65-byte credentials, 257-byte filename), authenticate locally
through `server_auth`, and cleanse the **entire 65-byte password buffer** on every
parsing/authentication path. Unknown-user and wrong-password responses are identical.
Within these read handlers there is no peer connection, role decision, schema
provisioning or shared DB handle.

Responses are precisely the read layouts above: explicit numeric u8 status,
u32 big-endian count/size, and only the specified names or raw bytes. The returned
`server_read_result_t {status, complete}` is for local control/logging; it is **not
an instruction to send another status**. Complete includes a successfully sent
error response. Incomplete means the abort callback was invoked; log a generic
local failure and close/free transport without additional application output.
After any response, close the one-operation connection. Production `handle_request` owns response dispatch;
`handle_client` only handles TLS shutdown/cleanup and never appends a status.

Policies:

- Missing authenticated user folder: LIST is OK/count zero; DOWNLOAD is NOT_FOUND.
  Missing/unusable data root and inaccessible user directory are INTERNAL. Reads
  never create directories. User-directory symlinks/non-directories are INTERNAL.
- LIST includes only regular files with frozen-contract-valid names, sorted by
  bytewise lexicographic order. Directory entries, symlinks, non-ASCII/control or
  otherwise invalid filenames are excluded. At most 10,000 names are retained;
  a 10,001st eligible entry yields INTERNAL before any OK is sent.
- The current upload staging prefix `.temp_` is reserved: exclude it from LIST
  and return NOT_FOUND for DOWNLOAD. Other valid dotfiles are allowed. There is
  no additional metadata namespace in the current scaffold; coordinate any new
  internal naming convention with read filtering before introducing it.
- Open the trusted configured root, then authenticated username and filename
  using directory-relative APIs. User directories and download files use
  O_NOFOLLOW, and downloaded descriptors must be regular by fstat. Symlink files,
  directories and FIFOs return NOT_FOUND; local open/stat errors return INTERNAL.
  Root ancestors/DB configuration must be administrator-controlled. The service
  does not defend against privileged filesystem changes or cross-user hard links
  created by another local actor; provision permissions accordingly.
- DOWNLOAD uses at most 16 KiB per local read, accepts sizes through UINT32_MAX,
  and rejects larger files with TOO_LARGE. A short positive read is continued;
  premature EOF or local I/O failure aborts. After OK, **no extra error/status**
  can be sent on failure. File growth beyond the initial size is not streamed.
- LIST is not a snapshot transaction. Vanished entries are skipped; other stat
  failures yield INTERNAL before success. Open DOWNLOAD descriptors survive
  atomic rename/delete; in-place truncation is detected, but in-place same-size
  modification cannot guarantee snapshot consistency. Partner writes should
  publish committed files with rename and retain the staging convention.

`server_protocol_io` is the production TLS adapter. Initialize it only after
successful TLS handshake, with a positive timeout in milliseconds from the server
configuration (default 15 seconds). It sets the borrowed
socket nonblocking, tries SSL_read before polling, retries WANT_READ/WANT_WRITE,
and guards SIGPIPE in the calling thread. One monotonic deadline covers all
network I/O for the request/response, preventing per-byte timeout extension.
DB/disk latency and the caller's handshake are outside this adapter's deadline.
It does not restore blocking mode: the caller closes the connection after use.

Production hooks are complete: required startup DB configuration/preflight,
exact-verb dispatch, adapter initialization and read response ownership. Reads
remain role-neutral and use local disk/DB only. Tests cover the actual production
executable and completed client in addition to isolated module fixtures.

The shared bounded field/status helpers live in `server_protocol_fields.h`.
Legacy write I/O compatibility signatures now delegate to the SSL-first adapter,
which is necessary because dispatch leaves sockets nonblocking. Write helper calls
retain per-call deadlines; final write status uses the default 15-second timeout.
Client-facing handshake socket waits use the configured timeout and SIGPIPE is
ignored in production. Outbound replication connect/handshake lacks a configured
application deadline.

## Routing and failover

The client knows topology from `client.conf`; users address one logical service.
Client-side failover is implemented for LIST/DOWNLOAD: one primary attempt,
then at most one replica attempt for RESOLVE_ERROR, CONNECT_ERROR, TIMEOUT,
IO_ERROR or EOF during connect/request transmission/initial status reading.
Both attempts use the configured endpoints and verified TLS. The same transient
password is reused without a second prompt and cleansed after the whole operation.

The boundary is receipt of a **valid application status byte**. Every valid status
ends failover eligibility, including OK: failures reading count/length or payload
afterward are final. Unknown statuses, malformed replies, certificate/identity
failures, invalid CA/configuration, TLS negotiation errors and local failures
never trigger failover. Download staging is removed on handled transfer failures.

UPLOAD/DELETE always use the primary and never retry or fail over, including after
ambiguous connection loss. There are no general retry loops or backoff. A failed
replica attempt is final; the client does not return to the primary. Server-side
replica support is additionally exercised by the production two-node suite.

## Ownership boundary

Client transport/commands, password DB/admin, authentication integration, and
LIST/DOWNLOAD belong to the client/read/auth work. Shared codecs, server roles,
replica transaction endpoints, and replicated upload/delete prepare/commit belong
to replicated-write coordination. Shared dispatch/configuration changes require
coordination. Production dispatch/auth/read integration and the later role/peer
scaffolding already changed these shared files. Deployment, acceptance tests and
final documentation are shared responsibilities.

The acceptor polls a nonblocking listener at most 500 ms between shutdown checks;
SIGINT/SIGTERM only set a signal-safe flag. This avoids relying on listener
shutdown to wake accept on macOS. Listener shutdown and primary/replica worker survival have regression coverage;
shutdown is not a durable transaction recovery mechanism.

## Current partner-owned write integration

`server_config_t` and startup now support `--role primary|replica`,
`--replication-port`, `--coordinator-name` and `--peer-cert`. On primary,
`--coordinator-name` selects the replica destination. Replica opens separate
client and mTLS listeners; its client write gate returns REPLICATION_FAILED.
See [DEPLOYMENT.md](DEPLOYMENT.md) for explicit launch commands and trust setup.

Exact-verb dispatch consumes no username bytes. The protocol has no verb delimiter:
`LISTXalice\0...` means LIST for username Xalice, not an extended command.
Accepted primary writes use bounded credentials and size-before-filename UPLOAD
headers. The read handlers still own complete responses; dispatch must not append
a second read status.

Required client-facing completion contract is unchanged:

- UPLOAD: header, preliminary status; payload only after OK; final status only
  after required distributed completion. Zero bytes still require both statuses.
- DELETE: one final status after coordinated completion.
- Neither write retries or fails over. EXISTS/NOT_FOUND remain errors, not retry
  success. An ambiguous failure cannot be assumed to mean no remote mutation.

Implemented write behavior:

- UPLOAD sends preliminary OK before receiving payload. After staging and checked
  local close, primary prepares the replica, publishes locally, sends COMMIT and
  awaits confirmation. Replica stages exclusively and handles short writes/EINTR.
- DELETE prepares before local deletion; missing replica data fails with
  REPLICATION_FAILED and preserves primary data. Missing local data is NOT_FOUND.
- No peer configuration or an unavailable replica fails closed. Reads need no peer.
- Conflicting `(username, filename)` writes serialize through completion/cleanup;
  unrelated keys remain concurrent. Both nodes use short exclusive `.temp_XXXXXX`
  names, mode 0600, hidden by reads. Write-side reserved-prefix enforcement and
  broader no-follow containment are not implemented.
- Replica field readers take buffer capacity including NUL, while protocol maxima
  count content only. Username 64 and filename 256 parse without truncation;
  one-byte-over values fail. Host NAME_MAX is checked separately before write-side
  filesystem use. Unsupported upload components yield INTERNAL; DELETE yields
  NOT_FOUND. Full paths that exceed buffers are rejected, never shortened.
- Post-commit errors can leave an ambiguous distributed outcome. No retries,
  persistent journal, crash recovery or fsync durability guarantee are provided.
- Replica rejects an existing regular upload destination, but primary rename can
  replace a primary-only destination in divergent state. Fixed-width peer reads
  still assume complete TLS reads; some peer error paths append dispatcher errors.

See [protocol.md](protocol.md) for message shapes and [README.md](README.md) for
consolidated limitations. Explicit peer certificate trust remains the deployment
model; outbound peer hostname verification and SNI are absent.

## Validation boundaries

`make test` covers unit/fault tests, TLS mocks and production startup/read/write
framing checks. `make test-two-node` covers 23 real-node scenarios, including
replicated writes, outage/divergence, mTLS, failover and process survival.
`make test-contract-boundaries` covers 13 field/filesystem/concurrency tests.
`make test-server-write-correctness` covers seven groups of startup, conflicting
writes, disconnect, partial-payload and local-I/O fault cases.

`make acceptance` composes those four targets; `make acceptance-sanitize` runs the
same targets with ASan/UBSan. Focused targets remain available. Fault injection
is confined to dedicated test objects/binaries, never production builds. All these
suites pass in both modes; arbitrary crash recovery and peer fragmentation are
not proven by those results. See [README.md](README.md) for invocation examples.
