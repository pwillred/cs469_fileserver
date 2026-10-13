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
- Both nodes eventually authenticate locally. Unknown users and wrong passwords
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

All active operations authenticate through `server_auth`. The legacy
`verify_password` compatibility symbol is unused and fails closed. Write credentials
now use bounded NUL parsing and full-capacity password erasure. No shared DB handle
or boolean inversion is introduced.

Detached workers own deep copies of the data/DB paths and their scalar configuration,
plus an explicit SSL_CTX reference acquired before thread creation. The acceptor
may release its config/TLS reference on shutdown; workers finish using their own
resources and release them. No worker-pool or replication redesign is included.

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

Unknown status bytes map to INTERNAL/client protocol error, never availability
failure. Status decoding is not implemented by the transport module.

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
No peer connection, role decision, schema provisioning or shared DB handle exists.

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
Handshake socket waits use the configured timeout; a disconnected peer cannot
terminate the process with SIGPIPE. This is not a full transport/lifecycle redesign.

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
replica support is not established by these client/mock-server tests.

## Ownership boundary

Client transport/commands, password DB/admin, authentication integration, and
LIST/DOWNLOAD belong to the client/read/auth work. Shared codecs, server roles,
replica transaction endpoints, and replicated upload/delete prepare/commit belong
to replicated-write coordination. Shared dispatch/configuration changes require
coordination; this chunk makes none.

The acceptor polls a nonblocking listener at most 500 ms between shutdown checks;
SIGINT/SIGTERM only set a signal-safe flag. This avoids relying on listener
shutdown to wake accept on macOS. Existing workers finish independently.

## Remaining partner-owned write integration

Production command parsing now incrementally matches the four prefix-free literal
verbs at their exact lengths, without consuming the first username byte. Unknown
prefixes produce BAD_REQUEST when the transport remains writable; incomplete verbs
are deadline-bounded. The frozen contract has no separator after a verb: for
example, `LISTXalice\0secret\0` is LIST with username Xalice, so authentication
rejects an unknown account. It cannot be distinguished from a hypothetical extended
verb without changing the frozen wire protocol.

UPLOAD/DELETE now authenticate bounded NUL credentials. Filenames use bounded
NUL parsing and frozen printable-ASCII/no-separator validation. UPLOAD request
field order was corrected to size:u32BE then filename\0. Payload handling, local
rename/unlink, size limit, success semantics and the prepare/commit TODO remain
unchanged. No replication algorithm, peer acknowledgement or role behavior was added.

UPLOAD still lacks the preliminary acceptance status required by the completed
client. It receives the payload immediately and returns only a final local status;
therefore ordinary client UPLOAD remains incompatible until the partner implements
that workflow. Production regression tests exercise raw request/auth framing and
known local effects, and explicitly check that no preliminary OK was fabricated.
DELETE continues to return one final local status. The legacy write filesystem
and local fwrite/error handling are unchanged and still require partner hardening.

Remaining work: primary/replica role enforcement, mTLS peer endpoints, synchronous
replicated writes/prepare-commit, UPLOAD acceptance/final-status integration and
write-failure consistency. Provision credentials and directories on both nodes;
credential DBs remain outside file replication. Client code and `protocol.h` are
unchanged by this integration patch.
