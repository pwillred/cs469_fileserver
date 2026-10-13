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

## Server authentication hook (module implemented, integration pending)

`server_auth.h` exposes `server_auth_verify(db_path, username, username_size,
password, password_size)` and `server_auth_to_error`. Sizes are decoded byte counts
including the final NUL, not padded array capacities. Credentials must be 1–64
characters; usernames follow DB policy `[A-Za-z0-9_-]`, and passwords use printable
ASCII. The module rejects malformed/nonterminated spans and cleanses the supplied
password span even on failure, without copying plaintext. The future caller must
also cleanse unused buffer capacity and parsing-error paths.

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

Future startup should add `--auth-db users.db` and `server_config_t.auth_db_path`.
The path and parent directories must be administrator-controlled, and its storage
must outlive worker use. Startup must not provision an empty replacement DB.
Future `read_and_verify_credentials()` integration must decode the frozen bounded
NUL-terminated fields, call the new API and explicitly map its result. It cannot
safely reuse the current unchecked fixed-width reader. No startup, worker-lifetime,
request-parser or legacy-stub changes are included in this isolated module chunk.

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

## Isolated server read handlers (implemented; production wiring pending)

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
After any response, close the one-operation connection. This requires bypassing
the legacy `handle_client` unconditional final `send_error` on the new read path.

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

`server_protocol_io` is an optional isolated TLS adapter. Initialize it only after
successful TLS handshake, with a positive timeout in milliseconds (future server
configuration can supply its existing 15-second policy). It sets the borrowed
socket nonblocking, tries SSL_read before polling, retries WANT_READ/WANT_WRITE,
and guards SIGPIPE in the calling thread. One monotonic deadline covers all
network I/O for the request/response, preventing per-byte timeout extension.
DB/disk latency and the caller's handshake are outside this adapter's deadline.
It does not restore blocking mode: the caller closes the connection after use.

Remaining coordinated hooks: provision each node's DB and directories; add the
startup auth DB path with safe worker lifetimes; parse literal verbs; initialize
the TLS adapter; dispatch reads on either role; honor complete/abort and sole
response ownership; retain primary-only writes and partner replication separately.
No changes to production server sources, worker lifecycle, writes, client contract
or `protocol.h` are part of this implementation. The test-only TLS harness and real
client validate these isolated handlers, not the production scaffold.

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

## Current checkout conflicts

The original server scaffold does not yet implement this contract:

- `handle_request()` reads eight command bytes for every verb.
- Credential/filename readers consume fixed 65/65/257-byte fields rather than
  reading through a NUL delimiter, and do not enforce termination.
- Upload reads filename before size, receives the payload immediately, and sends
  only the wrapper's final status. There is no preliminary acceptance status.
- Production LIST/DOWNLOAD still return success without response payloads or
  authentication; the new isolated handlers are not wired to that dispatcher.
- Status output takes one byte from an enum object rather than explicit u8 encoding.
- Password verification still always succeeds; roles/replication are not implemented.

These conflicts are recorded, not repaired here. TLS primitives can be tested
independently; production command interoperability still requires coordinated
server changes. Isolated read handlers now interoperate with the completed client
through a test-only TLS dispatcher.
