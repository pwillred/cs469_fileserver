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
- LIST/DOWNLOAD return success without response payloads or authentication.
- Status output takes one byte from an enum object rather than explicit u8 encoding.
- Password verification still always succeeds; roles/replication are not implemented.

These conflicts are recorded, not repaired here. TLS primitives can be tested
independently, but command interoperability requires coordinated server changes.
