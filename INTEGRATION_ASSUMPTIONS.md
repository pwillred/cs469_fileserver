# Working integration contract — subject to coordinated changes

This is the team's working client integration contract, not an instructor-provided
specification. Changes require coordination between client/read/authentication
work and server/protocol/replicated-write coordination. Transport primitives do
not implement these messages yet.

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

The existing local password prompt accepts up to 4096 bytes. Future request
encoding must reject credentials that exceed the 64-character wire limit or
violate ASCII requirements; it must never truncate them silently.

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
LIST/DOWNLOAD start with the primary and may fail over only for eligible
connection/transport unavailability. UPLOAD/DELETE always use the primary and
never fail over. Certificate/identity failures and invalid trust configuration
must fail closed, not trigger failover. All application status responses above
are **not failover triggers**. Future callers must track response/transfer progress
before deciding whether a read can safely restart. No retry/failover exists yet.

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
