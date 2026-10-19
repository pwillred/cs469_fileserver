# Fileserver Wire Protocol

This is the frozen client-facing integration contract for the tested service.
The merged client is the baseline for client-facing bytes and
routing. Changes require coordination. See [README.md](README.md) for status,
[INTEGRATION_ASSUMPTIONS.md](INTEGRATION_ASSUMPTIONS.md) for module interfaces, and
[DEPLOYMENT.md](DEPLOYMENT.md) for local setup.

## 1. Scope and implementation status

The supported topology is **one primary and one replica**. Client reads use local
authentication/storage on either node; writes belong to primary. The replica has
a separate mTLS endpoint for coordinated writes. Accounts are administered locally
on each node, not replicated as files. Each client connection has its own thread.

Client commands, verified TLS, authentication, reads, read failover, role gates,
mTLS and coordinated writes pass the normal and sanitizer acceptance suites.
See the remaining limitations below; passing tests do not imply crash atomicity.

## 2. Common wire conventions

- TCP is immediately upgraded to TLS; no plaintext fallback.
- One operation per connection. UPLOAD has two status phases, not one response.
- Command verbs are literal ASCII bytes without NUL, delimiter or padding.
- Other strings are NUL-terminated printable ASCII. Credentials contain 1–64
  characters plus NUL; filenames contain 1–256 characters plus NUL. Read at most
  N+1 bytes for a maximum-N-character field; never truncate overlong input.
- Server usernames additionally follow `[A-Za-z0-9_-]`. Filenames exclude `/`,
  `\`, `.` and `..`. `.temp_` is internal staging space, hidden by read handlers;
  write-side enforcement remains incomplete.
- Multi-byte integers are unsigned 32-bit big-endian. The maximum representable
  size is UINT32_MAX (4 GiB minus one byte). Current server UPLOAD policy is 1 GiB.
- Status is exactly one byte; payload bytes have no delimiter or checksum field.
  TLS provides transport integrity. Disk and concurrency correctness are separate.

## 3. Client-visible statuses

| Byte | Status | Meaning |
| --- | --- | --- |
| 0 | OK | Success for this phase; upload preliminary OK is only acceptance |
| 1 | AUTH_FAILED | Unknown account or incorrect password |
| 2 | NOT_FOUND | Requested local file absent/unavailable under operation policy |
| 3 | EXISTS | Existing remote name rejected; not treated as success by client |
| 4 | BAD_REQUEST | Malformed/invalid request |
| 5 | TOO_LARGE | Size exceeds the applicable limit |
| 6 | REPLICATION_FAILED | Required replication failed; does not guarantee rollback after a commit decision |
| 7 | INTERNAL | Internal server failure |

Unknown status bytes are client protocol errors, not availability failures.
All nonzero statuses produce client failure, including EXISTS and NOT_FOUND.
Replica client-write rejection currently uses status 6. Status additions require
coordination; the client does not silently accept extensions.

## 4. Client operations (frozen layouts)

### LIST

```text
request:  "LIST" username\0 password\0
response: status:u8
          if OK: count:u32BE, then count filename\0 strings
```

The server returns sorted eligible regular-file names, excluding staging and
symlinks. Missing user directory means an empty list. Maximum count is 10,000;
server overflow returns INTERNAL. The client validates count and every name.

### DOWNLOAD

```text
request:  "DOWNLOAD" username\0 password\0 filename\0
response: status:u8
          if OK: size:u32BE, exactly size raw bytes
```

Zero bytes are valid. Missing files and excluded types/names return NOT_FOUND.
After OK, an incomplete transfer closes/aborts the connection; no extra status
can be appended to the payload. The client publishes only a complete local file
and refuses to overwrite an existing local destination.

### UPLOAD

```text
header:      "UPLOAD" username\0 password\0 size:u32BE filename\0
response 1:  preliminary status:u8
             if nonzero: client stops without sending payload
             if OK: client sends exactly size raw bytes
response 2:  final status:u8
```

Primary validates credentials, header/name/size and local filename capacity, then
sends preliminary OK before receiving payload. It stages locally and contacts the
replica after receiving the payload. Preliminary OK does not promise peer
availability or commit. Final OK follows local publication and replica commit
confirmation. Zero-byte uploads still require both statuses. Missing peer trust
or an unavailable replica fails closed; there is no local-only fallback.

Replica rejects an existing regular destination with EXISTS. Primary publication
uses rename, so a primary-only existing file can be replaced if the replica lacks
it. Use fresh names; this is not a general overwrite/reconciliation guarantee.

### DELETE

```text
request:  "DELETE" username\0 password\0 filename\0
response: one final status:u8
```

Primary authenticates, validates the name and local existence, prepares the
replica, unlinks locally, sends COMMIT and awaits confirmation before client OK.
Missing local files return NOT_FOUND. A missing replica copy produces
REPLICATION_FAILED and preserves the primary copy. Failed prepare does not delete
locally. No write retry or failover occurs.

## 5. Peer protocol and transaction states

These are the implemented peer message shapes. One outbound channel targets the configured
replica per write. Authentication is by mTLS, so no password is in the peer header.

```text
UPLOAD prepare: "UPLOAD" username\0 size:u32BE filename\0, exactly size bytes
DELETE prepare: "DELETE" username\0 filename\0
prepare reply:  0 = prepared/ready; nonzero = failure
primary decision: 0 = COMMIT; 1 = ABORT
commit confirmation: 0 = success; nonzero = failure
```

| Phase | Coordinator | Replica |
| --- | --- | --- |
| Prepare UPLOAD | Stage locally, send header and body | Validate and stage without publishing; send ready |
| Prepare DELETE | Check local file; send header | Check existence without deleting; send ready |
| Commit | After ready, rename/unlink locally; send COMMIT; await confirmation | Apply rename/unlink, then confirm |
| Abort | On local commit failure, attempt ABORT | Discard upload staging or preserve delete target |
| Completion | Return OK only after required confirmation | Close channel |

Actual prepare errors use client status values where implemented. Replica commit
handlers currently emit 0/1 confirmation bytes; these are success/failure flags,
not a new client-visible authentication result. Replica abort branches currently
send 0 before closing; the coordinator does not wait for an abort confirmation.
Some error paths also append a dispatcher error, so peer response ownership needs
repair. There is **no commit retry** or multi-replica coordination in current code.

The replica attempts to discard upload staging on pre-decision disconnect/timeout;
a prepared DELETE has not yet unlinked anything. Exact-maximum strings plus NUL
are accepted without truncation; over-limit or
unterminated fields fail. Fixed-width command/size reads still assume complete
fields in individual SSL_read calls; arbitrary peer fragmentation is not covered.

## 6. Failure, concurrency and durability limits

Writes require replica participation. Missing peer configuration or unavailable
replica produces REPLICATION_FAILED, without a local-only success path. Primary
reads remain independent of replica availability.

The coordinator commits locally before sending COMMIT/receiving confirmation. A
peer failure or lost acknowledgement in that window can leave one node changed
and the other unchanged. Status 6 or connection loss therefore does **not** imply
“no state changed.” The client never automatically retries, fails over writes, or
treats EXISTS/NOT_FOUND as successful retries. Manual inspection/reconciliation
may be needed; no recovery log or automated reconciliation exists.

Primary serializes conflicting writes by `(username, filename)` through replication
and cleanup; unrelated keys can run concurrently. Both nodes use exclusive
`.temp_XXXXXX` staging within the user directory, independent of destination name
length. Primary checks fwrite/ferror/fclose; replica handles short writes, EINTR,
zero/error writes and close failure. Failed uploads remove staging before return.

Wire filename capacity is 256 content bytes plus NUL. Local `NAME_MAX` may be 255
or otherwise smaller. Write handlers check the directory's limit before use;
unsupported UPLOAD names return INTERNAL, and DELETE returns NOT_FOUND for a name
that cannot identify a local file. DOWNLOAD returns INTERNAL on an unsupported
component. Full paths are bounded and rejected rather than truncated. No filesystem
is assumed to support the entire wire filename range.

Neither write implementation fsyncs file/directory state. There is no durable
transaction journal or crash reconciliation. Storage ancestors remain trusted;
write containment is less strict than directory-relative no-follow read access.

## 7. TLS, authentication and timeouts

The client verifies CA/certificate trust plus DNS/IP identity and requires TLS 1.2
or newer. Client requests carry credentials inside TLS. Replica client writes are
rejected at the role gate without authentication, after bounded header parsing. Both nodes otherwise verify
credentials against local read-only DB handles; accounts require manual provisioning.

Replication uses separate TLS contexts/listener, reusing each node's `-c/-k`.
Replica requires a peer certificate; both directions load trust from `--peer-cert`.
Outbound peer hostname/IP verification and SNI are absent. Exact peer-certificate
trust and broader CA trust have different identity implications; do not claim the
latter restricts access to a designated host. Trusted/untrusted peer cases pass
end-to-end acceptance using explicit peer certificates.

Credential storage is implemented PBKDF2-HMAC-SHA256: default 600,000 iterations,
16-byte random salts, 32-byte derived keys and stored KDF parameters. Verification
uses stored validated parameters and constant-time derived-key comparison; unknown
account/KDF timing is not equalized. Plaintext passwords are not stored.

Current timeout behavior is not one universal idle deadline:

- Client: default five-second connect/TLS deadline after synchronous resolution,
  and deadlines per I/O call. DNS resolution is not deadline-bounded.
- Server: `--timeout` defaults to 15 seconds. Read handlers use a configured network
  operation deadline; DB/disk work is outside it. Write helpers reset per-call
  deadlines, with several peer helpers using the default 15 seconds.
- Replica raw TLS uses configured socket timeouts. Outbound peer connect/handshake
  has no configured application deadline. This remains an implementation gap.

## 8. Read failover (merged client behavior)

LIST/DOWNLOAD try primary first, then replica at most once for RESOLVE_ERROR,
CONNECT_ERROR, TIMEOUT, IO_ERROR or EOF during connect, request transmission or
initial status read. Both attempts verify TLS and reuse the same transient password.

Receipt of **any valid application status, including OK**, ends eligibility.
Count/length/payload failures after OK are final. Certificate/identity failures,
invalid CA/config, TLS negotiation errors, malformed/unknown statuses and local
errors do not trigger failover. A replica failure is final; there is no return to
primary, general retry loop or backoff. UPLOAD/DELETE never retry or fail over.

## 9. Scope of guarantees

The single-primary/single-replica design uses explicit peer trust and no automatic
recovery or retries. Remote overwrite asymmetry, fragmented fixed-width peer
reads and duplicate error bytes on some peer failure paths remain limitations;
none changes the frozen client layouts. See [README.md](README.md) for the
consolidated known-limitations list.
