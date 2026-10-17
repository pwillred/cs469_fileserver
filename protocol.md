# Fileserver Wire Protocol

Scope: client ↔ server wire protocol for the CS469 fileserver project, plus the
server-side behaviors it implies (replication, security, failover).

## 1. Overview

A small FTP-like file service. A user can:

- `LIST` — list the files they have uploaded
- `UPLOAD` — upload a file
- `DOWNLOAD` — retrieve a file
- `DELETE` — remove a file

Two server nodes run in a replicated pair.  One server is the primary that accepts read/write
requests.  The other is a secondary replica that accepts read-only requests.  All traffic 
(client ↔ server and server ↔ server) is TLS-encrypted.

## 2. System architecture (summary)

- Two server nodes, each a C/POSIX process, one handler thread per client
  connection.
- Files are stored in a per-user directory (`<root>/<username>/<filename>`).
  A user can only ever see or touch their own files.
- Usernames, salted password hashes, and salts live in a local SQLite database.
  Accounts are created with a small administrative CLI tool, not over the
  network protocol.
- Node-to-node replication is authenticated with mutual TLS (client
  certificates), not username/password.
- Reads (`LIST`, `DOWNLOAD`) are served from local disk. Writes (`UPLOAD`,
  `DELETE`) are applied locally, synchronously replicated to the peer, and only
  acknowledged to the client once both nodes have committed. If the peer is
  unreachable, writes are rejected; reads continue.

## 3. Wire conventions

- **Connection model:** exactly one operation per TCP connection. The client
  connects, performs the operation, receives the complete response, and closes.
  No framing is needed beyond the message formats below because there is at
  most one request and one response per connection.
- **Transport:** every connection is upgraded to TLS immediately. No plaintext
  traffic is accepted. Credentials are never sent outside a TLS channel.
- **Integers:** all multi-byte integers are big-endian (network byte order).
- **Strings:** null-terminated ASCII. A field "no longer than N bytes" means at
  most N characters plus one null terminator on the wire (N+1 bytes). A
  receiver that reads N bytes and has not seen the null must abort the
  connection with `BAD_REQUEST` (4) — never truncate.
- **Filenames:** 1–256 characters, ASCII, and must not contain `/`. The names
  `.` and `..` are rejected. This guarantees a name is always a single flat
  entry inside the user's directory (no path traversal, no subdirectories).
- **File sizes/lengths:** 32-bit unsigned integers, big-endian. This caps any
  file at 4 GiB; larger files are out of scope.
- **Timeouts:** the server applies an idle timeout to every read (header and
  payload). A client that stalls mid-upload is disconnected and any partial
   state is discarded. (Concrete value: open issue, §11.)

## 4. Error codes

Returned in the 1-byte status field of every response.

| Code | Name                | Meaning                                                                           |
|------|---------------------|-----------------------------------------------------------------------------------|
| 0    | `OK`                | Success.                                                                          |
| 1    | `AUTH_FAILED`       | Unknown username or wrong password                                                |
| 2    | `NOT_FOUND`         | Named file does not exist in the user's directory.                                |
| 3    | `EXISTS`            | File already exists (`UPLOAD` only). Client must `DELETE` first.                  |
| 4    | `BAD_REQUEST`       | Malformed message: bad verb, over-long string, invalid filename, etc.             |
| 5    | `TOO_LARGE`         | Declared size exceeds a server limit (e.g., disk quota/space).                    |
| 6    | `REPLICATION_FAILED`| Secondary node unavailable or refused the write; the operation was not performed. |
| 7    | `INTERNAL`          | Unexpected server error.                                                          |

This set is a proposal and is subject to extension; new codes may be added
in later revisions. Unrecognized codes must be treated as `INTERNAL` by clients.

## 5. Operations

### 5.1 LIST

Request:

```
+--------+---------------------------+---------------------------+
| "LIST" | username (<=64 + NUL)     | password (<=64 + NUL)     |
+--------+---------------------------+---------------------------+
   4 B               variable                  variable
```

Response (all cases):

```
+----------+
| status   |
+----------+
   1 B
```

On `OK`, immediately followed by:

```
+----------------------+-----------------------------------------+
| count (uint32 BE)    | count filenames, each <=256 chars + NUL |
+----------------------+-----------------------------------------+
     4 B                         variable
```

- `count` is the number of files in the user's directory (a flat namespace —
  there are no subdirectories). `count = 0` on an empty directory.
- The client must read exactly `count` null-terminated strings.

### 5.2 UPLOAD

Request (header only):

```
+----------+-------------------+--------------------+-------------------+------------------------+
| "UPLOAD" | username (<=64+NUL)| password (<=64+NUL)| size (uint32 BE)  | filename (<=256 + NUL) |
+----------+-------------------+--------------------+-------------------+------------------------+
    6 B              variable               variable          4 B               variable
```

`size` is the exact number of file-data bytes that follow, if accepted.

Response 1 (after header):

```
+----------+
| status   |
+----------+
```

- The server validates, in order: request format; authentication; filename
  rules; `size` against server limits; peer liveness (it is a write); and that
  no file with that name already exists.
- `EXISTS` (3) if the name is taken. `REPLICATION_FAILED` (6) if the peer is
  unavailable. The client sends **no file data** unless status is `OK`.
- On `OK`, the client streams exactly `size` bytes of raw file data, then
  reads:

Response 2 (after file data):

```
+----------+
| status   |
+----------+
```

- `OK` only after the file is durably stored on **both** nodes (see §7).
- Any failure during the transfer (timeout, disk error, replication failure)
  returns a non-zero status and the server discards its partial state.

### 5.3 DOWNLOAD

Request:

```
+------------+--------------------+---------------------+------------------------+
| "DOWNLOAD" | username (<=64+NUL)| password (<=64+NUL)  | filename (<=256 + NUL) |
+------------+--------------------+---------------------+------------------------+
    8 B              variable              variable             variable
```

Response:

```
+----------+
| status   |
+----------+
   1 B
```

On `OK`, immediately followed by:

```
+----------------------+-----------------------------+
| length (uint32 BE)   | length bytes of file data    |
+----------------------+-----------------------------+
     4 B                      variable
```

- `length` equals the on-disk file size. The client reads exactly `length`
  bytes. A file of size 0 yields `length = 0` and no data bytes.
- `NOT_FOUND` (2) if the file does not exist.

### 5.4 DELETE

Request:

```
+----------+--------------------+--------------------+------------------------+
| "DELETE" | username (<=64+NUL)| password (<=64+NUL)| filename (<=256 + NUL) |
+----------+--------------------+--------------------+------------------------+
    6 B              variable             variable             variable
```

Response:

```
+----------+
| status   |
+----------+
   1 B
```

- The server authenticates, checks the file exists (`NOT_FOUND` otherwise),
  confirms peer liveness (it is a write — `REPLICATION_FAILED` if unavailable),
  then deletes locally, replicates the deletion, and acknowledges only after
  both nodes have committed.

## 6. Server-side processing notes

- **Atomicity:** uploads are written to a temporary file in the user's
  directory and `rename()`d into place only after local commit (and, for the
  client ack, after peer commit). A crash mid-write can therefore never leave
  a partial file under its final name. On any failure path the temp file is
  unlinked.
- **Concurrent same-name uploads:** In shared memory, the primary fileserver
  maintains a set of uploads in progress.  An upload with a duplicate name is 
  immediately rejected.  .
- **Reads during peer outage:** `LIST` and `DOWNLOAD` are served from local
  disk with no peer involvement by both the primary and replica, so the service 
  degrades to read-only rather than going down.
- **No in-band checksum:** file-data integrity is provided by TLS; the
  protocol does not add a checksum field.

## 7. Replication and consistency

- Model: synchronous replication on every write. The primary node that receives 
  client request prepares the operation locally, sends the same operation to
  its replicas over a dedicated TLS (mTLS) replication channel, and acknowledges
  the client only after the replicas confirms they committed as well.
- `DELETE` is a write and uses the same coordinate-then-ack flow as `UPLOAD`.
- If the replica is unreachable or refuses, the write is rejected with
  `REPLICATION_FAILED` and no state is changed on the receiving node.
- Crash window: the primary can have fully prepared replicas, commit locally and 
  have a replica crash before it commits the transaction.  The client will then see 
  a connection error and may retry the write. On retry an upload of an already-applied name returns 
  `EXISTS`, which the client treats as success (the file is present), and a delete of an
  already-applied name returns `NOT_FOUND`, also treated as success.
- The node-to-node message format and the prepare/commit exchange are. Every client-visible operation is
  specified in §8.

## 8. Write coordination between nodes (UPLOAD and DELETE)

Primary/secondary replication reuses the client wire protocol (§3 conventions:
big-endian, null-terminated strings), omitting the password field — channel
authentication is the mTLS client certificate, so no in-band credential is
needed. Each write opens one replication channel per peer, one per operation,
and the channel closes when the operation completes.

All writes use a two-phase prepare/commit exchange. The flow is identical for a 
2-node or 3-node cluster — with more nodes the primary simply requires a successful 
prepare from *all* peers before it commits, and every replica waits on the primary's byte
before applying the write.

### 8.1 UPLOAD

1. The primary receives the file from the client and writes it to a local
   temp file (§6).
2. For each replica, the primary opens a replication channel and sends the
   header (§5.2 layout, minus the password field), followed by exactly
   `size` bytes of file data:

   ```
   +----------+--------------------+-------------------+------------------------+
   | "UPLOAD" | username (<=64+NUL)| size (uint32 BE)  | filename (<=256 + NUL) |
   +----------+--------------------+-------------------+------------------------+
    6 B               variable           4 B               variable
   ```

3. Each replica validates the header (format, filename rules, size
   limit, name not already present), writes the data to its own temp file, and
   replies with one byte:
   - `0` = prepared. The host then waits for the commit byte (step 4).
   - non-zero = failure, using the §4 codes (e.g. `EXISTS`, `TOO_LARGE`,
     `INTERNAL`). The replica unlinks its temp file and closes the channel.
4. A prepared replica waits for one byte from the coordinator (idle
   timeout applies; a timeout is treated as abort, which covers a crashed
   coordinator):
   - `0` = commit → rename its temp file to the indicated filename, send one
     confirmation byte back to the coordinator (`0` = success, non-zero =
     failure), and terminate.
   - `1` = abort → unlink its temp file and terminate.
5. The primary waits for the prepare byte from every peer:
   - All prepared: the primary renames its own temp file to the final
     filename, sends commit (`0`) to every replica, waits for every replica's
     confirmation byte, then returns `OK` to the client. A replica that fails to
     confirm gets one commit retry; if it still fails, the primary returns
     `REPLICATION_FAILED` (6) to the client even though the other replicas
     committed — a client retry against the other node converges (§7).
   - Any replica failed to prepare: the coordinator unlinks its own temp
     file, sends abort (`1`) to every peer that prepared, and returns
     `REPLICATION_FAILED` (6) to the client.

Net effect: a file appears under its final name on a replica host only
after the primary has decided to commit. .

### 8.2 DELETE

1. The primary validates the request as in §5.4 (authentication, filename
   rules, local file existence, peer liveness).
2. For each replica, the primary sends over a replication channel (the §5.4
   layout, minus the password field):

   ```
   +----------+--------------------+------------------------+
   | "DELETE" | username (<=64+NUL)| filename (<=256 + NUL) |
   +----------+--------------------+------------------------+
    6 B               variable              variable
   ```

3. Each replica checks that the file exists in its copy of the user's
   directory and replies with one byte:
   - `0` = ready. The host then waits for the commit byte (step 4).
   - `2` = `NOT_FOUND` — the file is absent on this node. That indicates state
     divergence; it is treated as a failure and logged by the primary
     (§8.3). Other §4 codes may be returned for validation problems. The host
     closes the channel and deletes nothing.
4. A ready replica waits for one byte from the primary (idle
   timeout applies; timeout = abort):
   - `0` = commit → delete the file, send one confirmation byte to the
     primary (`0` = success, non-zero = failure), and terminate.
   - `1` = abort → leave the file in place and terminate.
5. The primary waits for readiness from every replica:
   - All ready: the primary deletes its own copy, sends commit (`0`)
     to all replicas, waits for all confirmations, and returns `OK` to the
     client (same retry / `REPLICATION_FAILED` fallback as §8.1).
   - Any replica not ready: the primary leaves its own file in place,
     sends abort (`1`) to the ready replicas, and returns `REPLICATION_FAILED`
     (6) to the client.

### 8.3 Coordinator crash mid-commit

The prepare→commit window is the same crash window described in §7: a
coordinator that dies after deciding to commit but before its commit byte
reaches a peer leaves that peer's wait to time out, so the peer aborts while
the surviving node(s) commit. Since the decision was commit, the correct
converged state is the post-write state; the restart/resync procedure (open
issue, §11) must reconcile the nodes toward it.

Note: the post-commit confirmation byte (steps 4/5 above) is an addition to
the initial sketch — it lets the coordinator verify each peer's final
rename/delete actually succeeded before it acknowledges the client. The
prepare→commit structure itself is as sketched.

## 9. Security

- **Transport:** TLS on every connection (client ↔ server, node ↔ node).
- **Authentication:** every request carries username + password; the server
  verifies the password against the stored salted hash and rejects with
  `AUTH_FAILED` on any mismatch. Hashes are compared in constant time.
- **Credential storage:** SQLite stores usernames, salts, and salted hashes
  only — never plaintext passwords. Proposed KDF: PBKDF2-HMAC-SHA256 via
  OpenSSL, iteration count an open issue (§11). Accounts are provisioned
  offline by the admin CLI.
- **Data isolation:** per-user directories mean authentication doubles as
  access control — a session can only ever list, download, or delete files
  in its own directory. No cross-user visibility by construction.
- **Path traversal:** prevented by the filename rules in §3 (no `/`, no `.`/
  `..`), enforced server-side before any filesystem operation.

## 10. Client failover behavior

- The client is configured with both server addresses (a preferred "primary"
  and a peer). The user interacts with one logical file service.
- On a connection-level failure (cannot connect, TLS handshake failure,
  or a dropped mid-operation connection), the client transparently retries the
  same operation against the other node, at most once, then reports failure.
- On `REPLICATION_FAILED` (6) the client immediately reports the error and will
  not retry the request. 
- Operation-level errors (`AUTH_FAILED`, `NOT_FOUND`, `EXISTS`, `TOO_LARGE`,
  …) are not retried against the peer; they are returned to the user.

## 11. Open issues

- Exact idle-timeout value for header and upload-payload reads.  
- PBKDF2 iteration count / any per-user disk quota (basis for `TOO_LARGE`).
- Replication: restart/resync procedure to reconcile nodes after a
  coordinator crash mid-commit (§8.3), and the idle-timeout value for a
  replicating host waiting on the commit byte.
- Whether to allow uploading an empty file (`size = 0`). Current draft: yes.
