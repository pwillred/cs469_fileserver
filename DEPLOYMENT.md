# Local Two-Node Demo

This is a **local development/reproduction guide**, not a working distributed
release. At `7c96481`, primary reads work, but replica requests can return data
then crash; replication-port connections can crash/reset; UPLOAD acceptance is
missing. Run `make test-two-node` for automated isolated reproduction. Replicated
write success below is an acceptance goal **after fixes**, not a current result.

## 1. Build and choose a temporary workspace

Use one POSIX shell session from the repository root for the following steps.
On macOS/Homebrew:

```sh
make OPENSSL_PREFIX="$(brew --prefix openssl@3)"
openssl_cli="$(brew --prefix openssl@3)/bin/openssl"
```

On a system with development libraries in standard locations, use `make` and
`openssl_cli=openssl` instead. Python 3 is needed for dynamic port selection.

```sh
project_dir="$PWD"
umask 077
demo_dir=$(mktemp -d "${TMPDIR:-/tmp}/cs469-demo.XXXXXX")
mkdir -p "$demo_dir/primary/data" "$demo_dir/replica/data"
primary_pid=
replica_pid=
cleanup_demo() {
  for demo_pid in "$primary_pid" "$replica_pid"; do
    if [ -n "$demo_pid" ]; then
      kill "$demo_pid" 2>/dev/null || true
    fi
  done
  for demo_pid in "$primary_pid" "$replica_pid"; do
    if [ -n "$demo_pid" ]; then
      wait "$demo_pid" 2>/dev/null || true
    fi
  done
}
trap cleanup_demo EXIT
```

Manual-demo files remain until the cleanup step; they contain private keys and
credential DBs. Do not commit them. The automated harness removes its fixtures
itself, including on failure, and has bounded terminate/kill cleanup. Manual
shutdown can wait on a stuck worker because current peer setup is not fully bounded.

## 2. Provision independent accounts and directories

```sh
./admin "$demo_dir/primary/users.db" init
./admin "$demo_dir/replica/users.db" init
./admin "$demo_dir/primary/users.db" add alice
./admin "$demo_dir/replica/users.db" add alice
mkdir -p "$demo_dir/primary/data/alice" "$demo_dir/replica/data/alice"
```

Enter the same password interactively on both nodes (1–64 printable ASCII
characters for client use). No password appears in command arguments. Independent
salts/hashes are expected; do not compare DB bytes. Repeat later password changes
or account deletions on both nodes. Admin does not create user directories.

Seed both disks manually for read/failover demonstrations. This is **not** evidence
of replication:

```sh
printf 'CS469 read demo\n' > "$demo_dir/primary/data/alice/hello.txt"
cp "$demo_dir/primary/data/alice/hello.txt" "$demo_dir/replica/data/alice/hello.txt"
```

## 3. Generate temporary test identities and trust

The current server reuses its `-c/-k` identity for client-facing TLS and peer mTLS.
Use distinct self-signed subjects with SANs matching the test addresses and both
serverAuth/clientAuth usages. These are disposable local identities, not a
production PKI. Unlike the basic `cert_gen.sh`, this supplies explicit SANs and
purpose extensions and verifies them before launch.

```sh
for node in primary replica; do
  cat > "$demo_dir/$node/openssl.cnf" <<EOF_CERT
[req]
distinguished_name=dn
x509_extensions=ext
prompt=no
[dn]
CN=$node.localhost
[ext]
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:TRUE
extendedKeyUsage=serverAuth,clientAuth
EOF_CERT
  "$openssl_cli" req -x509 -newkey rsa:2048 -nodes -days 1 \
    -config "$demo_dir/$node/openssl.cnf" \
    -keyout "$demo_dir/$node/key.pem" -out "$demo_dir/$node/cert.pem"
  chmod 600 "$demo_dir/$node/key.pem"
done
cat "$demo_dir/primary/cert.pem" "$demo_dir/replica/cert.pem" > "$demo_dir/trust.pem"
for node in primary replica; do
  "$openssl_cli" verify -CAfile "$demo_dir/trust.pem" \
    -verify_ip 127.0.0.1 "$demo_dir/$node/cert.pem"
done
```

Client trust includes both identities and checks the configured IP/DNS identity.
Each server trusts only the other node's certificate for this demo. Replica mTLS
requires a client certificate; primary presents its own identity. Current outbound
replication code does not perform hostname/IP verification or SNI. Do not substitute
a broad CA and assume it restricts access to the intended peer. The application
still has lifecycle defects regardless of valid certificates.

## 4. Choose ports and define launch commands

Select three distinct unused loopback ports. There is a small release-to-bind race;
if a port is taken before startup, select new ports and regenerate client config.
The servers themselves bind all IPv4 interfaces; use a trusted local test machine.

```sh
ports=$(python3 - <<'PY_PORTS'
import socket
sockets = [socket.socket() for _ in range(3)]
try:
    for sock in sockets:
        sock.bind(('127.0.0.1', 0))
    print(' '.join(str(sock.getsockname()[1]) for sock in sockets))
finally:
    for sock in sockets:
        sock.close()
PY_PORTS
)
read -r primary_port replica_port replication_port <<EOF_PORTS
$ports
EOF_PORTS

start_replica() {
  "$project_dir/server" \
    -p "$replica_port" -c "$demo_dir/replica/cert.pem" -k "$demo_dir/replica/key.pem" \
    -d "$demo_dir/replica/data" --auth-db "$demo_dir/replica/users.db" \
    --role replica --replication-port "$replication_port" \
    --peer-cert "$demo_dir/primary/cert.pem" --timeout 3 \
    > "$demo_dir/replica.log" 2>&1 &
  replica_pid=$!
}
start_primary() {
  "$project_dir/server" \
    -p "$primary_port" -c "$demo_dir/primary/cert.pem" -k "$demo_dir/primary/key.pem" \
    -d "$demo_dir/primary/data" --auth-db "$demo_dir/primary/users.db" \
    --role primary --replication-port "$replication_port" \
    --coordinator-name 127.0.0.1 --peer-cert "$demo_dir/replica/cert.pem" --timeout 3 \
    > "$demo_dir/primary.log" 2>&1 &
  primary_pid=$!
}
start_replica
start_primary
```

Inspect each log for `Server listening` before using the client:

```sh
cat "$demo_dir/replica.log" "$demo_dir/primary.log"
kill -0 "$replica_pid"
kill -0 "$primary_pid"
```

If banners are not yet present, inspect again; if a process exited, read its log
before continuing. Avoid TCP port probes: accepting a connection can trigger the
known replica defect. `--coordinator-name` is the **replica destination on primary**,
not the primary's own advertised name. Do not omit `--peer-cert`: primary currently
silently enables local-only writes in that case. There is no `--standalone` option.

## 5. Configure the actual client and test primary reads

```sh
cat > "$demo_dir/client.conf" <<EOF_CLIENT
primary_host=127.0.0.1
primary_port=$primary_port
replica_host=127.0.0.1
replica_port=$replica_port
ca_file=$demo_dir/trust.pem
EOF_CLIENT
./client --config "$demo_dir/client.conf" --username alice list
./client --config "$demo_dir/client.conf" --username alice \
  download hello.txt "$demo_dir/from-primary.txt"
cmp "$demo_dir/primary/data/alice/hello.txt" "$demo_dir/from-primary.txt"
```

Each command prompts once. DOWNLOAD refuses an existing destination, so use a new
local filename when repeating it. LIST should show `hello.txt` and DOWNLOAD should
match the manually seeded bytes. Do not count a response as success for process
lifetime: check that both server processes remain alive.

## 6. Exercise read failover and inspect replica lifetime

```sh
kill "$primary_pid"
wait "$primary_pid"
primary_pid=
./client --config "$demo_dir/client.conf" --username alice list
kill -0 "$replica_pid"
```

The client should report `Primary server unavailable; trying replica...`. Current
code may return the correct list and then crash the replica. A failed `kill -0`
is a known failing integration outcome, not proof of working redundancy. Inspect
`replica.log`; use `make sanitize-two-node` for the invalid-free diagnostic.

For an independent DOWNLOAD failover reproduction, restart replica if it exited
(`wait "$replica_pid"` to reap it, then `start_replica` and inspect the banner).
Keep primary stopped and use:

```sh
./client --config "$demo_dir/client.conf" --username alice \
  download hello.txt "$demo_dir/from-replica.txt"
kill -0 "$replica_pid"
```

The same cleanup crash may follow DOWNLOAD. Once fixed, both commands must leave
replica alive. A connection error after a valid application status does not cause
a second read attempt; writes never fail over.

## 7. Replicated write demonstration — only after fixes

First pass the two-node acceptance suite. Ensure both processes are running,
restarting stopped/exited nodes with the functions above and checking banners.
Use a fresh remote name. The following are **target acceptance steps**, not
currently passing instructions:

```sh
printf 'Replicated upload demo\n' > "$demo_dir/upload.txt"
./client --config "$demo_dir/client.conf" --username alice \
  upload "$demo_dir/upload.txt" uploaded.txt
cmp "$demo_dir/upload.txt" "$demo_dir/primary/data/alice/uploaded.txt"
cmp "$demo_dir/upload.txt" "$demo_dir/replica/data/alice/uploaded.txt"
./client --config "$demo_dir/client.conf" --username alice delete uploaded.txt
test ! -e "$demo_dir/primary/data/alice/uploaded.txt"
test ! -e "$demo_dir/replica/data/alice/uploaded.txt"
```

Current UPLOAD lacks preliminary OK and replication connections can crash/reset.
Do not send payload early or alter the client to bypass this. After fixes, also
stop replica and confirm primary reads work while writes return replication
failure without unintended local changes. The harness automates these checks.
An error after commit can leave an unknown outcome; do not automatically retry.

## 8. Stop and remove the disposable demo

```sh
cleanup_demo
primary_pid=
replica_pid=
trap - EXIT
# Remove only the fresh mktemp workspace created in step 1, after nodes stop.
rm -rf -- "$demo_dir"
```

If a current worker hangs during manual shutdown, terminate that recorded server
PID before removing its files. Never reuse these demo certificates for deployment.
