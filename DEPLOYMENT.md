# Local Two-Node Demo

This walkthrough uses actual binaries and disposable local credentials/certificates.
Run the shell blocks in order in one terminal, from the repository root. Use a
fresh workspace for each run. Commands prompt interactively for passwords; enter
the same demo password each time. No production credentials are needed.

## 1. Build and choose a temporary workspace

Use one Bash session (`bash`) from the repository root for the following steps.
On macOS/Homebrew:

```sh
make OPENSSL_PREFIX="$(brew --prefix openssl@3)"
openssl_cli="$(brew --prefix openssl@3)/bin/openssl"
```

On a system with development libraries in standard locations, use `make` and
`openssl_cli=openssl` instead. Python 3 is needed for dynamic port selection.

```sh
set -e
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
itself, including on failure, and has bounded terminate/kill cleanup. Outbound
peer setup is not fully deadline-bounded; this demo uses local peers.

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
a broad CA and assume it restricts access to the intended peer. The two-node suite
covers both trusted and untrusted peer connections.

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
wait_ready() {
  python3 - "$1" "$2" <<'PY_READY'
import os, sys, time
from pathlib import Path
pid, log = int(sys.argv[1]), Path(sys.argv[2])
for _ in range(100):
    os.kill(pid, 0)
    if log.exists() and 'Server listening' in log.read_text(errors='replace'):
        break
    time.sleep(0.1)
else:
    raise SystemExit('Listener not ready: inspect ' + str(log))
PY_READY
}
start_replica
wait_ready "$replica_pid" "$demo_dir/replica.log"
start_primary
wait_ready "$primary_pid" "$demo_dir/primary.log"
```

The readiness helper waits for the post-listen banner without creating an extra
worker connection. On error, inspect `primary.log` and `replica.log` before
continuing. `--coordinator-name` is the replica destination on primary. Both peers
need explicit trust; missing primary peer configuration never permits local-only
write success. There is no `--standalone` option.

## 5. Configure client, LIST, UPLOAD, LIST, DOWNLOAD

```sh
cat > "$demo_dir/client.conf" <<EOF_CLIENT
primary_host=127.0.0.1
primary_port=$primary_port
replica_host=127.0.0.1
replica_port=$replica_port
ca_file=$demo_dir/trust.pem
EOF_CLIENT
./client --config "$demo_dir/client.conf" --username alice list
printf 'CS469 replicated upload demo\n' > "$demo_dir/upload.txt"
./client --config "$demo_dir/client.conf" --username alice \
  upload "$demo_dir/upload.txt" uploaded.txt
./client --config "$demo_dir/client.conf" --username alice list
./client --config "$demo_dir/client.conf" --username alice \
  download uploaded.txt "$demo_dir/from-primary.txt"
cmp "$demo_dir/upload.txt" "$demo_dir/from-primary.txt"
cmp "$demo_dir/upload.txt" "$demo_dir/primary/data/alice/uploaded.txt"
cmp "$demo_dir/upload.txt" "$demo_dir/replica/data/alice/uploaded.txt"
```

The first LIST is empty; the second shows `uploaded.txt`. The replica copy comes
from replication, not manual copying. DOWNLOAD refuses existing local destinations;
use fresh local names if repeating a step. Each command prompts once.

## 6. Stop primary and demonstrate read failover

```sh
kill "$primary_pid"
wait "$primary_pid"
primary_pid=
./client --config "$demo_dir/client.conf" --username alice list
./client --config "$demo_dir/client.conf" --username alice \
  download uploaded.txt "$demo_dir/from-replica.txt"
cmp "$demo_dir/upload.txt" "$demo_dir/from-replica.txt"
kill -0 "$replica_pid"
```

Both commands report `Primary server unavailable; trying replica...` and succeed.
Failover is only eligible before a valid application status. Writes never retry
or fail over. Restart primary before deleting:

```sh
start_primary
wait_ready "$primary_pid" "$demo_dir/primary.log"
./client --config "$demo_dir/client.conf" --username alice delete uploaded.txt
test ! -e "$demo_dir/primary/data/alice/uploaded.txt"
test ! -e "$demo_dir/replica/data/alice/uploaded.txt"
./client --config "$demo_dir/client.conf" --username alice list
```

## 7. Stop replica and demonstrate fail-closed writes

```sh
kill "$replica_pid"
wait "$replica_pid"
replica_pid=
# Primary reads remain available; this LIST is empty.
./client --config "$demo_dir/client.conf" --username alice list
if ./client --config "$demo_dir/client.conf" --username alice \
    upload "$demo_dir/upload.txt" outage.txt; then
  echo 'Unexpected write success during replica outage' >&2
  exit 1
fi
test ! -e "$demo_dir/primary/data/alice/outage.txt"
test ! -e "$demo_dir/replica/data/alice/outage.txt"
start_replica
wait_ready "$replica_pid" "$demo_dir/replica.log"
kill -0 "$primary_pid"
kill -0 "$replica_pid"
```

The client exits nonzero with REPLICATION_FAILED (status 6). This outage occurs
before commit and leaves no published file. More generally, an error after the
commit decision may mean the client cannot confirm the final distributed outcome;
never infer guaranteed rollback or automatically retry.

## 8. Stop and remove the disposable demo

```sh
cleanup_demo
primary_pid=
replica_pid=
trap - EXIT
# Remove only the fresh mktemp workspace created above, after nodes stop.
rm -rf -- "$demo_dir"
```

The EXIT trap stops recorded server processes on early exit but retains files for
diagnostics. On an interrupted run, stop those processes before deleting that
workspace. Never reuse these disposable certificates for deployment. The automated
acceptance harness provides bounded cleanup and independently exercises the same
operations. No passwords, keys or database files belong in the repository.
