# Running the Nebula stack without Docker

The Docker Compose file remains available, but the repo now ships with a process
runner so you can launch Hyperledger Fabric and the API gateway entirely as host
processes. This mode is useful on machines where Docker is not allowed or when
you want faster iteration loops.

The process stack is functionally equivalent to the Docker stack:

- The same MSP material under `api-gateway/organizations/` is reused.
- `scripts/bootstrap.sh` runs from the host to (re)create the channel, join peers,
  and deploy the `gateway` chaincode.
- The Go API server is compiled from `api/cmd/gateway`, so authentication,
  whitelist registration, convergence tracking, and data/model APIs behave exactly
  like they do in Docker. Every request you issue in Docker works unmodified in
  process mode.

## 1. Prerequisites

From the repo root (`thesis-blockchain/`):

1. Install the Fabric binaries and samples if you have not already:
   ```bash
   ./install-fabric.sh binary samples
   ```
   This drops `orderer`, `peer`, `cryptogen`, etc. into `./bin/`.

2. Install Go 1.20+ and ensure `go` is on your PATH. The process runner builds
   the API gateway binary before launching it.

3. Make sure no Docker stack (or any other Fabric deployment) is listening on
   the standard ports (7050, 7051, 8051, 9051, 9000). Run
   `docker compose down -v` if you previously brought up the Docker stack. The
   process runner now refuses to start when those ports are occupied.

4. Generate or refresh the MSP material and channel artifacts (only needed the
   first time or whenever you need a clean slate). **Run these commands from the
   `api-gateway/` directory** because the process runner reads artifacts from
   there, not from the repo root:
   ```bash
   cd api-gateway
   rm -rf organizations system-genesis-block channel-artifacts

   cryptogen generate --config=crypto-config.yaml --output=organizations

   export FABRIC_CFG_PATH=$PWD/configtx
   mkdir -p system-genesis-block channel-artifacts

   configtxgen -profile NebulaGenesis -channelID system-channel \
     -outputBlock system-genesis-block/genesis.block

   configtxgen -profile NebulaChannel -channelID nebulachannel \
     -outputCreateChannelTx channel-artifacts/nebula-channel.tx

   configtxgen -profile NebulaChannel -channelID nebulachannel \
     -asOrg Org1MSP \
     -outputAnchorPeersUpdate channel-artifacts/Org1MSPanchors.tx
   ```

5. Point the Fabric hostnames at `127.0.0.1` so TLS validation succeeds:
   ```
   127.0.0.1 orderer.nebula.com peer0.org1.nebula.com peer1.org1.nebula.com peer2.org1.nebula.com
   ```

6. Copy `api-gateway/.env.example` to `.env`, fill in `AUTH_JWT_SECRET` and
   `ADMIN_PUBLIC_KEY`, and keep the rest aligned with your deployment. The
   process runner automatically loads this file.

## 2. Prepare trainer identities

The Docker-free workflow uses the same trainer tooling described in
`api-gateway/README.md`. Complete these steps **before** starting the stack so
the API has every MSP identity, VC, and JWT it needs.

1. **Review node definitions.** Each trainer definition lives under
   `nodes-setup/nodes/node_X.json`. Update these files to reflect your topology:
   every entry must include `state`, `cluster`, and `node_id`. The `node_id`
   drives the Fabric identity name (`trainer-node-XXX`).

2. **Generate trainer credentials and JWTs.** From `api-gateway/`:
   ```bash
   # set AUTH_JWT_SECRET or pass --auth-secret explicitly
   AUTH_JWT_SECRET="super-secret" \
   node scripts/generate-trainer-identities.js \
     --generate-jwt registration,runtime \
     --auth-secret "$AUTH_JWT_SECRET"
   ```
   This writes:
   - Keys: `nodes-setup/keys/<trainer-id>_{sk,pk}.pem`
   - Unsigned VCs: `nodes-setup/vc-unsigned/<trainer-id>.json`
   - JWTs: `nodes-setup/tokens/<trainer-id>_{registration,runtime}.jwt`
   Copy each trainer’s private key and runtime JWT to the machine that will run
   that node. Treat `nodes-setup/` as a staging area—never commit these secrets.

3. **Ensure MSP material exists for every trainer identity.** Each trainer must
   have `organizations/peerOrganizations/org1.nebula.com/users/<trainer-id>/msp`
   populated with the same certificate hierarchy embedded in the channel
   artifacts. You can copy the MSP folders manually or run the Fabric CA **as a
   local process** (no Docker needed—`fabric-ca-server` already lives in the repo
   root `./bin/`). When running from `api-gateway/`, reference the binaries with
   `../bin/...`:

   > **Tip:** make sure the process stack is stopped (`./process-runner/manage.sh stop`)
   > before launching the CA; the orderer’s operations service also listens on
   > port 9443, which will conflict if the stack is still running.

   ```bash
   # start the CA using the certified keypair shipped in organizations/.../ca
   export FABRIC_CA_SERVER_HOME=$PWD/organizations/peerOrganizations/org1.nebula.com/ca-server
   mkdir -p "$FABRIC_CA_SERVER_HOME"
   FABRIC_CA_SERVER_OPERATIONS_LISTENADDRESS=127.0.0.1:10443 \
   ../bin/fabric-ca-server start \
     -b admin:adminpw \
     --port 7054 \
     --ca.name ca-org1 \
     --ca.certfile $PWD/organizations/peerOrganizations/org1.nebula.com/ca/ca.org1.nebula.com-cert.pem \
     --ca.keyfile  $PWD/organizations/peerOrganizations/org1.nebula.com/ca/priv_sk \
     --csr.cn ca.org1.nebula.com
   ```
   Leave that terminal running. Stop it later with `Ctrl+C` (or `SIGINT`) once all
   identities are enrolled. In another terminal:

   ```bash
   # enroll the CA admin once
   export FABRIC_CA_CLIENT_HOME=$PWD/organizations/peerOrganizations/org1.nebula.com/users/Admin@org1.nebula.com
   ../bin/fabric-ca-client enroll \
     -u http://admin:adminpw@localhost:7054 \
     --caname ca-org1 \
     -M "$FABRIC_CA_CLIENT_HOME/msp"
   # copy the Org1 MSP template so NodeOUs/admin roles resolve correctly
   cp organizations/peerOrganizations/org1.nebula.com/msp/config.yaml \
      "$FABRIC_CA_CLIENT_HOME/msp/config.yaml"

   # enroll trainer identities (default secret <trainerId>pw)
   node scripts/enroll-trainer-identities.js \
     --ca-url http://localhost:7054 \
     --ca-name ca-org1 \
     --tls-cert organizations/peerOrganizations/org1.nebula.com/msp/cacerts/ca.org1.nebula.com-cert.pem
   # add --force if you want to re-register/re-enroll every trainer identity
   ```
   The enrollment script writes MSP material and TLS certs under
   `organizations/.../users/<trainer-id>/`. Use `--force` to re-enroll or
   `--secret-template` for custom passwords. Stop the CA process later with
   `Ctrl+C` in its terminal.

4. **Sign the VCs with the admin Ed25519 key.**
   ```bash
   node scripts/sign-trainer-vcs.js \
     --key admin_ed25519_sk.pem \
     --force
   ```
   Signed VCs land in `nodes-setup/vc-signed/<trainer-id>_vc.json`.

5. **(Optional) Build a bulk registration payload.**
   ```bash
   node scripts/build-bulk-register-payload.js \
     --did-template did:nebula:trainer-node-{trainerSeq} \
     --output nodes-setup/bulk-register.json \
     --force
   ```
   The resulting JSON array can be POSTed to `/auth/register-trainers` once the
   gateway is running. Make sure your DID template matches the VC `subject`
   values produced in step 2; adjust `--subject-template` during generation if
   you need a different DID format.

6. **Generate JWTs.**
   - Admin bulk registration token:
     ```bash
     AUTH_JWT_SECRET="super-secret" \
     JWT_ALG=HS256 JWT_ROLE=admin JWT_SUB=admin \
     node jwt.js > admin.jwt
     ```
   - Trainer registration tokens: reuse the files produced in step 2 or regenerate
     with `JWT_ALG=HS256`.
   - Trainer runtime tokens: sign with each trainer’s Ed25519 key
     (`JWT_ALG=EdDSA TRAINER_PRIVATE_KEY=/path/to/sk.pem`).

7. **Shut down the CA and reset runtime data (clean bootstrap).**
   Once MSP material and JWTs are ready, stop the Fabric CA process (Ctrl+C in
   the terminal where `fabric-ca-server` is running). If you want to guarantee a
   fresh raft/ledger state before starting Fabric, wipe the process runner data
   **and** clear the trainer database so registrations start from scratch:
   ```bash
   ./process-runner/manage.sh stop      # no-op if nothing is running yet
   rm -rf process-runner/runtime/data
   rm -f data/trainers.json && echo "[]" > data/trainers.json
   ```

With identities ready, you can start the Fabric processes.

## 3. Starting the process stack

```bash
cd api-gateway
./process-runner/manage.sh start
```

The script:

1. Copies `config/` into `process-runner/runtime/config/` and rewrites the
   external builder paths so Golang/Node builders point at your checkout.
2. Starts the orderer and three peers using the Fabric binaries from `./bin/`.
3. Executes `scripts/bootstrap.sh` on the host to create `nebulachannel`, join
   all peers, and (re)deploy the `gateway` chaincode. This step can take a
   minute or two while all peers join and the chaincode is packaged/committed.
   Check `./process-runner/manage.sh logs bootstrap` for live progress.
4. Builds the Go API gateway binary and launches it on port `9000` *after*
   bootstrap completes successfully.

Logs live under `process-runner/runtime/logs/`, per-process PIDs under
`process-runner/runtime/pids/`, and ledger/state data under
`process-runner/runtime/data/`.

## 4. Registering trainers

With the gateway online you can enroll trainers exactly like you would when
running Docker. If you generated `admin.jwt` and the optional bulk payload in
step 2, seed the registry with:

```bash
curl -sS -X POST http://localhost:9000/auth/register-trainers \
  -H "Authorization: Bearer $(cat admin.jwt)" \
  -H "Content-Type: application/json" \
  --data @nodes-setup/bulk-register.json
```

The endpoint mirrors `/auth/register-trainer` but handles an array of trainers at
once. Successful registrations persist to `data/trainers.json`. Delete or reset
that file (e.g., `rm data/trainers.json && echo "[]" > data/trainers.json`) if
you ever need to rebuild the registry without reinstalling Fabric.

Individual trainers can still call `/auth/register-trainer` with their HS256
registration JWTs, and runtime APIs continue to rely on the Ed25519 JWTs tied to
each trainer’s private key.

### Inspecting or tailing components

```bash
./process-runner/manage.sh status          # shows whether each component is running
./process-runner/manage.sh logs orderer    # tail the orderer log
./process-runner/manage.sh logs peer0      # tail a peer log
./process-runner/manage.sh logs gateway    # tail API output
./process-runner/manage.sh logs bootstrap  # watch channel/chaincode bootstrapping
```

### Stopping the stack

```bash
./process-runner/manage.sh stop
```

This sends `SIGTERM` to the API, peers, and orderer, clears PID files, and leaves
the ledgers on disk so you can restart quickly. Delete
`process-runner/runtime/data/` if you want a clean slate.

## 5. Verifying functionality

Because the same bootstrap script, MSP artifacts, and Go binary are used, the
API behaves exactly as it does when launched with Docker. You can re-run any
existing workflow (enrollment, whitelist sync, convergence queries, data/model
commits, etc.) without modification. A typical smoke test looks like:

1. **Health check**
   ```bash
   curl http://localhost:9000/health
   # → {"status":"ok","chaincode":"gateway","default_peer":"peer0","job_id":""}
   ```

2. **Trainer enrollment** (same payloads/tokens as Docker). From the repo root:
   ```bash
   AUTH_JWT_SECRET=... \
   curl -H "Authorization: Bearer $(cat nodes-setup/tokens/trainer-node-001_registration.jwt)" \
        -H "Content-Type: application/json" \
        -d @nodes-setup/vc-unsigned/trainer-node-001.json \
        http://localhost:9000/auth/register-trainer
   ```
   The API writes the trainer entry into `data/trainers.json` inside the repo.

3. **Runtime data/model calls** use the same EdDSA JWTs (from
   `nodes-setup/tokens/*_runtime.jwt`) and succeed because the peer CLI inside
   the API container has been replaced with the host `peer` binary.

4. **Whitelist refresh and convergence APIs** run against the same chaincode.
   Use the HS256 “admin” token exactly like you do in Docker.

If any of these commands succeed in Docker, they succeed here—the process runner
simply swaps Docker Compose for local processes without altering identities,
configuration, or chaincode.

## 6. Troubleshooting tips

- Missing binaries? Re-run `./install-fabric.sh binary samples` or ensure
  `${repo}/bin` is on your PATH.
- TLS or hostname errors? Double-check `/etc/hosts`.
- Chaincode rejected during bootstrap? Remove `process-runner/runtime/data/`
  and re-run `./process-runner/manage.sh start` to force a clean channel + chaincode deploy.
- API refuses to start? Confirm `AUTH_JWT_SECRET` and `ADMIN_PUBLIC_KEY` are
  exported or present in `.env`.
- Port already in use? The runner now attempts to terminate leftover `orderer`,
  `peer`, or `api-gateway` processes that are bound to the expected ports. If a
  different program owns the port, the script will stop and tell you which PID
  to close before retrying.
- Orderer still pointing at `/var/hyperledger`? Delete
  `process-runner/runtime/data/orderer/` and re-run `./process-runner/manage.sh start`.
  The script automatically places the Raft WAL/snapshot folders under that path now,
  so the orderer no longer needs root-owned directories.
- Peer fails with `mkdir /var/hyperledger: permission denied`? Remove the peer’s
  data folder (e.g., `rm -rf process-runner/runtime/data/peer0`) and restart.
  The runner now sets all ledger/snapshot directories inside
  `process-runner/runtime/data/peer*/`, so subsequent launches stay Docker-free.

With those steps complete, you can switch between Docker (`docker compose up`)
and process mode (`./process-runner/manage.sh start`) at any time while keeping
the same developer experience and features.
