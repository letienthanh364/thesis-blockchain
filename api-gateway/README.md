# API Gateway Stack

1. A Verifiable Credential (VC)–aware enrollment endpoint that maps runtime JWTs to Fabric wallet identities and registers them on-chain.
2. A scoped model-reference API layered by “cluster”, “state”, and “nation” with commit/list/retrieve operations plus pagination, alongside the original generic data commit/retrieve helpers for ad-hoc payloads.
3. A trainer whitelist feed so aggregators can fetch the canonical list of enrolled nodes straight from the ledger.
4. Convergence services for “state” and “nation” scopes that track cluster/state convergence claims (individual and “all converged”) and expose status/list APIs.

`docker-compose.yaml` still provisions the entire Fabric network (orderer + 3 peers), the bootstrap CLI, the gateway CLI, and the HTTP server in a single command so you can spin everything up with one `docker compose up` just like the original stack.

## Quick start

All commands below run from the `api-gateway/` directory:

```bash
cd api-gateway
```

Follow these steps the first time you spin up the stack:

0. **Environment file.** Copy `.env.example` to `.env` and edit the values:
   ```bash
   cp .env.example .env
   # edit .env to set AUTH_JWT_SECRET and ADMIN_PUBLIC_KEY at minimum
   ```
   `AUTH_JWT_SECRET` secures `/auth/register-trainer`. `ADMIN_PUBLIC_KEY` must match the base64 Ed25519 key derived from your admin private key. All other entries already match the defaults used by `docker-compose.yaml`.

1. **Seed Fabric MSP artifacts.**
   - If `./organizations`, `./system-genesis-block`, and `./channel-artifacts` already contain valid material (default clone), skip this step.
   - For a clean slate remove the existing folders and regenerate everything with `cryptogen` and `configtxgen` **before** running Docker Compose:
     ```bash
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
     These commands repopulate the MSP folders and recreate the genesis/channel transactions consumed by `docker-compose.yaml`.

2. **Generate the admin Ed25519 keypair** (used to sign VCs and populate `ADMIN_PUBLIC_KEY`).
   ```bash
   openssl genpkey -algorithm Ed25519 -out admin_ed25519_sk.pem
   
   openssl pkey -in admin_ed25519_sk.pem -pubout -outform DER | tail -c 32 | base64 > admin_public_key.b64
   ```
   Copy the single line from `admin_public_key.b64` into `.env` as `ADMIN_PUBLIC_KEY=...`. Keep `admin_ed25519_sk.pem` safe—you will use it to sign VCs.

3. **Prepare trainer identities (automated).**
   - Each trainer definition lives under `nodes-setup/nodes/node_X.json`. Update these files to change the list of trainer nodes or tweak per-node metadata (dataset parameters, topology hints, etc.). Each entry must now include `state` and `cluster` identifiers so the whitelist and convergence modules can build the hierarchy (clusters roll up into states, which roll up into the nation). The `node_id` determines the trainer identifier used throughout the tooling (`trainer-node-XXX` naming is derived automatically).
   - To generate Ed25519 keypairs, unsigned VC payloads, and both JWT flavors for *all* trainers, run:
     ```bash
     # ensure AUTH_JWT_SECRET is exported or pass --auth-secret explicitly
     AUTH_JWT_SECRET="super-secret" \
     node scripts/generate-trainer-identities.js \
       --generate-jwt registration,runtime \
       --auth-secret "$AUTH_JWT_SECRET"
     ```
     This writes:
     - Keys: `nodes-setup/keys/<trainer-id>_{sk,pk}.pem` + `<trainer-id>_public_key.b64`
     - Unsigned VCs: `nodes-setup/vc-unsigned/<trainer-id>.json`
     - JWTs (optional): `nodes-setup/tokens/<trainer-id>_{registration,runtime}.jwt`
   - Copy the private key PEM (and optional runtime JWT) to the *actual machine* that will run that trainer node. These files must never be checked in or shared broadly; treat `nodes-setup/` as a staging area.
   - Make sure each trainer still has MSP material under `organizations/peerOrganizations/org1.nebula.com/users/<fabric-client-id>/msp` where `<fabric-client-id>` matches the `trainer-xxx` naming convention.
   - **If you prefer Fabric CA over copying MSPs manually**, bring up a CA server and enroll the admin once:
     ```bash
     # 3a. start the CA container (run before docker compose up)
     docker run -d --name ca-org1.nebula.com \
       -p 7054:7054 \
       -v $PWD/organizations/peerOrganizations/org1.nebula.com/ca:/etc/hyperledger/fabric-ca-server/ca \
       -e FABRIC_CA_SERVER_CA_NAME=ca-org1 \
       -e FABRIC_CA_SERVER_CA_CERTFILE=/etc/hyperledger/fabric-ca-server/ca/ca.org1.nebula.com-cert.pem \
       -e FABRIC_CA_SERVER_CA_KEYFILE=/etc/hyperledger/fabric-ca-server/ca/priv_sk \
       -e FABRIC_CA_SERVER_TLS_ENABLED=false \
       hyperledger/fabric-ca:1.5 \
       sh -c 'fabric-ca-server start -b admin:adminpw --port 7054'

     # 3b. enroll the CA admin (one time, plain HTTP because TLS is disabled)
     export FABRIC_CA_CLIENT_HOME=$PWD/organizations/peerOrganizations/org1.nebula.com/users/Admin@org1.nebula.com
     fabric-ca-client enroll \
       -u http://admin:adminpw@localhost:7054 \
       --caname ca-org1 \
       -M "$FABRIC_CA_CLIENT_HOME/msp"
     ```
     The CA must reuse the same certificate/key pair shipped in `organizations/.../ca` so that any identities it issues match the MSP embedded in the channel artifacts. You can confirm alignment by running `openssl x509 -in organizations/peerOrganizations/org1.nebula.com/users/trainer-node-001/msp/signcerts/cert.pem -noout -issuer` and checking that the issuer reads `CN=ca.org1.nebula.com`.
      Then enroll all trainers automatically:
     ```bash
     node scripts/enroll-trainer-identities.js \
       --ca-url http://localhost:7054 \
       --ca-name ca-org1 \
       --tls-cert organizations/peerOrganizations/org1.nebula.com/msp/cacerts/ca.org1.nebula.com-cert.pem
     ```
     This registers each trainer (default secret `<trainerId>pw`), writes MSP material to `organizations/.../users/<trainer-id>/msp`, and provisions TLS certs under `.../users/<trainer-id>/tls`. Run it after the CA is up; pass `--force` to re-enroll or `--secret-template` if you need custom passwords. Stop the CA later with `docker rm -f ca-org1.nebula.com` if you no longer need it.
     > The script now also copies `organizations/peerOrganizations/org1.nebula.com/msp/cacerts/ca.org1.nebula.com-cert.pem` into every trainer’s `msp/cacerts` folder so that the filenames referenced by `config.yaml` always exist. Use `--canonical-ca-cert /path/to/cert.pem` (or `--canonical-ca-cert skip`) if your deployment needs a different CA file.

4. **Admin issues signed VCs.** Use the helper script to sign every unsigned VC with the admin Ed25519 key (`admin_ed25519_sk.pem` generated in step 2):
   ```bash
   node scripts/sign-trainer-vcs.js \
     --key admin_ed25519_sk.pem \
     --force   # optional overwrite
   ```
   Signed credentials land in `nodes-setup/vc-signed/<trainer-id>_vc.json`. Give each trainer its matching signed VC so it can call `/auth/register-trainer`.

5. **Prepare a bulk-registration payload (optional but recommended).** After the network is up and the signed VCs exist, stitch the artifacts together:
   ```bash
   node scripts/build-bulk-register-payload.js \
     --did-template did:nebula:trainer-node-{trainerSeq} \
     --output nodes-setup/bulk-register.json \
     --force   # overwrite existing file
   ```
   The template accepts `{trainerId}`, `{nodeId}`, and `{trainerSeq}` (001, 002, …). The resulting JSON array can be POSTed to `/auth/register-trainers` once the server is running.
   > **Heads-up:** `/auth/register-trainer(s)` compares the request `did` against the VC’s `subject`. By default `generate-trainer-identities.js` emits subjects like `did:nebula:trainer-node-001`, so keep your `did` fields identical to those values. If you prefer a different DID format (for example `did:nebula:trainer-node001`), rerun the generator with `--subject-template did:nebula:trainer-{trainerSeq}` (or similar) so the VC subject and API payload still match; otherwise the server will return `vc subject does not match requested did`.

6. **Generate JWTs for admin, registration, and runtime.**
   - **Admin bulk-registration token:** Reuse the shared `AUTH_JWT_SECRET`, elevate the role to `admin`, and persist the token once. Example:
     ```bash
     AUTH_JWT_SECRET="super-secret" \
     JWT_ALG=HS256 \
     JWT_ROLE=admin \
     JWT_SUB=admin \
     node jwt.js > admin.jwt
     ```
     `admin.jwt` (stored under `api-gateway/`) is the bearer token for `/auth/register-trainers`; guard it like a password.
   - **Trainer registration:** HS256 JWT using the shared `AUTH_JWT_SECRET`. You can re-run `node jwt.js --sub trainer-node-001` with `JWT_ALG=HS256` and the secret exported, or reuse the pre-generated token from `nodes-setup/tokens/*_registration.jwt`.
   - **Runtime APIs:** Ed25519 JWT signed with the trainer’s private key. Again you can re-run `node jwt.js --sub trainer-node-001` with `JWT_ALG=EdDSA TRAINER_PRIVATE_KEY=/path/to/sk.pem`, or reuse `*_runtime.jwt`. Keep the private key PEM on the trainer host.

7. **Start the stack.**
   ```bash
   export AUTH_JWT_SECRET="super-secret"
   export ADMIN_PUBLIC_KEY=$(cat admin_public_key.b64)
   DOCKER_BUILDKIT=1 docker compose up --build
   ```

Stop with `docker compose down -v`. If you do not want to export variables manually, drop the environment variables into `.env`.

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `FABRIC_CHANNEL` | `nebulachannel` | Fabric channel name. Must match the channel created by the CLI bootstrap script. |
| `FABRIC_CHAINCODE` | `gateway` | Chaincode name deployed by the bootstrap script. |
| `MSP_ID` | `Org1MSP` | MSP ID for the peer org. |
| `ORG_CRYPTO_PATH` | `/organizations/peerOrganizations/org1.nebula.com` | Base path that contains `users/<identity>/msp`. The gateway dynamically switches identities per trainer using this root. |
| `ADMIN_IDENTITY` | `Admin@org1.nebula.com` | Default identity used by the gateway (also doubles as fallback if a trainer-specific identity is missing). |
| `ORDERER_ENDPOINT` | `orderer.nebula.com:7050` | Orderer gRPC endpoint. |
| `ORDERER_TLS_CA` | `/organizations/ordererOrganizations/nebula.com/orderers/orderer.nebula.com/msp/tlscacerts/tlsca.nebula.com-cert.pem` | TLS CA used when invoking the orderer. |
| `PEER_ENDPOINTS` | `peer0=peer0.org1.nebula.com:7051,peer1=...,peer2=...` | CSV map of peer name → address. The gateway picks `DEFAULT_PEER` for all transactions. |
| `DEFAULT_PEER` | `peer0` | Peer used for submits/queries. |
| `AUTH_JWT_SECRET` | _(required)_ | Shared HS256 secret used to protect the `/auth/register-trainer` endpoint. Runtime APIs require per-trainer Ed25519 JWTs. |
| `ADMIN_PUBLIC_KEY` | _(required)_ | Base64-encoded Ed25519 public key used to verify VC signatures. |
| `TRAINER_DB_PATH` | `/data/trainers.json` | Location on disk where the gateway remembers enrolled trainers. When unset the gateway tries `/data/trainers.json` first and then walks up from `cwd` to locate `./data/trainers.json`, so local runs automatically reuse the repo copy. Mount `./data:/data` (already configured) for persistence in Docker. |
| `GATEWAY_JOB_ID` | empty | Optional job identifier – if set, the VC `job_id` must match this value. |

`ADMIN_PUBLIC_KEY` expects the raw 32-byte Ed25519 public key (no PEM headers) encoded with standard base64—the same data produced by the quick start commands above.

## Authentication flow

1. **Layer 1 (JWT):** every HTTP request supplies `Authorization: Bearer <token>`. Tokens carry `sub`, `role`, and `exp` claims plus optional `state`, `cluster`, and `nation` hints so the API can determine topology without extra parameters. They can be HS256 (shared secret) or EdDSA (per-trainer keys) depending on the endpoint. Runtime tokens may set `sub` to either the trainer’s `jwt_sub` or the DID string—they both resolve to the same enrollment now. Admin/aggregator-only APIs (e.g., `/whitelist`, convergence lists) keep using HS256 tokens signed with the shared `AUTH_JWT_SECRET`. A new `central_checker` role governs the `<scope>/convergence/all` endpoints.
   - The **registration token** proves the caller knows the shared bootstrap secret (`AUTH_JWT_SECRET`). Only this token is accepted on `/auth/register-trainer`.
   - The **runtime token** proves the caller controls the trainer-specific Ed25519 key registered earlier. These are required for `/data/*` APIs.
2. **Layer 2 (VC enrollment):** before a node can call any runtime API it must invoke `POST /auth/register-trainer` once. During this call the gateway:
   - Verifies the JWT and resolves `sub`.
   - Verifies the VC signature against `ADMIN_PUBLIC_KEY`. The VC is canonicalized (stable key ordering, no whitespace) before hashing/signing; a SHA256 hash of the signed VC (including the signature field) becomes `vc_hash` and is stored on-chain.
   - Checks `valid_from`/`valid_until`, the DID, and optional `job_id`.
   - Maps the JWT subject to a Fabric wallet identity using the rule `trainer-<nodeId>` (non-alphanumeric characters collapse to `-`). The MSP material must live under `${ORG_CRYPTO_PATH}/users/<fabric-id>/msp`.
   - Calls the Fabric chaincode function `RegisterTrainer(did, nodeId, vcHash, publicKey)` signed by that identity.
   - Persists `{jwt_sub, fabric_client_id, nodeId, vc_hash, did, public_key}` inside `TRAINER_DB_PATH`.
3. **Layer 2 (runtime checks):** The data and model endpoints validate the EdDSA runtime token, resolve the trainer enrollment (by `jwt_sub` or DID), then sign Fabric transactions with that trainer’s MSP identity. Chaincode enforces the whitelist, so runtime calls still require the registered private key.

## HTTP API

Base URL: `http://localhost:9000`

### Health check

```
GET /health
```
`public_key` must be the base64-encoded 32-byte Ed25519 public key generated in step 2 (the same key used for JWT signing).

Response:

```json
{
  "status": "ok",
  "chaincode": "gateway",
  "default_peer": "peer0",
  "job_id": ""
}
```

### Register trainer

```
POST /auth/register-trainer
Authorization: Bearer <JWT>
Content-Type: application/json

{
  "did": "did:nebula:trainer-node001",
  "nodeId": "trainer-node-001",
  "state_id": "state-alpha",
  "cluster_id": "cluster-01",
  "public_key": "<trainer public key base64>",
  "vc": { ... signed VC JSON ... }
}
```

Successful response:

```json
{
  "status": "ok",
  "jwt_sub": "trainer-node-001",
  "fabric_client_id": "trainer-node-001",
  "vc_hash": "1bc9...",
  "did": "did:nebula:trainer",
  "node_id": "node-001",
  "registered_at": "2025-01-02T03:04:05Z"
}
```

Failures:
- Invalid/missing JWT → `401`.
- VC signature mismatch, outside validity window, or DID/job mismatch → `403`.
- Fabric invocation error (missing Fabric identity, ledger failure) → `500`.
- Missing `state_id` or `cluster_id` → `400`. Every trainer must be tagged with its state/cluster so convergence and whitelist hierarchies stay in sync.

### Bulk register trainers (admin only)

```
POST /auth/register-trainers
Authorization: Bearer <ADMIN JWT>
Content-Type: application/json

[
  {
    "did": "did:nebula:trainer-node001",
    "nodeId": "trainer-node-001",
    "public_key": "...",
    "vc": { ... }
  },
  {
    "did": "did:nebula:trainer-node002",
    "nodeId": "trainer-node-002",
    "public_key": "...",
    "vc": { ... }
  }
]
```

The admin token must carry `role=admin`. Each array element reuses the same schema as the single-trainer endpoint; you can optionally include `jwt_sub` or `subject` to specify the runtime JWT subject. If omitted, the gateway falls back to `nodeId`, then `did`. The response returns a list of per-trainer results, and the HTTP status becomes `207 Multi-Status` when at least one entry fails.

### Commit data

```
POST /data/commit
Authorization: Bearer <JWT>
Content-Type: application/json

{
  "payload": {"anything":"goes"}
}
```

Response:

```json
{
  "data_id": "data-7b52c8...",
  "node_id": "node-001",
  "vc_hash": "1bc9...",
  "submitted_at": "2025-01-02T03:04:05Z"
}
```

The gateway generates `data_id`, signs a Fabric transaction with the trainer’s identity, and stores the entire JSON payload on-chain. Save the `data_id` to retrieve the payload later.

### Retrieve data

```
GET /data/<data_id>
Authorization: Bearer <JWT>
```

Response:

```json
{
  "data_id": "data-7b52c8...",
  "payload": {"anything":"goes"},
  "owner": "node-001",
  "submitted_at": "2025-01-02T03:04:05Z"
}
```

Only the trainer that originally committed the data (same Fabric client identity) can read it. If another JWT is used the chaincode will reject the read.

## Chaincode

The previous asset-transfer sample was replaced with a purpose-built contract (`chaincode/asset-transfer-basic/chaincode/gateway_contract.go`). It exposes:

- `RegisterTrainer(did, nodeId, vcHash, publicKey)` → stores the trainer metadata keyed by the invoker’s Fabric `clientID`.
- `CommitData(dataId, payload)` / `ReadData(dataId)` → legacy helpers for arbitrary payloads.
- `CommitModel(dataId, layer, scopeId, payload)`, `ReadModel(dataId)`, and `ListModels(layer, scopeId, page, perPage)` → scoped model reference handling with pagination.
- `RecordWhitelistEntry(jwtSub, did, nodeId, vcHash, publicKey, registeredAt)` / `ListWhitelist(page, perPage)` → mirrors the trainer whitelist keyed by JWT subject.
- `CommitStateClusterConvergence(stateId, clusterId, payload)`, `CommitNationStateConvergence(stateId, payload)`, `DeclareStateConvergence(stateId, payload)`, and `DeclareNationConvergence(payload)` → convergence write paths.
- `ReadStateConvergence(stateId)`, `ListStateConvergence()`, `ReadNationConvergence()`, and `ListNationConvergence()` → convergence queries for regular nodes and admins.
- `IsTrainerAuthorized()` helper shared by the read/write functions.

The bootstrap CLI now packages this chaincode under the label `gateway` so the API and Fabric stay in sync.

## Redeploying & testing

- **Chaincode:** bump `CHAINCODE_VERSION`/`CHAINCODE_SEQUENCE` and rerun `/scripts/bootstrap.sh` inside `gateway-cli`. Example: `docker exec gateway-cli bash -c 'CHAINCODE_VERSION=1.1 CHAINCODE_SEQUENCE=2 /scripts/bootstrap.sh'`.
- **API:** `docker compose build api-gateway && docker compose up -d api-gateway`.
- **Smoke test:** after the stack is up, call `GET /health`, register a trainer with the VC JSON and JWT you prepared, then hit `POST /cluster/models` (or state/nation) followed by `GET /cluster/models/<id>` to verify the layered endpoint. `POST /data/commit` / `GET /data/<id>`, `GET /whitelist`, and the new convergence endpoints (`POST /state/convergence`, `GET /state/convergence`, etc.) should all work to confirm the ledger flow end-to-end.

Everything still runs behind the single compose file, so the workflow stays the same as `nebula-gateway` while giving you a trimmed, VC-hardened API surface.
> **Note:** The Fabric containers mount `./organizations/**` from your host. If you cloned a trimmed repo or wiped that directory, regenerate MSP material (via `cryptogen` or the CA flow above) *before* running `docker compose up`; otherwise the peers/orderer will crash with “could not load a valid signer certificate.”
### Commit model reference

Each layer gets its own endpoint: `/cluster/models`, `/state/models`, `/nation/models`. The body must include the payload plus the scope identifier expected by the layer, and (optionally) the training round you are committing for:

```
POST /state/models
Authorization: Bearer <runtime EdDSA JWT>
Content-Type: application/json

{
  "state_id": "state-41",
  "state_round": 1,
  "payload": {
    "artifact_hash": "sha256:9f57...",
    "dataset": "mnist-v1",
    "train_accuracy": 0.982
  }
}
```

You can also provide a generic `scope_id`/`scopeId` field instead of the layer-specific key. Round numbers are accepted via `round`, `<scope>_round`, or `<scope>-round` (e.g., `cluster_round`, `state-round`, `round`). The response mirrors `POST /data/commit` but includes layer/scope metadata:

```json
{
  "data_id": "model-1a2b3c...",
  "layer": "state",
  "scope_id": "state-41",
  "round": 1,
  "node_id": "trainer-node-001",
  "vc_hash": "1bc9...",
  "submitted_at": "2025-01-02T03:04:05Z"
}
```

For nation-wide commits, the same structure applies—just swap in the nation identifier and round keys:

```
POST /nation/models
Authorization: Bearer <runtime EdDSA JWT>
Content-Type: application/json

{
  "nation_id": "federal-1",
  "nation_round": 3,
  "payload": {
    "model_hash": "sha256:...v0.2",
    "cid": "cid-of-model-ver0.2",
    "dataset": "global-mnist-v2",
    "train_accuracy": 0.941,
    "notes": "post-state aggregation run"
  }
}
```

### Retrieve model reference

```
GET /state/models/<data_id>
Authorization: Bearer <runtime EdDSA JWT>
```

Response:

```json
{
  "data_id": "model-1a2b3c...",
  "layer": "state",
  "scope_id": "state-41",
  "round": 1,
  "owner": "trainer-node-001",
  "payload": { ... },
  "submitted_at": "2025-01-02T03:04:05Z"
}
```

### Lookup model reference by scope & round

```
GET /state/models?state=state-41&round=1
Authorization: Bearer <runtime EdDSA JWT>
```

Provide the scope identifier using either `scopeId`, the layer-specific key (e.g., `state_id`), or a shorthand such as `state`. Pair it with `round`, `<scope>_round`, or `<scope>-round` to retrieve the model committed for that exact round. When no record matches, the API responds with `404 {"error":"no model provided for state state-41 round 1"}` so callers can detect missing submissions.

### List model references

```
GET /state/models?state=state-41&page=2
Authorization: Bearer <runtime EdDSA JWT>
```

Parameters:
- `scopeId` / layer-specific aliases such as `state`, `state_id`, `cluster`, etc. (optional) filter to a specific cluster/state/nation ID. When omitted you receive every record for that layer.
- `page` (optional) defaults to `1`. Page size is fixed at 10 items.

Response:

```json
{
  "items": [
    {
      "data_id": "model-...",
      "layer": "state",
      "scope_id": "state-41",
      "round": 1,
      "owner": "trainer-node-001",
      "payload": {...},
      "submitted_at": "..."
    }
  ],
  "page": 2,
  "per_page": 10,
  "total": 17,
  "has_more": true
}
```

### Latest model reference

```
GET /state/models/latest?state=state-41
Authorization: Bearer <runtime EdDSA JWT>
```

- Accepts the same scope aliases as the other model queries (`scopeId`, `state`, `state_id`, etc.).
- Returns the most recent submission for the provided scope, or the most recent record in the entire layer when no scope parameter is supplied.
- The response mirrors `GET /state/models/<data_id>` and also includes the layer-specific identity field (`state_id`, `cluster_id`, `nation_id`) so callers can verify which scope produced the model.

Example response:

```json
{
  "data_id": "model-...",
  "layer": "state",
  "scope_id": "state-41",
  "state_id": "state-41",
  "round": 4,
  "owner": "trainer-node-009",
  "payload": {...},
  "submitted_at": "2025-01-05T12:00:00Z"
}
```

Additional layers can be added server-side without changing the HTTP surface—new `/layer/models` routes are registered automatically.

### Trainer whitelist

```
GET /whitelist?per_page=25&page=2
Authorization: Bearer <admin-or-aggregator HS256 JWT>
```

- `page` defaults to `1`.
- `per_page` defaults to `50`.

Response:

```json
{
  "states": [
    {
      "state_id": "state-alpha",
      "clusters": [
        {
          "cluster_id": "cluster-01",
          "nodes": [
            {
              "jwt_sub": "trainer-node-001",
              "did": "did:nebula:trainer-node-001",
              "node_id": "trainer-node-001",
              "state": "state-alpha",
              "cluster": "cluster-01",
              "vc_hash": "1bc9...",
              "public_key": "base64...",
              "registered_at": "2025-01-02T03:04:05Z"
            }
          ]
        }
      ]
    }
  ],
  "page": 1,
  "per_page": 50,
  "total": 5,
  "has_more": false
}
```

Every entry inside `data/trainers.json` is mirrored to the ledger at startup, and future registrations automatically append to that whitelist, so the endpoint above always returns the canonical trainer set grouped by state/cluster. Only `admin`, `aggregator`, or `central_checker` JWT roles can call it.

### Convergence APIs

The convergence service tracks whether each cluster (state scope) and each state (nation scope) has reported convergence.

#### Submit cluster → state convergence

```
POST /state/convergence
Authorization: Bearer <aggregator runtime JWT>
Content-Type: application/json

{
  "state_id": "state-alpha",
  "cluster_id": "cluster-01",
  "payload": {
    "cid": "bafybeia...",
    "hash": "sha256:123...",
    "accuracy": 0.982
  }
}
```

Cluster aggregators submit convergence payloads for the state scope. The `state_id`/`cluster_id` pair can come from the runtime token claims or directly from the request body. The payload blob is stored as-is on-chain so you can include whatever metadata makes sense (CID, hash, accuracy, etc.). Response: `201 {"status":"ok"}`.

#### Submit state → nation convergence

```
POST /nation/convergence
Authorization: Bearer <aggregator runtime JWT>

{
  "state_id": "state-alpha",
  "payload": {
    "cid": "...",
    "accuracy": 0.995
  }
}
```

State aggregators submit convergence payloads toward the nation scope. Response mirrors the state endpoint.

#### Declare “all converged”

```
POST /state/convergence/all
Authorization: Bearer <central_checker runtime JWT>

{
  "state_id": "state-alpha",
  "payload": {
    "cid": "...",
    "hash": "...",
    "notes": "all clusters acknowledged"
  }
}
```

Central checkers can only declare “all converged” once per scope. Subsequent calls for the same state/nation return an error indicating the scope is already converged (the chaincode keeps the first declaration). Use `/nation/convergence/all` for the nation-wide summary. Responses are `201 {"status":"ok"}` when the declaration wins.

#### Query convergence for the caller’s scope

```
GET /state/convergence?stateId=state-alpha
Authorization: Bearer <any runtime JWT>
```

If `stateId` is omitted the gateway uses the `state` claim from the runtime token. Response:

```json
{
  "state_id": "state-alpha",
  "is_converged": true,
  "converged_at": "2025-01-02T04:05:06Z",
  "declared_by": "checker-node-01",
  "summary_payload": {"cid":"...","notes":"..."},
  "clusters": [
    {
      "cluster_id": "cluster-01",
      "is_converged": true,
      "submitted_at": "2025-01-02T03:00:00Z",
      "source_id": "cluster-01-aggregator",
      "payload": {"cid":"...","accuracy":0.982}
    }
  ]
}
```

`GET /nation/convergence` returns a similar object for the nation scope with a `states` array describing each state’s contribution.

#### Admin lists

```
GET /state/convergence/list
Authorization: Bearer <admin HS256 JWT>
```

Returns a map of state IDs to `StateStatus` objects (same structure as the single-state endpoint). `GET /nation/convergence/list` returns the full nation map. Only `admin` tokens are allowed because the responses expose the entire network topology.
