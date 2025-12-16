# API Gateway Stack

1. A Verifiable Credential (VC)–aware enrollment endpoint that maps runtime JWTs to Fabric wallet identities and registers them on-chain.
2. A tiny data-service with only two APIs – commit arbitrary payloads and retrieve them later using the ID returned at commit time.

`docker-compose.yaml` still provisions the entire Fabric network (orderer + 3 peers), the bootstrap CLI, the gateway CLI, and the HTTP server in a single command so you can spin everything up with one `docker compose up` just like the original stack.

## Quick start

Follow these steps the first time you spin up the stack:

0. **Environment file.** Copy `.env.example` to `.env` and edit the values:
   ```bash
   cd api-gateway
   cp .env.example .env
   # edit .env to set AUTH_JWT_SECRET and ADMIN_PUBLIC_KEY at minimum
   ```
   `AUTH_JWT_SECRET` secures `/auth/register-trainer`. `ADMIN_PUBLIC_KEY` must match the base64 Ed25519 key derived from your admin private key. All other entries already match the defaults used by `docker-compose.yaml`.

1. **Seed Fabric MSP artifacts.**
   - If `./organizations` already contains MSP folders (default clone), skip.
   - To regenerate from scratch:
     - **Option A – cryptogen:**
       ```bash
       cd api-gateway
       cryptogen generate --config=crypto-config.yaml --output=organizations
       ```
     - **Option B – Fabric CA:** reuse the CA flow described later.
       1. Start CA:
          ```bash
          docker run -d --name ca-org1.nebula.com -p 7054:7054 -v $PWD/organizations/peerOrganizations/org1.nebula.com/ca:/etc/hyperledger/fabric-ca-server/ca -v $PWD/organizations/peerOrganizations/org1.nebula.com/tlsca:/etc/hyperledger/fabric-ca-server/tlsca hyperledger/fabric-ca:1.5 sh -c 'fabric-ca-server start -b admin:adminpw --ca.name ca-org1 --port 7054'
          ```
       2. Enroll admin:
          ```bash
          export FABRIC_CA_CLIENT_HOME=$PWD/organizations/peerOrganizations/org1.nebula.com/users/Admin@org1.nebula.com
          fabric-ca-client enroll \
            -u http://admin:adminpw@localhost:7054 \
            --caname ca-org1 \
            -M $FABRIC_CA_CLIENT_HOME/msp
          ```
       3. Enroll trainers:
          ```bash
          node scripts/enroll-trainer-identities.js \
            --ca-url http://localhost:7054 \
            --ca-name ca-org1 \
            --tls-cert organizations/peerOrganizations/org1.nebula.com/users/Admin@org1.nebula.com/msp/cacerts/localhost-7054-ca-org1.pem
          ```

2. **Generate the admin Ed25519 keypair** (used to sign VCs and populate `ADMIN_PUBLIC_KEY`).
   ```bash
   openssl genpkey -algorithm Ed25519 -out admin_ed25519_sk.pem
   
   openssl pkey -in admin_ed25519_sk.pem -pubout -outform DER | tail -c 32 | base64 > admin_public_key.b64
   ```
   Copy the single line from `admin_public_key.b64` into `.env` as `ADMIN_PUBLIC_KEY=...`. Keep `admin_ed25519_sk.pem` safe—you will use it to sign VCs.

3. **Prepare trainer identities (automated).**
   - Each trainer definition lives under `nodes-setup/nodes/node_X.json`. Update these files to change the list of trainer nodes or tweak per-node metadata (dataset parameters, topology hints, etc.). The `node_id` determines the trainer identifier used throughout the tooling (`trainer-node-XXX` naming is derived automatically).
   - To generate Ed25519 keypairs, unsigned VC payloads, and both JWT flavors for *all* trainers, run:
     ```bash
     cd api-gateway
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
       -v $PWD/organizations/peerOrganizations/org1.nebula.com/tlsca:/etc/hyperledger/fabric-ca-server/tlsca \
       hyperledger/fabric-ca:1.5 \
       sh -c 'fabric-ca-server start -b admin:adminpw --ca.name ca-org1 --port 7054'

     # 3b. enroll the CA admin (one time)
     export FABRIC_CA_CLIENT_HOME=$PWD/organizations/peerOrganizations/org1.nebula.com/users/Admin@org1.nebula.com
     fabric-ca-client enroll \
       -u http://admin:adminpw@localhost:7054 \
       --caname ca-org1 \
       -M $FABRIC_CA_CLIENT_HOME/msp
     ```
      Then enroll all trainers automatically:
     ```bash
     node scripts/enroll-trainer-identities.js \
       --ca-url http://localhost:7054 \
       --ca-name ca-org1 \
       --tls-cert organizations/peerOrganizations/org1.nebula.com/users/Admin@org1.nebula.com/msp/cacerts/localhost-7054-ca-org1.pem
     ```
     This registers each trainer (default secret `<trainerId>pw`), writes MSP material to `organizations/.../users/<trainer-id>/msp`, and provisions TLS certs under `.../users/<trainer-id>/tls`. Run it after the CA is up; pass `--force` to re-enroll or `--secret-template` if you need custom passwords. Stop the CA later with `docker rm -f ca-org1.nebula.com` if you no longer need it.

4. **Admin issues signed VCs.** Use the helper script to sign every unsigned VC with the admin Ed25519 key (`admin_ed25519_sk.pem` generated in step 2):
   ```bash
   cd api-gateway
   node scripts/sign-trainer-vcs.js \
     --key admin_ed25519_sk.pem \
     --force   # optional overwrite
   ```
   Signed credentials land in `nodes-setup/vc-signed/<trainer-id>_vc.json`. Give each trainer its matching signed VC so it can call `/auth/register-trainer`.

5. **Prepare a bulk-registration payload (optional but recommended).** After the network is up and the signed VCs exist, stitch the artifacts together:
   ```bash
   cd api-gateway
   node scripts/build-bulk-register-payload.js \
     --did-template did:nebula:hospitalA-node{trainerSeq} \
     --output nodes-setup/bulk-register.json \
     --force   # overwrite existing file
   ```
   The template accepts `{trainerId}`, `{nodeId}`, and `{trainerSeq}` (001, 002, …). The resulting JSON array can be POSTed to `/auth/register-trainers` once the server is running.

6. **Generate JWTs for registration and runtime.**
   - **Trainer registration:** HS256 JWT using the shared `AUTH_JWT_SECRET`. You can re-run `node jwt.js --sub trainer-node-001` with `JWT_ALG=HS256` and the secret exported, or reuse the pre-generated token from `nodes-setup/tokens/*_registration.jwt`.
   - **Runtime APIs:** Ed25519 JWT signed with the trainer’s private key. Again you can re-run `node jwt.js --sub trainer-node-001` with `JWT_ALG=EdDSA TRAINER_PRIVATE_KEY=/path/to/sk.pem`, or reuse `*_runtime.jwt`. Keep the private key PEM on the trainer host.

7. **Start the stack.**
   ```bash
   cd api-gateway
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
| `TRAINER_DB_PATH` | `/data/trainers.json` | Location on disk where the gateway remembers enrolled trainers. Mount `./data:/data` (already configured) for persistence. |
| `GATEWAY_JOB_ID` | empty | Optional job identifier – if set, the VC `job_id` must match this value. |

`ADMIN_PUBLIC_KEY` expects the raw 32-byte Ed25519 public key (no PEM headers) encoded with standard base64—the same data produced by the quick start commands above.

## Authentication flow

1. **Layer 1 (JWT):** every HTTP request supplies `Authorization: Bearer <token>`. Tokens use HS256, carry `sub`, `role`, and `exp` claims, and the gateway stores the resolved subject in the context for later lookups.
   - The **registration token** proves the caller knows the shared bootstrap secret (`AUTH_JWT_SECRET`). Only this token is accepted on `/auth/register-trainer`.
   - The **runtime token** proves the caller controls the trainer-specific Ed25519 key registered earlier. These are required for `/data/*` APIs.
2. **Layer 2 (VC enrollment):** before a node can call any runtime API it must invoke `POST /auth/register-trainer` once. During this call the gateway:
   - Verifies the JWT and resolves `sub`.
   - Verifies the VC signature against `ADMIN_PUBLIC_KEY`. The VC is canonicalized (stable key ordering, no whitespace) before hashing/signing; a SHA256 hash of the signed VC (including the signature field) becomes `vc_hash` and is stored on-chain.
   - Checks `valid_from`/`valid_until`, the DID, and optional `job_id`.
   - Maps the JWT subject to a Fabric wallet identity using the rule `trainer-<nodeId>` (non-alphanumeric characters collapse to `-`). The MSP material must live under `${ORG_CRYPTO_PATH}/users/<fabric-id>/msp`.
   - Calls the Fabric chaincode function `RegisterTrainer(did, nodeId, vcHash, publicKey)` signed by that identity.
   - Persists `{jwt_sub, fabric_client_id, nodeId, vc_hash, did, public_key}` inside `TRAINER_DB_PATH`.
3. **Layer 2 (runtime checks):** `POST /data/commit` and `GET /data/<id>` first validate the JWT, then look up the stored enrollment. The JWT signature must be Ed25519/`EdDSA` using the same public key supplied at registration. After that the Fabric transaction is signed with the trainer’s MSP, and the chaincode enforces the on-chain whitelist. A stolen registration token won’t help here; runtime calls require the private key that matches the registered public key.

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
  "did": "did:nebula:hospitalA-node001",
  "nodeId": "trainer-node-001",
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
  "did": "did:nebula:hospitalA",
  "node_id": "node-001",
  "registered_at": "2025-01-02T03:04:05Z"
}
```

Failures:
- Invalid/missing JWT → `401`.
- VC signature mismatch, outside validity window, or DID/job mismatch → `403`.
- Fabric invocation error (missing Fabric identity, ledger failure) → `500`.

### Bulk register trainers (admin only)

```
POST /auth/register-trainers
Authorization: Bearer <ADMIN JWT>
Content-Type: application/json

[
  {
    "did": "did:nebula:hospitalA-node001",
    "nodeId": "trainer-node-001",
    "public_key": "...",
    "vc": { ... }
  },
  {
    "did": "did:nebula:hospitalA-node002",
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
- `CommitData(dataId, payload)` → requires the invoker to be authorized, then writes the payload and metadata.
- `ReadData(dataId)` → returns the stored payload but only if the caller is the same trainer that originally committed it.
- `IsTrainerAuthorized()` helper used by future chaincode functions.

The bootstrap CLI now packages this chaincode under the label `gateway` so the API and Fabric stay in sync.

## Redeploying & testing

- **Chaincode:** bump `CHAINCODE_VERSION`/`CHAINCODE_SEQUENCE` and rerun `/scripts/bootstrap.sh` inside `gateway-cli`. Example: `docker exec gateway-cli bash -c 'CHAINCODE_VERSION=1.1 CHAINCODE_SEQUENCE=2 /scripts/bootstrap.sh'`.
- **API:** `docker compose build api-gateway && docker compose up -d api-gateway`.
- **Smoke test:** after the stack is up, call `GET /health`, then register a trainer with the VC JSON and JWT you prepared, and finally hit `POST /data/commit` followed by `GET /data/<id>` to ensure the ledger roundtrip works end-to-end.

Everything still runs behind the single compose file, so the workflow stays the same as `nebula-gateway` while giving you a trimmed, VC-hardened API surface.
> **Note:** The Fabric containers mount `./organizations/**` from your host. If you cloned a trimmed repo or wiped that directory, regenerate MSP material (via `cryptogen` or the CA flow above) *before* running `docker compose up`; otherwise the peers/orderer will crash with “could not load a valid signer certificate.”
