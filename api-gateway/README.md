# API Gateway Stack

This directory clones the former `nebula-gateway` deployment and trims it down to the two services we now care about:

1. A Verifiable Credential (VC)–aware enrollment endpoint that maps runtime JWTs to Fabric wallet identities and registers them on-chain.
2. A tiny data-service with only two APIs – commit arbitrary payloads and retrieve them later using the ID returned at commit time.

`docker-compose.yaml` still provisions the entire Fabric network (orderer + 3 peers), the bootstrap CLI, the gateway CLI, and the HTTP server in a single command so you can spin everything up with one `docker compose up` just like the original stack.

## Quick start

Follow these steps the first time you spin up the stack:

1. **Generate the admin Ed25519 keypair** (used to sign VCs and populate `ADMIN_PUBLIC_KEY`).
   ```bash
   openssl genpkey -algorithm Ed25519 -out admin_ed25519_sk.pem
   openssl pkey -in admin_ed25519_sk.pem -pubout -outform DER | tail -c 32 | base64 > admin_public_key.b64
   ```
   Copy the single line from `admin_public_key.b64` into `.env` as `ADMIN_PUBLIC_KEY=...`. Keep `admin_ed25519_sk.pem` safe—you will use it to sign VCs.

2. **Prepare trainer MSP folders.** For every node that might participate, create a directory under `organizations/peerOrganizations/org1.nebula.com/users/<fabric-client-id>/msp`. The `<fabric-client-id>` must match `trainer-<nodeId>` once lowercased and sanitized. You can either:
   - Copy one of the sample users (e.g., `User1@org1.nebula.com`) and rename the folder, or
   - Enroll a real identity via Fabric CA and place the resulting `msp/` structure there.

3. **Issue a VC for each trainer.** Build the helper tool and sign the credential JSON with the admin private key:
   ```bash
   cd api-gateway/api
   go build ./cmd/vctool

   cat > trainer-node-001_unsigned.json <<'EOF'
   {
     "issuer": "did:nebula:admin001",
     "job_id": "job_2025_heart_model",
     "subject": "did:nebula:hospitalA-node001",
     "permissions": ["train", "commit"],
     "valid_from": "2025-12-01T00:00:00Z",
     "valid_until": "2026-12-31T00:00:00Z"
   }
   EOF

   ./vctool -vc trainer-node-001_unsigned.json -key /path/to/admin_ed25519_sk.pem -out trainer-node-001_vc.json
   ```
   The output file already contains the canonical JSON plus the `signature` field.

4. **Generate a JWT for testing.** The gateway accepts HS256-signed tokens with `sub`, `role`, and `exp`. Update `jwt.js` in the repo (set `SECRET` and the payload claims to match your node) and run:
   ```bash
   cd api-gateway
   AUTH_JWT_SECRET="super-secret" node jwt.js
   ```
   The script prints a ready-to-use token that you can drop into the `Authorization: Bearer ...` header.

5. **Start the stack.**
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
| `AUTH_JWT_SECRET` | _(required)_ | Shared HS256 secret that signs runtime JWTs. |
| `ADMIN_PUBLIC_KEY` | _(required)_ | Base64-encoded Ed25519 public key used to verify VC signatures. |
| `TRAINER_DB_PATH` | `/data/trainers.json` | Location on disk where the gateway remembers enrolled trainers. Mount `./data:/data` (already configured) for persistence. |
| `GATEWAY_JOB_ID` | empty | Optional job identifier – if set, the VC `job_id` must match this value. |

`ADMIN_PUBLIC_KEY` expects the raw 32-byte Ed25519 public key (no PEM headers) encoded with standard base64—the same data produced by the quick start commands above.

## Authentication flow

1. **Layer 1 (JWT):** every HTTP request supplies `Authorization: Bearer <token>`. Tokens use HS256, carry `sub`, `role`, and `exp` claims, and the gateway stores the resolved subject in the context for later lookups.
2. **Layer 2 (VC enrollment):** before a node can call any runtime API it must invoke `POST /auth/register-trainer` once. During this call the gateway:
   - Verifies the JWT and resolves `sub`.
   - Verifies the VC signature against `ADMIN_PUBLIC_KEY`. The VC is canonicalized (stable key ordering, no whitespace) before hashing/signing; a SHA256 hash of the signed VC (including the signature field) becomes `vc_hash` and is stored on-chain.
   - Checks `valid_from`/`valid_until`, the DID, and optional `job_id`.
   - Maps the JWT subject to a Fabric wallet identity using the rule `trainer-<nodeId>` (non-alphanumeric characters collapse to `-`). The MSP material must live under `${ORG_CRYPTO_PATH}/users/<fabric-id>/msp`.
   - Calls the Fabric chaincode function `RegisterTrainer(did, nodeId, vcHash, publicKey)` signed by that identity.
   - Persists `{jwt_sub, fabric_client_id, nodeId, vc_hash, did, public_key}` inside `TRAINER_DB_PATH`.
3. **Layer 2 (runtime checks):** `POST /data/commit` and `GET /data/<id>` first validate the JWT, then look up the stored enrollment. The Fabric transactions are also signed with that trainer identity, so the chaincode performs an additional whitelist check using the caller’s `clientID` before mutating ledger state. A stolen JWT alone is not enough to bypass the Fabric-level authorization.

## HTTP API

Base URL: `http://localhost:9000`

### Health check

```
GET /health
```

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
  "public_key": "<trainer public key base64 or hex>",
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
