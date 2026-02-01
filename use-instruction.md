# Model Reference API Usage

Quick guide for committing and querying model references across the cluster, state, and nation scopes exposed by the gateway.

## Authentication

- All endpoints below require `Authorization: Bearer <runtime EdDSA JWT>`.
- Each trainer/aggregator JWT must map to a registered node so the gateway can resolve Fabric credentials.

## POST `<scope>/models`

Commit a model reference for a specific cluster, state, or nation. Each scope has its own slug:

| Scope   | Path             | Scope field examples                       | Round field examples                 |
|---------|------------------|--------------------------------------------|--------------------------------------|
| Cluster | `/cluster/models`| `cluster_id`, `scope_id`, `cluster`        | `round`, `cluster_round`, `cluster-round` |
| State   | `/state/models`  | `state_id`, `scope_id`, `state`            | `round`, `state_round`, `state-round`    |
| Nation  | `/nation/models` | `nation_id`, `scope_id`, `nation`          | `round`, `nation_round`, `nation-round`  |

Example payloads:

```http
POST /cluster/models
Content-Type: application/json

{
  "cluster_id": "cluster-7",
  "cluster_round": 12,
  "payload": {
    "model_hash": "sha256:cluster-model-v12",
    "cid": "bafybeicluster...",
    "dataset": "mnist-v1",
    "train_accuracy": 0.911,
    "notes": "cluster aggregation"
  }
}
```

```http
POST /state/models
Content-Type: application/json

{
  "state_id": "alpha",
  "state_round": 3,
  "payload": {
    "model_hash": "sha256:state-model-v3",
    "cid": "bafybeistate...",
    "dataset": "mnist-v1",
    "notes": "post-state aggregation run"
  }
}
```

```http
POST /nation/models
Content-Type: application/json

{
  "nation_id": "federal-1",
  "nation_round": 2,
  "payload": {
    "model_hash": "sha256:nation-model-v2",
    "cid": "bafybeinaton...",
    "dataset": "global-mnist-v2",
    "train_accuracy": 0.941,
    "notes": "post-state aggregation run"
  }
}
```

Response (`201 Created`) for all scopes:

```json
{
  "data_id": "model-1a2b3c",
  "layer": "state",
  "scope_id": "alpha",
  "round": 3,
  "node_id": "trainer-node-007",
  "vc_hash": "1bc9...",
  "submitted_at": "2025-01-02T03:04:05Z"
}
```

## GET `<scope>/models/<data_id>`

Retrieve a specific record by its `data_id`:

```
GET /state/models/model-1a2b3c
Authorization: Bearer <token>
```

Response (`200`):

```json
{
  "data_id": "model-1a2b3c",
  "layer": "state",
  "scope_id": "alpha",
  "round": 3,
  "owner": "trainer-node-007",
  "payload": { ... },
  "submitted_at": "2025-01-02T03:04:05Z"
}
```

## GET `<scope>/models?scope=...&round=...`

Use query parameters to fetch the record that matches a specific scope + round:

```
GET /state/models?state=alpha&round=3
```

- Scope aliases: `scopeId`, layer-specific key (`state_id`, `cluster_id`, `nation_id`), or shorthand (`state`, `cluster`, `nation`).
- Round aliases: `round`, `<scope>_round`, `<scope>-round`.
- Returns the single matching record (`200 OK`) or `404` with `{"error":"no model provided for state alpha round 3"}` if missing.

## GET `<scope>/models?scope=...&page=...`

List historical submissions for a scope (round optional):

```
GET /cluster/models?cluster=cluster-7&page=2
```

- `scopeId`/`cluster_id`/`state`/`nation` is optional; omit to list every record for that layer.
- `page` defaults to `1`; page size is fixed at 10.
- Response (`200`) includes `items`, `page`, `per_page`, `total`, and `has_more`. Each item mirrors the retrieve payload (with `round` when provided on commit).

## GET `<scope>/models/latest`

Fetch the latest submission for a scope (or for the entire layer when the scope parameter is omitted):

```
GET /state/models/latest?state=alpha
```

- Scope aliases match the list above (`scopeId`, `state_id`, `state`, etc.).
- When the scope parameter is omitted, the gateway returns the most recent model for the entire layer (e.g., the most recent nation submission).
- The response mirrors `GET /<scope>/models/<data_id>` and also echoes the scope identity using the layer-specific field (`state_id`, `cluster_id`, `nation_id`).

Example response (`200`):

```json
{
  "data_id": "model-1a2b3c",
  "layer": "state",
  "scope_id": "alpha",
  "state_id": "alpha",
  "round": 3,
  "owner": "trainer-node-007",
  "payload": { ... },
  "submitted_at": "2025-01-02T03:04:05Z"
}
```

## Error Handling

- Missing scope or round parameters return `400` responses that cite the required field.
- Unknown layers or unauthenticated calls return `404`/`401`.
- When querying by scope+round and no model exists, the API replies with `404` so callers can determine that the round has not been submitted yet.
