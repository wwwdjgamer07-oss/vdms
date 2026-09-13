# Trust-Aware Virtual Database (TAVDB)

TAVDB is a runnable educational prototype of a virtual database layer: a client calls one API, while that layer validates a limited SQL dialect, classifies requested columns, routes work by node trust, and produces an immutable-style audit trail. It demonstrates access control and query isolation; it does **not** claim cryptographic confidentiality against a fully compromised execution node.

```mermaid
flowchart LR
 C[Client] --> V[Virtual Database Layer] --> T[Trust Evaluation] --> R[Query Router]
 R --> A[Trusted node] & B[Semi-trusted node] & D[Non-trusted node]
```

```mermaid
flowchart TD
 Q[Query]-->P[Allowlisted parser]-->C[Column classification]-->E{Policy}
 E--safe-->N[Least-trusted eligible node]
 E--sensitive-->S[Trusted execution / split plan]
 E--unsafe-->X[Denied and audited]
```

## Trust model and security

`employees.id` is PUBLIC, `name` and `department` INTERNAL, `salary` CONFIDENTIAL, and `medical_information` HIGHLY_CONFIDENTIAL. Non-trusted nodes may only SELECT approved tables and cannot receive confidential columns. Mixed queries requested against a non-trusted node are rewritten to trusted execution; the audit record describes the split plan. The production extension point is in `VirtualDatabaseLayer._run`, where real separately credentialed replicas would execute the projection fragments.

SQL is constrained to single, simple SELECT statements over allowlisted tables/columns. Semicolons, comments, destructive DDL, UNION, and mutations are blocked. This is deliberate: it is not a general SQL gateway.

Docker includes three physical PostgreSQL node containers plus metadata PostgreSQL. The `non-trusted-db` uses its own `nontrusted_user` credentials and is not exposed by an API or host port. Its initialization grants only `SELECT(id,name,department)` and explicitly omits salary, medical data, mutation, and metadata privileges. The virtual layer applies the same policy before delegation.

## Run

Local (uses SQLite metadata):

```bash
python -m venv .venv
.venv\\Scripts\\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
python demo.py
pytest -q
```

Or start services with `docker compose up --build`, then open `/docs` or `/dashboard/`. Register, log in, pass `Authorization: Bearer <token>`, and call `POST /queries` with `{ "sql": "SELECT name FROM employees", "preferred_node": "non-trusted-node" }`.

## Vercel deployment

Set `DATABASE_URL` to a hosted PostgreSQL URL and `JWT_SECRET` to a long random value in Vercel Project Settings before deploying. Standard `postgres://` and `postgresql://` provider URLs are normalized automatically for the installed `psycopg` driver. A Vercel deployment without `DATABASE_URL` uses ephemeral `/tmp` SQLite only as a preview fallback; data will not persist.

## Persistent application data

The managed `employees`, `customers`, `products`, `orders`, `students`, and
`patients` tables are real SQLAlchemy tables, not in-memory fixtures. They are
created at startup and are read by the policy-routed query layer. Use the Data
Manager at `/dashboard/data.html` after signing in, or the authenticated API:

```text
GET    /data/{table}       list records
POST   /data/{table}       create: {"values": {"name": "Cara", ...}}
PUT    /data/{table}/{id}  update supplied values
DELETE /data/{table}/{id}  delete a record
```

Only the approved table columns can be written. The generated `id` cannot be
supplied by clients, and all SQL reads continue through the parser, trust
policy, router, and audit trail.

For persistent Vercel data, set `DATABASE_URL` to a hosted PostgreSQL instance.
The `/tmp` SQLite preview fallback is ephemeral and will lose records when the
deployment is recycled.

## Data model and audit

SQLAlchemy models cover User, Database, Node, TableMetadata, ColumnMetadata, QueryRequest, QueryExecution, and AuditLog. Every decision includes requested data, selected node/trust level, reason, outcome, and duration at `GET /audit/logs`.

## Limitations / future work

This is a small demonstration, with in-process replica data and a restricted parser instead of a full AST/optimizer. It does not implement encryption at rest/in transit, key management, differential privacy, TEEs, row-level policy, distributed transactions, or cryptographic protection after a trusted node is compromised. Production work should use a mature SQL parser, parameter binding, real replica initialization/grants, TLS, secrets management, and optionally TEE/encrypted-compute integration.
