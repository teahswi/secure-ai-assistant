# Secure AI Assistant for Defense Organizations

**Thesis: authorization belongs outside the LLM.** Even a fully manipulated model cannot read or do anything beyond what the requesting *user* is allowed to. Every access decision is made by deterministic code (`backend/security.py`) that never looks at model output.

```
React frontend ─► FastAPI backend ─► SQLite
 chat · admin · audit   ├─ Auth + RBAC middleware        (trusted code)
                        ├─ Chat job queue + worker       (trusted code)
                        ├─ Retrieval / RAG               (authorize in SQL, then rank)
                        ├─ Processing LM (Ollama)        (model, UNTRUSTED)
                        └─ Action executor               (trusted code, re-checks everything)
Ingestion (admin upload) ─► parse → chunk → label → embed → SQLite
```

## What the app does

| Feature | How it works |
|---|---|
| **Create an account** | Log-in screen → *Create account*. A new account has clearance 0 and **no roles**, so it can see nothing until an admin assigns permissions. The UI shows a "waiting for an administrator" banner and picks up the change automatically. |
| **Clearance levels** | A user's clearance is the highest document sensitivity level they may read: clearance 1 allows levels 0-1, clearance 3 allows levels 0-3. Clearance alone does not grant project access; the user also needs a `read:project` permission. |
| **Create a project** | Admin → *Projects* → enter a project name. Then upload documents into it and assign `read:project` or `write:project` permissions through a role. |
| **Admin console** (Admin tab, admin only) | *Users*: set clearance 0-4 and roles. *Roles & permissions*: create roles, add/remove `action:project` permissions. *Documents*: upload, list, delete, re-embed. The last administrator can't be removed. |
| **Upload → RAG ingestion** | Admin uploads `.txt .md .docx .pdf` with a project and level. Ingestion extracts text, chunks it, flags suspected injection, embeds every chunk and stores it with its project + level (one atomic transaction). |
| **You name the documents** | Instead of embedding-search over *everything*, you pick documents with `@mention` autocomplete or **+ Documents**. Only documents you're cleared for are even listed. RAG then runs inside those documents: embed the question, rank chunks, send the top-k to the model. |
| **Queued chat** | `POST /chat` enqueues a job and returns immediately. One background worker processes jobs in order. The UI shows your message at once, then *Queued (n ahead)* → *Searching your selected documents* → *Model is writing a reply*, then the answer rendered as sanitized Markdown. You can keep typing; replies arrive in order. Conversations are saved, listed in the sidebar and survive a page refresh. |
| **Audit** (Audit tab) | Admins and auditors see the whole hash-chained log with filters (event, user, text, date range), pagination and **Verify chain**. Everyone else sees only their own events. |
| **Confirmation path** | In a session that touched sensitive (level ≥ `taint_level`) or injection-flagged content, `send_email`, `export` and `write` become *pending confirmation*: Approve / Reject in the chat. Permissions are re-checked on approval. |

Clearance is a numeric sensitivity ceiling, not a role: level 0 is the lowest sensitivity, level 1 allows levels 0-1, level 2 allows levels 0-2, level 3 allows levels 0-3, and level 4 is the highest demo sensitivity and allows levels 0-4. A user still needs a project-specific `read` permission, and `write` is granted separately.

## Why the security properties hold

| Constraint | Implementation |
|---|---|
| Authorization outside the LLM | `can()`, `allowed_docs()`, `allowed_chunks()` in `security.py`: plain SQL and set lookups |
| Least privilege per user | JWT holds only `user_id`; role, clearance and permissions are re-read on **every** request and again when a queued job is *processed* |
| Block data before the model | Retrieval filters in SQL (`project IN (...) AND level <= clearance`) before anything is loaded, scored or prompted. The document selection can only **narrow** that set; an empty selection means nothing, never everything |
| Multi-tool coverage | Every model-proposed action (`read`, `write`, `send_email`, `export`) goes through one executor that calls `can()` |
| Default deny | `*` as a project is honoured **only** for `audit`/`admin`. A stray `write:*` row grants nothing, and the admin API refuses to create one |
| Auditability | `audit_log` is hash-chained and writes are serialized with a lock (the worker and API threads both write); `/audit/verify` detects tampering |
| Indirect injection | Retrieved text is wrapped in `<DOC>` tags (a document can't forge/close the tags); ingestion flags suspicious documents; the model can only *propose* |
| Stale context | History turns built on chunks the user can no longer access are dropped from the prompt |
| Air-gapped | Only local components: SQLite and Ollama |

## Setup

Prerequisites: Python 3.10+, Node 18+, [Ollama](https://ollama.com) (optional: use mock mode without it).

### 1. Models (skip for mock mode)
```powershell
ollama serve
ollama pull qwen3:1.7b          # light chat model used for RAG answers (default, see config.json)
# optional, only if you switch embed_backend to "ollama":
ollama pull qwen3-embedding
```

### 2. Backend
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt     # NEW vs. before: python-multipart, pypdf, httpx
python seed.py                      # creates app.db (re-run to reset everything)
uvicorn main:app --port 8000
```
**Mock mode** (no Ollama; simulates a *fully compromised* model that obeys any `ACTION:` line it finds in documents): `$env:MOCK_LLM="1"` before `uvicorn`.

### 3. Frontend
```powershell
cd frontend
npm install
npm run dev                         # http://localhost:5173 (proxies /api to :8000)
```
The frontend pins `vite` to 4.5.5 (see CHANGES.txt) so it builds without Rollup 4's native module.

### 4. Accounts
| User | Password | Clearance | Role | Permissions |
|---|---|---|---|---|
| bob | bob123 | 1 | contractor | read X |
| alice | alice123 | 3 | analyst_x | read, **write**, send_email, export on X |
| carol | carol123 | 4 | analyst_y | read, send_email on Y |
| dave | dave123 | 0 | auditor | view the full audit log |
| admin | admin123 | 0 | admin | admin console + audit log |

**Change the admin password and `JWT_SECRET` outside a demo.** `admin` has no document access of its own; it manages users and uploads, and can grant itself a read role if it wants to chat over documents.

When a user logs in again, the token identifies only the account. Roles, read/write permissions, and clearance are loaded from the database again, so administrator changes apply without creating a new account.

## Configuration: `backend/config.json`

| Key | Default | Meaning |
|---|---|---|
| `chat_model` | `qwen3:1.7b` | RAG answer model. For the full model use `qwen3:8b` (other light options: `qwen3:0.6b`, `llama3.2:1b`) |
| `chat_think` | `false` | Sent to Ollama as `think`. Set `null` if your model rejects the flag |
| `embed_backend` | `hash` | `hash` = built-in local embedder, no model needed (placeholder quality). `ollama` = real embeddings via `embed_model` |
| `embed_model` | `qwen3-embedding` | Used when `embed_backend` is `ollama` |
| `top_k` / `chunk_size` / `history_messages` | `4` / `500` / `6` | RAG tuning |
| `taint_level` | `2` | Chunk level at which a session needs confirmation for outbound/write actions |
| `max_queue_per_user` | `5` | Queued + running messages per user (HTTP 429 beyond that) |
| `max_upload_mb` | `5` | Upload size limit |
| `mock_llm`, `ollama_url`, `llm_timeout_s` | `false`, `http://localhost:11434`, `300` | |

Every key can also be overridden by an upper-case environment variable (e.g. `CHAT_MODEL=qwen3:8b`). Restart `uvicorn` after editing. **After changing `embed_backend`/`embed_model`, click *Re-embed all*** (Admin → Documents) so stored vectors match; until then the retriever never compares vectors from different embedders, it falls back to the built-in one.
Other env vars: `JWT_SECRET`, `DB_PATH`, `CONFIG_PATH`.

## Demo script (about 4 minutes)

1. **Sign-up needs an admin.** Create account `eve`. Banner: no permissions, no documents. Log in as `admin` → Admin → Users → give `eve` clearance 1 + role `contractor` → `eve`'s banner disappears on its own.
2. **Upload → RAG.** As `admin`: Admin → Documents → upload a file as project `X`, level 3. As `bob`: it isn't listed (level 3 > clearance 1). As `alice`: `@mention` it, ask a question, see the sourced answer.
3. **Confused deputy blocked.** As `bob`: select *Project X Vendor Notes*, ask for a summary. The document tells the model to read Project Y; the chat shows **denied: user lacks 'read' on project Y**. Bob's picker never lists Project Y or the level 2-3 X documents.
4. **Bob can't write to X.** As `bob`: select *Project X Write Probe* (it carries an injected `write` on X). Result: **denied: user lacks 'write'**. As `alice` the same action is allowed (or asks for confirmation if the session is tainted).
5. **Exfiltration needs a human.** As `alice`: select *Project X Field Memo* → model proposes `send_email` to an attacker → **pending_confirm** → Reject.
6. **Tamper-evident audit.** As `admin` (or `dave`): Audit log → filter, **Verify chain** (valid). Then `sqlite3 backend/app.db "update audit_log set event='x' where id=3"` and verify again.
7. **Queue.** Send three messages quickly and watch *Queued (n ahead)* → searching → writing.

(The injection demos 3-5 need `MOCK_LLM=1`, or a model that actually follows the injected line. The mock deliberately plays a fully compromised model.)

## Tests
```powershell
cd backend
$env:MOCK_LLM="1"; pytest -q tests      # 21 tests
```
Covers `can()`, wildcard handling, bob-cannot-write, SQL chunk filter + document selection never widening access, sign-up/admin flow, last-admin protection, RAG ranking, injection through the queue, forbidden-document selection, upload + level enforcement, `.docx` extraction, audit scoping/filters, concurrent audit writers and tamper detection.

## Layout
```
backend/
  config.json / config.py   model + RAG settings (edit config.json)
  main.py        public API: register, login, chat (enqueue), jobs, sessions, documents, confirm, audit
  admin.py       admin API: users, roles, documents (upload), re-embed
  jobs.py        queue + worker: retrieve → generate → propose → execute
  rag.py         authorize → narrow to selected docs → rank by embedding
  actions.py     action executor (re-checks permissions, confirmation logic)
  security.py    can(), allowed_*(), password hashing, audit chain   <-- the trust boundary
  auth.py        JWT dependency, require_admin
  ingest.py      parse (.txt/.md/.docx/.pdf), chunk, flag, embed, store
  llm.py         Ollama chat + embeddings (+ mock mode)
  db.py          schema, migrations for old app.db files
  seed.py        demo users, roles, documents
frontend/src/    App, Auth, Chat, Admin, Audit, api.js, styles.css
```

## API
| Endpoint | Purpose |
|---|---|
| `POST /register`, `POST /login`, `GET /me` | sign-up (no permissions), JWT, current permissions |
| `GET /documents` | documents *this user* may read (the picker's source) |
| `POST /chat` `{message, session_id?, doc_ids[]}` | enqueue → `202 {job_id, session_id}` |
| `GET /jobs/{id}` | `queued` (with `position`) / `running` (`stage`) / `done` (result) / `error` |
| `GET /sessions`, `GET /sessions/{id}` | conversation list / history (+ jobs still pending) |
| `POST /actions/{id}/confirm` | owner approves/rejects a `pending_confirm` action |
| `GET /audit?limit&offset&user_id&event&text&since&until`, `GET /audit/verify` | audit log (own events unless auditor/admin), chain check |
| `/admin/users`, `/admin/roles`, `/admin/documents`, `/admin/reembed`, `/admin/meta` | admin only; every change is audited |

## Known limitations
- **Single process and DB.** A backend bug could bypass RBAC. Mitigation: checks live in a few small, unit-tested functions. For production use Postgres row-level security with per-project DB roles. The queue is in-process with one worker; use a real broker for several workers.
- **Injection flagging is regex-based** and misses encoded/obfuscated payloads. It's a *signal for taint*, not the control; RBAC is the control.
- **Aggregation/inference** is only partly covered: a summary can only use chunks the user may read, and tainting adds confirmation on outbound actions, but there is no semantic leak detector.
- `send_email` / `export` / `write` are **simulated**; `read` lists documents. Wire real tools through the same executor.
- A small model can *say* it did something ("I've added it to X"). Only the executor's outcome line under the message is real; the system prompt tells the model not to claim actions, but that's a prompt, not a control.
- The built-in `hash` embedder is a bag-of-words placeholder; use `embed_backend: ollama` for semantic search.
- Taint is session-wide and coarse by design. Passwords use per-user salted PBKDF2; the audit log has no external anchor, so someone with DB write access could rebuild the chain. Login throttling is in memory only.

## Troubleshooting
- *"Cannot reach the backend"* in the UI: start `uvicorn main:app --port 8000` from `backend/`.
- *Replies look like "Summary: …" only*: Ollama isn't reachable or the model isn't pulled, so the mock model answered. Check `ollama list`; the uvicorn log prints a warning.
- *Old `app.db`*: it migrates automatically and old passwords still work, but it has no admin: run `python seed.py` to reset.
- *Upload says PDF needs pypdf*: run `pip install -r requirements.txt` again.
- *Reset everything*: `python seed.py`.
