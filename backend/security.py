"""ALL authorization lives here. No LLM output is ever consulted for access decisions."""
import json, hashlib, hmac, secrets, threading, time
from db import q, x

ACTIONS = {"read", "write", "send_email", "export"}          # things the model may *propose*
ADMIN_ACTIONS = {"audit", "admin"}                           # global (project "*") capabilities
VALID_ACTIONS = ACTIONS | ADMIN_ACTIONS
CONFIRM_WHEN_TAINTED = {"send_email", "export", "write"}     # outbound / state-changing -> human in the loop
WILDCARD_OK = ADMIN_ACTIONS                                  # "*" project is only honoured for these
MAX_CLEARANCE = 4
CLEARANCE_MEANINGS = {
    0: "Lowest sensitivity; can read level 0 documents in permitted projects.",
    1: "Can read level 0-1 documents in permitted projects.",
    2: "Can read level 0-2 documents in permitted projects.",
    3: "Can read level 0-3 documents in permitted projects.",
    4: "Highest demo sensitivity; can read level 0-4 documents in permitted projects.",
}

# ---------- passwords ----------
def hpw(p, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", p.encode(), bytes.fromhex(salt), 200_000).hex()
    return f"pbkdf2${salt}${h}"

def check_pw(p, stored):
    stored = stored or ""
    if stored.startswith("pbkdf2$"):
        try: _, salt, _h = stored.split("$")
        except ValueError: return False
        return hmac.compare_digest(hpw(p, salt), stored)
    # legacy demo hash (older app.db files)
    return hmac.compare_digest(hashlib.sha256(("salt:" + p).encode()).hexdigest(), stored)

# ---------- authorization ----------
def perms(uid):
    u = q("select clearance from users where id=?", (uid,), one=True)
    if not u: return -1, set()
    rows = q("select rp.action a, rp.project p from user_roles ur join role_permissions rp on rp.role=ur.role where ur.user_id=?", (uid,))
    return (u["clearance"] or 0), {(r["a"], r["p"]) for r in rows}

def can(uid, action, project, level=0):
    """Default deny. A wildcard project is honoured only for audit/admin, never for data actions."""
    cl, p = perms(uid)
    if cl < 0 or level > cl: return False
    if (action, project) in p: return True
    return action in WILDCARD_OK and (action, "*") in p

def is_admin(uid): return can(uid, "admin", "*")
def can_audit(uid): return can(uid, "audit", "*") or is_admin(uid)

def _read_projects(p): return sorted({pr for a, pr in p if a == "read" and pr != "*"})

def _where(uid, doc_ids=None):
    """SQL predicate for chunks the user may read. doc_ids (if given) only NARROWS the authorized set."""
    cl, p = perms(uid)
    projs = _read_projects(p)
    if not projs or cl < 0: return "0", []
    w, a = f"c.project in ({','.join('?' * len(projs))}) and c.level<=?", projs + [cl]
    if doc_ids is not None:
        if not doc_ids: return "0", []                      # empty selection means nothing, never "everything"
        w += f" and c.doc_id in ({','.join('?' * len(doc_ids))})"; a += [int(i) for i in doc_ids]
    return w, a

def allowed_chunks(uid, doc_ids=None):
    """SQL-level filter: restricted chunks are never loaded, scored, or sent to the model."""
    w, a = _where(uid, doc_ids)
    return q(f"select c.id,c.doc_id,c.project,c.level,c.text,c.embedding,c.emb_tag,d.flag,d.flag_reason,d.title from chunks c join documents d on d.id=c.doc_id where {w} order by c.doc_id, c.id", a)

def allowed_ids(uid):
    w, a = _where(uid)
    return {r["id"] for r in q(f"select c.id from chunks c where {w}", a)}

def allowed_docs(uid):
    """Documents the user may read; this (and nothing else) is what the UI picker may list."""
    cl, p = perms(uid)
    projs = _read_projects(p)
    if not projs or cl < 0: return []
    return q(f"select id,title,project,level,flag,flag_reason from documents where project in ({','.join('?' * len(projs))}) and level<=? order by id", projs + [cl])

# ---------- tamper-evident audit log ----------
_audit_lock = threading.Lock()    # chain writes must be serialized (API threads + queue worker)

def audit(uid, event, detail):
    with _audit_lock:
        last = q("select hash from audit_log order by id desc limit 1", one=True)
        prev = last["hash"] if last else "0" * 64
        ts = time.time(); d = json.dumps(detail, sort_keys=True, default=str)
        h = hashlib.sha256(f"{prev}|{ts}|{uid}|{event}|{d}".encode()).hexdigest()
        x("insert into audit_log(ts,user_id,event,detail,prev_hash,hash) values(?,?,?,?,?,?)", (ts, uid, event, d, prev, h))

def verify_chain():
    prev = "0" * 64
    for r in q("select * from audit_log order by id"):
        h = hashlib.sha256(f"{prev}|{r['ts']}|{r['user_id']}|{r['event']}|{r['detail']}".encode()).hexdigest()
        if r["prev_hash"] != prev or r["hash"] != h: return False, r["id"]
        prev = h
    return True, None
