import json, re, time, collections, threading
from contextlib import asynccontextmanager
from typing import List, Optional
import sqlite3
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from db import q, x, init
from config import cfg
import security as S, jobs, actions, ingest
from auth import current, make_token
import admin

init()
ingest.refresh_flag_reasons()

@asynccontextmanager
async def lifespan(app):
    jobs.start()
    yield

app = FastAPI(title="Secure AI Assistant", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(admin.router)

class Login(BaseModel): username: str; password: str
class Register(BaseModel): username: str; password: str
class Chat(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    session_id: Optional[int] = None
    doc_ids: List[int] = Field(default_factory=list, max_length=20)
class Confirm(BaseModel): approve: bool

# ---------------- accounts ----------------
USERNAME = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
_fails = collections.defaultdict(collections.deque); _fl = threading.Lock()

def _throttled(name):
    with _fl:
        d = _fails[name.lower()]
        while d and time.time() - d[0] > 300: d.popleft()
        return len(d) >= 8

@app.post("/register", status_code=201)
def register(b: Register):
    """Self-service sign-up. The new account has clearance 0 and NO roles: it can see nothing until an admin assigns permissions."""
    name = b.username.strip()
    if not USERNAME.match(name): raise HTTPException(400, "username: 3-32 characters, letters, digits, . _ -")
    if len(b.password) < 8: raise HTTPException(400, "password must be at least 8 characters")
    try: uid = x("insert into users(username,pw,clearance,created) values(?,?,0,?)", (name, S.hpw(b.password), time.time()))
    except sqlite3.IntegrityError: raise HTTPException(409, "username already taken")
    S.audit(uid, "user_registered", {"username": name})
    return {"id": uid, "username": name, "pending": True}

@app.post("/login")
def login(b: Login):
    if _throttled(b.username): raise HTTPException(429, "too many failed attempts; wait a few minutes")
    u = q("select * from users where username=?", (b.username,), one=True)
    if not u or not S.check_pw(b.password, u["pw"]):
        with _fl: _fails[b.username.lower()].append(time.time())
        S.audit(None, "login_denied", {"username": b.username}); raise HTTPException(401, "invalid credentials")
    S.audit(u["id"], "login", {})
    return {"token": make_token(u["id"])}

@app.get("/me")
def me(u=Depends(current)):
    cl, p = S.perms(u["id"])
    roles = [r["role"] for r in q("select role from user_roles where user_id=? order by role", (u["id"],))]
    return {**u, "permissions": sorted(f"{a}:{pr}" for a, pr in p), "roles": roles,
            "clearance_scope": f"Can read documents labeled level 0 through {cl}",
            "clearance_levels": [{"level": level, "meaning": S.CLEARANCE_MEANINGS[level]} for level in range(S.MAX_CLEARANCE + 1)],
            "is_admin": S.is_admin(u["id"]), "can_audit": S.can_audit(u["id"]), "pending": not p}

@app.get("/documents")
def documents(u=Depends(current)):
    """Only documents this user may read are ever listed (titles of other documents are not disclosed)."""
    return [{**dict(d), "flagged": bool(d["flag"])} for d in S.allowed_docs(u["id"])]

@app.get("/projects")
def projects(u=Depends(current)):
    """Return only projects that contain documents the current user may read."""
    docs = [dict(d) | {"flagged": bool(d["flag"])} for d in S.allowed_docs(u["id"])]
    grouped = {}
    for doc in docs:
        project = grouped.setdefault(doc["project"], {"name": doc["project"], "documents": [], "levels": set()})
        project["documents"].append(doc)
        project["levels"].add(doc["level"])
    return [
        {**project, "document_count": len(project["documents"]), "levels": sorted(project["levels"])}
        for project in sorted(grouped.values(), key=lambda item: item["name"].lower())
    ]

# ---------------- chat (queued) ----------------
@app.post("/chat", status_code=202)
def chat(b: Chat, u=Depends(current)):
    uid = u["id"]; msg = b.message.strip(); ids = sorted(set(b.doc_ids))
    if not msg: raise HTTPException(400, "empty message")
    if not ids: raise HTTPException(400, "Select or @mention at least one document to search.")
    busy = q("select count(*) n from jobs where user_id=? and status in ('queued','running')", (uid,), one=True)["n"]
    if busy >= cfg["max_queue_per_user"]: raise HTTPException(429, f"you already have {busy} messages in the queue; wait for them to finish")
    sid = b.session_id
    if sid:
        if not q("select id from sessions where id=? and user_id=?", (sid, uid), one=True): raise HTTPException(404, "no session")
    else:
        now = time.time(); sid = x("insert into sessions(user_id,title,created,updated) values(?,?,?,?)", (uid, msg[:60], now, now))
    jid = jobs.enqueue(uid, sid, msg, ids)
    return {"job_id": jid, "session_id": sid, "status": "queued"}

@app.get("/jobs/{jid}")
def job(jid: int, u=Depends(current)):
    j = q("select * from jobs where id=? and user_id=?", (jid, u["id"]), one=True)
    if not j: raise HTTPException(404, "no such job")
    return jobs.status(j)

@app.get("/sessions")
def sessions(u=Depends(current)):
    return [dict(r) | {"tainted": bool(r["tainted"])} for r in q("select id,title,tainted,created,updated from sessions where user_id=? order by coalesce(updated,created,id) desc limit 100", (u["id"],))]

@app.get("/sessions/{sid}")
def session(sid: int, u=Depends(current)):
    s = q("select * from sessions where id=? and user_id=?", (sid, u["id"]), one=True)
    if not s: raise HTTPException(404, "no session")
    out = []
    for m in q("select * from messages where session_id=? order by coalesce(job_id,id), id", (sid,)):
        meta = json.loads(m["meta"] or "{}"); action = None
        if meta.get("action_id"):          # live status, so a confirmed/rejected action shows its current state after reload
            a = q("select id,action,project,status,reason from action_requests where id=?", (meta["action_id"],), one=True)
            action = dict(a) if a else None
        out.append({"id": m["id"], "role": m["role"], "text": m["text"], "job_id": m["job_id"], "ts": m["ts"],
                    "sources": meta.get("sources"), "tainted": meta.get("tainted"), "error": meta.get("error"), "action": action})
    pend = [r["id"] for r in q("select id from jobs where session_id=? and status in ('queued','running') order by id", (sid,))]
    return {"id": sid, "title": s["title"], "tainted": bool(s["tainted"]), "messages": out, "pending_jobs": pend}

@app.post("/actions/{rid}/confirm")
def confirm(rid: int, b: Confirm, u=Depends(current)):
    r = q("select * from action_requests where id=? and user_id=? and status='pending_confirm'", (rid, u["id"]), one=True)
    if not r: raise HTTPException(404, "nothing to confirm")
    if not b.approve: return actions.finish(rid, "rejected", "rejected by user", u["id"])
    x("update action_requests set status='approved' where id=?", (rid,))
    S.audit(u["id"], "action_confirmed", {"request": rid})
    return actions.execute(rid)                                   # permissions re-checked again

# ---------------- audit ----------------
@app.get("/audit")
def audit(limit: int = 25, offset: int = 0, user_id: Optional[int] = None, event: Optional[str] = None,
          text: Optional[str] = None, since: Optional[float] = None, until: Optional[float] = None, u=Depends(current)):
    """Auditors/admins see everything (with filters); everyone else only their own events, enforced here."""
    if not S.can_audit(u["id"]): user_id = u["id"]
    w, a = [], []
    if user_id is not None: w.append("a.user_id=?"); a.append(user_id)
    if event: w.append("a.event=?"); a.append(event)
    if text: w.append("(a.detail like ? or a.event like ? or u.username like ?)"); a += [f"%{text}%"] * 3
    if since is not None: w.append("a.ts>=?"); a.append(since)
    if until is not None: w.append("a.ts<=?"); a.append(until)
    W = ("where " + " and ".join(w)) if w else ""
    limit = max(1, min(limit, 200)); offset = max(0, offset)
    total = q(f"select count(*) n from audit_log a left join users u on u.id=a.user_id {W}", a, one=True)["n"]
    rows = q(f"select a.id,a.ts,a.user_id,u.username,a.event,a.detail from audit_log a left join users u on u.id=a.user_id {W} order by a.id desc limit ? offset ?", a + [limit, offset])
    own = "" if S.can_audit(u["id"]) else "where user_id=%d" % u["id"]
    events = [r["event"] for r in q(f"select distinct event from audit_log {own} order by event")]
    return {"total": total, "items": [dict(r) for r in rows], "events": events, "scope": "all" if S.can_audit(u["id"]) else "own"}

@app.get("/audit/verify")
def verify(u=Depends(current)):
    ok, bad = S.verify_chain(); return {"valid": ok, "first_bad_row": bad}
