"""Admin API. Every route requires admin:* (checked by trusted code on every request) and every change is audited."""
import re, time
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from db import q, x, tx
from config import cfg
import security as S, ingest
from auth import require_admin

router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])
NAME = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

class Perm(BaseModel): action: str; project: str
class RoleBody(BaseModel): permissions: List[Perm]
class UserBody(BaseModel): clearance: Optional[int] = None; roles: Optional[List[str]] = None
class ProjectBody(BaseModel): name: str

def _clean_perms(perms):
    out = set()
    for p in perms:
        a, pr = p.action.strip(), p.project.strip()
        if a not in S.VALID_ACTIONS: raise HTTPException(400, f"unknown action '{a}' (allowed: {', '.join(sorted(S.VALID_ACTIONS))})")
        if a in S.ADMIN_ACTIONS: pr = "*"                               # audit/admin are global
        elif pr == "*" or not NAME.match(pr): raise HTTPException(400, f"project for '{a}' must be a name like X or Y (wildcards are not allowed for data actions)")
        out.add((a, pr))
    if not out: raise HTTPException(400, "a role needs at least one permission")
    return sorted(out)

def _admins_left(c):
    return c.execute("select count(*) from user_roles ur join role_permissions rp on rp.role=ur.role where rp.action='admin' and rp.project='*'").fetchone()[0]

def _guard_admin(c):
    if _admins_left(c) == 0: raise HTTPException(400, "refused: this would leave the system with no administrator")

# ---------- users ----------
@router.get("/users")
def users():
    roles = {}
    for r in q("select user_id,role from user_roles order by role"): roles.setdefault(r["user_id"], []).append(r["role"])
    return [{"id": u["id"], "username": u["username"], "clearance": u["clearance"], "created": u["created"], "roles": roles.get(u["id"], []), "pending": u["id"] not in roles}
            for u in q("select id,username,clearance,created from users order by id")]

@router.put("/users/{uid}")
def update_user(uid: int, b: UserBody, admin=Depends(require_admin)):
    if not q("select id from users where id=?", (uid,), one=True): raise HTTPException(404, "no such user")
    known = {r["role"] for r in q("select distinct role from role_permissions")}
    if b.clearance is not None and not 0 <= b.clearance <= S.MAX_CLEARANCE: raise HTTPException(400, f"clearance must be 0-{S.MAX_CLEARANCE}")
    if b.roles is not None and (set(b.roles) - known): raise HTTPException(400, f"unknown role(s): {', '.join(sorted(set(b.roles) - known))}")
    before = q("select clearance from users where id=?", (uid,), one=True)["clearance"]
    old = [r["role"] for r in q("select role from user_roles where user_id=?", (uid,))]
    with tx() as c:
        if b.clearance is not None: c.execute("update users set clearance=? where id=?", (b.clearance, uid))
        if b.roles is not None:
            c.execute("delete from user_roles where user_id=?", (uid,))
            for r in sorted(set(b.roles)): c.execute("insert into user_roles(user_id,role) values(?,?)", (uid, r))
        _guard_admin(c)
    S.audit(admin["id"], "admin_user_updated", {"target": uid, "clearance": [before, b.clearance if b.clearance is not None else before],
                                               "roles": [sorted(old), sorted(b.roles) if b.roles is not None else sorted(old)]})
    return {"ok": True}

# ---------- roles & permissions ----------
@router.get("/roles")
def roles():
    out = {}
    for r in q("select role,action,project from role_permissions order by role,action,project"):
        out.setdefault(r["role"], []).append({"action": r["action"], "project": r["project"]})
    cnt = {r["role"]: r["n"] for r in q("select role,count(*) n from user_roles group by role")}
    return [{"name": n, "permissions": p, "users": cnt.get(n, 0)} for n, p in out.items()]

@router.get("/meta")
def meta():
    projects = {r["name"] for r in q("select name from projects")}
    return {"actions": sorted(S.VALID_ACTIONS), "projects": sorted(projects), "max_clearance": S.MAX_CLEARANCE,
            "config": {k: cfg[k] for k in ("chat_model", "embed_backend", "embed_model", "mock_llm", "top_k")}}

@router.get("/projects")
def projects():
    return [dict(p) for p in q("select name,created from projects order by name")]

@router.post("/projects", status_code=201)
def create_project(b: ProjectBody, admin=Depends(require_admin)):
    name = b.name.strip()
    if not NAME.match(name) or name == "*": raise HTTPException(400, "project name must be 1-32 letters, digits, _ or -")
    if q("select name from projects where name=?", (name,), one=True): raise HTTPException(409, "project already exists")
    x("insert into projects(name,created) values(?,?)", (name, time.time()))
    S.audit(admin["id"], "admin_project_created", {"project": name})
    return {"name": name}

@router.put("/roles/{name}")
def put_role(name: str, b: RoleBody, admin=Depends(require_admin)):
    if not NAME.match(name): raise HTTPException(400, "role name: letters, digits, _ -")
    perms = _clean_perms(b.permissions)
    before = [(r["action"], r["project"]) for r in q("select action,project from role_permissions where role=?", (name,))]
    with tx() as c:
        c.execute("delete from role_permissions where role=?", (name,))
        for a, p in perms: c.execute("insert into role_permissions(role,action,project) values(?,?,?)", (name, a, p))
        _guard_admin(c)
    S.audit(admin["id"], "admin_role_saved", {"role": name, "before": sorted(before), "after": perms})
    return {"ok": True}

@router.delete("/roles/{name}")
def delete_role(name: str, admin=Depends(require_admin)):
    with tx() as c:
        c.execute("delete from role_permissions where role=?", (name,)); c.execute("delete from user_roles where role=?", (name,))
        _guard_admin(c)
    S.audit(admin["id"], "admin_role_deleted", {"role": name})
    return {"ok": True}

# ---------- documents (upload -> chunk -> label -> embed) ----------
@router.get("/documents")
def docs():
    return [dict(d) | {"flagged": bool(d["flag"])} for d in q("select d.id,d.title,d.project,d.level,d.flag,d.flag_reason,(select count(*) from chunks c where c.doc_id=d.id) chunks from documents d order by d.id desc")]

@router.post("/documents", status_code=201)
def upload(file: UploadFile = File(...), project: str = Form(...), level: int = Form(...), title: str = Form(""), admin=Depends(require_admin)):
    project = project.strip()
    if not NAME.match(project) or project == "*": raise HTTPException(400, "project must be a name like X or Y")
    if not 0 <= level <= S.MAX_CLEARANCE: raise HTTPException(400, f"level must be 0-{S.MAX_CLEARANCE}")
    limit = cfg["max_upload_mb"] * 1024 * 1024
    data = file.file.read(limit + 1)
    if len(data) > limit: raise HTTPException(413, f"file larger than {cfg['max_upload_mb']} MB")
    try: text = ingest.extract_text(file.filename, data)
    except ValueError as e: raise HTTPException(400, str(e))
    title = (title.strip() or re.sub(r"\.[^.]+$", "", file.filename or "Untitled"))[:200]
    try: r = ingest.add_document(title, project, level, text)
    except ValueError as e: raise HTTPException(400, str(e))
    S.audit(admin["id"], "document_uploaded", {"doc": r["id"], "title": title, "project": project, "level": level, "chunks": r["chunks"], "flagged": r["flagged"], "flag_reason": r["flag_reason"], "filename": file.filename, "embedder": cfg["embed_backend"]})
    return {**r, "title": title, "project": project, "level": level}

@router.delete("/documents/{did}")
def delete_doc(did: int, admin=Depends(require_admin)):
    d = q("select * from documents where id=?", (did,), one=True)
    if not d: raise HTTPException(404, "no such document")
    with tx() as c:
        c.execute("delete from chunks where doc_id=?", (did,)); c.execute("delete from documents where id=?", (did,))
    S.audit(admin["id"], "document_deleted", {"doc": did, "title": d["title"], "project": d["project"]})
    return {"ok": True}

@router.post("/reembed")
def reembed(admin=Depends(require_admin)):
    n = ingest.reembed_all()
    S.audit(admin["id"], "reembed_all", {"chunks": n, "embedder": cfg["embed_backend"], "model": cfg["embed_model"]})
    return {"chunks": n}
