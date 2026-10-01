"""Chat job queue. POST /chat only *enqueues*; one background worker runs the pipeline (retrieve -> generate -> propose
action -> executor) so a slow local model never blocks the API and users see queued / retrieving / generating states.
State lives in the `jobs` table, so it survives page reloads and is recovered after a server restart."""
import html, json, logging, queue, re, threading, time
from db import q, x
import security as S, llm, rag, actions
from config import cfg

log = logging.getLogger("jobs")
Q = queue.Queue()
_thread = None
_lock = threading.Lock()

def _set(jid, **kw):
    x(f"update jobs set {','.join(k + '=?' for k in kw)} where id=?", (*kw.values(), jid))

def enqueue(uid, sid, message, doc_ids):
    now = time.time()
    jid = x("insert into jobs(user_id,session_id,message,doc_ids,status,stage,created) values(?,?,?,?,'queued','queued',?)",
            (uid, sid, message, json.dumps(doc_ids), now))
    x("insert into messages(session_id,role,text,job_id,ts) values(?,?,?,?,?)", (sid, "user", message, jid, now))
    x("update sessions set updated=? where id=?", (now, sid))
    S.audit(uid, "chat_queued", {"job": jid, "session": sid, "docs": doc_ids})
    Q.put(jid)
    return jid

def status(j):
    out = {"id": j["id"], "session_id": j["session_id"], "status": j["status"], "stage": j["stage"], "error": j["error"],
           "result": json.loads(j["result"]) if j["result"] else None}
    if j["status"] == "queued":
        out["position"] = q("select count(*) n from jobs where status in ('queued','running') and id<?", (j["id"],), one=True)["n"]
    return out

def _doc_block(r):
    clean = re.sub(r"</?\s*DOC", "", r["text"], flags=re.I)       # a document may not close/forge DOC tags
    return f'<DOC id="{r["id"]}" title="{html.escape(r["title"], quote=True)}" project="{html.escape(r["project"], quote=True)}" level="{r["level"]}">{clean}</DOC>'

def _persist_reply(sid, jid, uid, text, top, mx, meta):
    x("insert into messages(session_id,role,text,chunk_ids,level,job_id,meta,ts) values(?,?,?,?,?,?,?,?)",
      (sid, "assistant", text, json.dumps([r["id"] for r in top]), mx, jid, json.dumps(meta), time.time()))

def run(jid):
    j = q("select * from jobs where id=?", (jid,), one=True)
    if not j or j["status"] != "queued": return
    uid, sid, msg = j["user_id"], j["session_id"], j["message"]
    doc_ids = json.loads(j["doc_ids"] or "[]")
    _set(jid, status="running", stage="retrieving", started=time.time())
    if not q("select id from users where id=?", (uid,), one=True): raise RuntimeError("user no longer exists")

    # 1. retrieval: authorization happens in SQL, at processing time (so role changes while queued still apply)
    res = rag.retrieve(uid, msg, doc_ids); top = res["chunks"]
    S.audit(uid, "retrieval", {"session": sid, "job": jid, "requested_docs": doc_ids, "candidates": res["candidates"], "returned": [r["id"] for r in top]})
    if res["denied"]: S.audit(uid, "retrieval_denied", {"session": sid, "job": jid, "docs": res["denied"], "reason": "not permitted or unknown"})
    note = (f" ({len(res['denied'])} selected document(s) are not accessible to you and were skipped.)" if res["denied"] else "")
    if not top:
        text = "I can't use any of the selected documents: you don't have access to them or they don't exist." if doc_ids else "Please select or @mention at least one document."
        _persist_reply(sid, jid, uid, text, [], 0, {"sources": [], "tainted": False, "denied": len(res["denied"])})
        result = {"session_id": sid, "reply": text, "tainted": False, "sources": [], "action": None, "denied_docs": len(res["denied"])}
        _set(jid, status="done", stage="done", result=json.dumps(result), finished=time.time()); return

    # 2. history: drop earlier turns built on chunks the user can no longer access
    ok = S.allowed_ids(uid); hist = []
    old = q("select * from messages where session_id=? and job_id<? order by id desc limit ?", (sid, jid, cfg["history_messages"]))
    for m in list(old)[::-1]:
        if json.loads(m["meta"] or "{}").get("error"): continue
        if all(i in ok for i in json.loads(m["chunk_ids"] or "[]")): hist.append({"role": m["role"], "content": m["text"]})
        else: S.audit(uid, "context_drop", {"message": m["id"]})

    # 3. generate (the model is untrusted: it can only propose)
    _set(jid, stage="generating")
    docs = "\n".join(_doc_block(r) for r in top)
    reply = llm.chat(hist + [{"role": "user", "content": f"{docs}\n\nQuestion: {msg}"}])
    m = re.search(r"ACTION:\s*(\{.*?\})", reply, re.S)
    text = re.sub(r"ACTION:\s*\{.*?\}", "", reply, flags=re.S).strip() or "(no answer)"
    mx = max(r["level"] for r in top)
    tainted = any(r["level"] >= cfg["taint_level"] or r["flag"] for r in top)
    sources = [{"id": r["id"], "doc_id": r["doc_id"], "title": r["title"], "project": r["project"], "level": r["level"], "flagged": bool(r["flag"]), "flag_reason": r["flag_reason"]} for r in top]
    x("update sessions set max_level_seen=max(max_level_seen,?), tainted=max(tainted,?), updated=? where id=?", (mx, int(tainted), time.time(), sid))

    # 4. model-proposed action -> executor (re-checks the USER's permissions; may require human confirmation)
    action = None
    if m:
        act = proj = None
        try: a = json.loads(m.group(1)); act, proj = a.get("action"), str(a.get("project", ""))
        except Exception: pass
        if act in S.ACTIONS:
            rid = x("insert into action_requests(session_id,user_id,action,project,args,status) values(?,?,?,?,?,'proposed')", (sid, uid, act, proj, json.dumps(a)))
            S.audit(uid, "action_proposed", {"request": rid, "action": act, "project": proj, "by": "model"})
            action = {**actions.execute(rid), "action": act, "project": proj}
    text += note
    _persist_reply(sid, jid, uid, text, top, mx, {"sources": sources, "tainted": tainted, "action_id": action["id"] if action else None})
    result = {"session_id": sid, "reply": text, "tainted": tainted, "sources": sources, "action": action, "denied_docs": len(res["denied"])}
    _set(jid, status="done", stage="done", result=json.dumps(result), finished=time.time())

def _fail(jid, e):
    log.exception("job %s failed", jid)
    j = q("select user_id,session_id from jobs where id=?", (jid,), one=True)
    msg = "Sorry, something went wrong while answering. Please try again."
    if j:
        x("insert into messages(session_id,role,text,job_id,meta,ts) values(?,?,?,?,?,?)", (j["session_id"], "assistant", msg, jid, json.dumps({"error": True}), time.time()))
        S.audit(j["user_id"], "chat_error", {"job": jid, "error": type(e).__name__})
    _set(jid, status="error", stage="error", error=msg, finished=time.time())

def _loop():
    while True:
        jid = Q.get()
        try: run(jid)
        except Exception as e: _fail(jid, e)
        finally: Q.task_done()

def start():
    """Idempotent. Recovers jobs left over from a previous run, then starts the single worker thread."""
    global _thread
    with _lock:
        if _thread and _thread.is_alive(): return
        x("update jobs set status='error', stage='error', error='server restarted while this was running', finished=? where status='running'", (time.time(),))
        for r in q("select id from jobs where status='queued' order by id"): Q.put(r["id"])
        _thread = threading.Thread(target=_loop, name="chat-worker", daemon=True); _thread.start()
