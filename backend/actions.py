"""Action executor (trusted code): re-checks authorization with the USER's rights; model output is never trusted."""
import json
from db import q, x
import security as S

def finish(rid, status, reason, uid, extra=None):
    x("update action_requests set status=?,reason=? where id=?", (status, reason, rid))
    S.audit(uid, "action_" + status, {"request": rid, "reason": reason, **(extra or {})})
    return {"id": rid, "status": status, "reason": reason}

def execute(rid):
    r = q("select * from action_requests where id=?", (rid,), one=True)
    uid, act, proj = r["user_id"], r["action"], r["project"]
    if act not in S.ACTIONS or not S.can(uid, act, proj):
        return finish(rid, "denied", f"user lacks '{act}' on project {proj}", uid, {"action": act, "project": proj})
    s = q("select tainted from sessions where id=?", (r["session_id"],), one=True)
    if act in S.CONFIRM_WHEN_TAINTED and s and s["tainted"] and r["status"] != "approved":
        x("update action_requests set status='pending_confirm' where id=?", (rid,))
        S.audit(uid, "action_pending_confirm", {"request": rid, "action": act, "project": proj})
        return {"id": rid, "status": "pending_confirm", "reason": "session handled sensitive/flagged content; human confirmation required"}
    a = json.loads(r["args"])
    if act == "read":
        t = [d["title"] for d in S.allowed_docs(uid) if d["project"] == proj]
        res = "Readable documents: " + (", ".join(t) or "none")
    else: res = f"[simulated] {act} of project {proj} data" + (f" to {a.get('to', 'n/a')}" if act != "write" else "")
    return finish(rid, "executed", res, uid, {"action": act, "project": proj})
