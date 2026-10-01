import os, time, jwt
from fastapi import Header, Depends, HTTPException, Request
from db import q
import security as S

SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-me")

def make_token(uid):
    return jwt.encode({"user_id": uid, "exp": int(time.time()) + 8 * 3600}, SECRET, algorithm="HS256")

def current(authorization: str = Header(None)):
    """Auth middleware: JWT carries ONLY user_id; clearance/roles are re-read from the DB every request."""
    try: uid = jwt.decode((authorization or "").replace("Bearer ", ""), SECRET, algorithms=["HS256"])["user_id"]
    except Exception: raise HTTPException(401, "bad token")
    u = q("select id,username,clearance from users where id=?", (uid,), one=True)
    if not u: raise HTTPException(401, "unknown user")
    return dict(u)

def require_admin(request: Request, u=Depends(current)):
    if not S.is_admin(u["id"]):
        S.audit(u["id"], "admin_denied", {"path": request.url.path, "method": request.method})
        raise HTTPException(403, "admin only")
    return u
