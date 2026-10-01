import sqlite3, os, time
from contextlib import contextmanager
DB = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.db"))
SCHEMA = """
create table if not exists users(id integer primary key, username text unique, pw text, clearance int default 0, created real);
create table if not exists user_roles(user_id int, role text, primary key(user_id, role));
create table if not exists role_permissions(role text, action text, project text, primary key(role, action, project));
create table if not exists projects(name text primary key, created real);
create table if not exists documents(id integer primary key, title text, project text, level int, flag int default 0, flag_reason text);
create table if not exists chunks(id integer primary key, doc_id int, project text, level int, text text, embedding blob, emb_tag text);
create table if not exists sessions(id integer primary key, user_id int, max_level_seen int default 0, tainted int default 0, title text, created real, updated real);
create table if not exists messages(id integer primary key, session_id int, role text, text text, chunk_ids text, level int default 0, job_id int, meta text, ts real);
create table if not exists action_requests(id integer primary key, session_id int, user_id int, action text, project text, args text, status text, reason text);
create table if not exists audit_log(id integer primary key, ts real, user_id int, event text, detail text, prev_hash text, hash text);
create table if not exists jobs(id integer primary key, user_id int, session_id int, message text, doc_ids text, status text, stage text, result text, error text, created real, started real, finished real);
create index if not exists idx_chunks_doc on chunks(doc_id);
create index if not exists idx_msgs_session on messages(session_id);
create index if not exists idx_jobs_status on jobs(status);
"""
# columns added after the first version; applied to pre-existing app.db files so old DBs keep working
MIGRATIONS = {
    "users": [("created", "real")],
    "chunks": [("emb_tag", "text")],
    "documents": [("flag_reason", "text")],
    "sessions": [("title", "text"), ("created", "real"), ("updated", "real")],
    "messages": [("job_id", "int"), ("meta", "text"), ("ts", "real")],
}


def conn():
    c = sqlite3.connect(DB, timeout=30)   # worker thread + request threads share the file
    c.row_factory = sqlite3.Row
    return c


def q(sql, a=(), one=False):
    c = conn(); r = c.execute(sql, a).fetchall(); c.close()
    return (r[0] if r else None) if one else r


def x(sql, a=()):
    c = conn(); cur = c.execute(sql, a); c.commit(); i = cur.lastrowid; c.close(); return i


@contextmanager
def tx():
    """Multi-statement transaction: commits on success, rolls everything back on any exception."""
    c = conn()
    try:
        yield c
        c.commit()
    except BaseException:
        c.rollback(); raise
    finally:
        c.close()


def init():
    c = conn(); c.executescript(SCHEMA)
    for t, cols in MIGRATIONS.items():
        have = {r["name"] for r in c.execute(f"pragma table_info({t})")}
        for name, decl in cols:
            if name not in have: c.execute(f"alter table {t} add column {name} {decl}")
    c.execute("insert or ignore into projects(name, created) select distinct project, ? from documents where project is not null", (time.time(),))
    c.execute("insert or ignore into projects(name, created) select distinct project, ? from role_permissions where project!='*'", (time.time(),))
    c.execute("update documents set flag_reason=? where flag=1 and (flag_reason is null or flag_reason='')",
              ("Matched injection-risk text during ingestion; the document contains instruction-like content that may try to manipulate the model.",))
    c.commit(); c.close()
