"""Ingestion: the ONLY writer to documents/chunks. Parse -> chunk -> label -> embed -> store (atomically).
Stamps project+level on every chunk. Called by seed.py and by the admin upload endpoint."""
import io, re, zipfile, numpy as np
import xml.etree.ElementTree as ET
from db import q, x, tx
from config import cfg
import llm
INJECTION_RULES = [
    ("instruction override", re.compile(r"ignore (all |previous |prior )?(rules|instructions)|disregard (all |previous |prior )?(rules|instructions)", re.I)),
    ("model action command", re.compile(r"(?<![A-Za-z0-9_])ACTION:\s*(?:\{[^}\n]{0,300}\})?", re.I)),
    ("cross-project retrieval instruction", re.compile(r"retrieve .{0,40}project", re.I)),
    ("system-prompt reference", re.compile(r"system prompt", re.I)),
]
TEXT_EXT = (".txt", ".md", ".csv", ".log")

def chunk(t, n=None):
    n = n or cfg["chunk_size"]
    out, cur = [], ""
    for s in re.split(r"(?<=[.!?])\s+", t):
        while len(s) > n * 2:                       # very long sentence / no punctuation: hard split
            if cur.strip(): out.append(cur.strip()); cur = ""
            out.append(s[:n]); s = s[n:]
        if len(cur) + len(s) > n and cur: out.append(cur.strip()); cur = ""
        cur += s + " "
    return out + ([cur.strip()] if cur.strip() else [])

def flag_reason(text):
    match = next(((label, pattern.search(text)) for label, pattern in INJECTION_RULES if pattern.search(text)), (None, None))
    if not match[1]: return None
    matched_text = re.sub(r"\s+", " ", match[1].group(0)).strip()
    start = max(0, match[1].start() - 45)
    end = min(len(text), match[1].end() + 45)
    excerpt = re.sub(r"\s+", " ", text[start:end]).strip()
    return f"Prompt-injection risk: {match[0]} matched `{matched_text}` in document text near: \"{excerpt}\""

def extract_text(filename, data):
    """Bytes -> plain text for .txt/.md/.csv/.log, .docx (stdlib only) and .pdf (needs pypdf)."""
    name = (filename or "").lower()
    if name.endswith(TEXT_EXT): return data.decode("utf-8", errors="replace")
    if name.endswith(".docx"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                if z.getinfo("word/document.xml").file_size > 20_000_000: raise ValueError("document too large")
                root = ET.fromstring(z.read("word/document.xml"))
        except Exception as e: raise ValueError(f"could not read .docx ({e})")
        ns = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
        paras = ["".join(t.text or "" for t in p.iter(ns + "t")) for p in root.iter(ns + "p")]
        return "\n".join(p for p in paras if p.strip())
    if name.endswith(".pdf"):
        try: from pypdf import PdfReader
        except ImportError: raise ValueError("PDF support needs `pip install pypdf`")
        try: return "\n".join((pg.extract_text() or "") for pg in PdfReader(io.BytesIO(data)).pages)
        except Exception as e: raise ValueError(f"could not read PDF ({e})")
    raise ValueError("unsupported file type (use .txt, .md, .docx or .pdf)")

def add_document(title, project, level, text):
    text = (text or "").strip()
    pieces = chunk(text)
    if not pieces: raise ValueError("document has no extractable text")
    reason = flag_reason(text)
    flag = int(bool(reason))
    embs = [llm.embed(c) for c in pieces]            # slow part (maybe Ollama) happens BEFORE the DB transaction
    with tx() as c:
        c.execute("insert or ignore into projects(name, created) values(?, strftime('%s','now'))", (project,))
        did = c.execute("insert into documents(title,project,level,flag,flag_reason) values(?,?,?,?,?)", (title, project, level, flag, reason)).lastrowid
        for t, (v, tag) in zip(pieces, embs):
            c.execute("insert into chunks(doc_id,project,level,text,embedding,emb_tag) values(?,?,?,?,?,?)",
                      (did, project, level, t, v.astype(np.float32).tobytes(), tag))
    return {"id": did, "chunks": len(pieces), "flagged": bool(flag), "flag_reason": reason}

def refresh_flag_reasons():
    """Re-evaluate stored documents so legacy warnings use the current detector."""
    for d in q("select id from documents"):
        text = "\n".join(r["text"] for r in q("select text from chunks where doc_id=? order by id", (d["id"],)))
        reason = flag_reason(text)
        x("update documents set flag=?,flag_reason=? where id=?", (int(bool(reason)), reason, d["id"]))

def reembed_all():
    """Re-embed every chunk with the currently configured embedder (run after changing embed_backend/embed_model)."""
    rows = q("select id,text from chunks"); n = 0
    for r in rows:
        v, tag = llm.embed(r["text"])
        x("update chunks set embedding=?, emb_tag=? where id=?", (v.astype(np.float32).tobytes(), tag, r["id"])); n += 1
    return n
