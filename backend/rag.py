"""Retrieval-augmented generation, step 1: authorize -> narrow to the documents the user named -> rank by embedding.
Authorization (SQL) always runs first; the user's document selection can only shrink the allowed set, never widen it."""
import numpy as np
import security as S, llm
from config import cfg

def retrieve(uid, question, doc_ids):
    doc_ids = [int(i) for i in doc_ids]
    ok_docs = {d["id"] for d in S.allowed_docs(uid)}
    denied = [i for i in doc_ids if i not in ok_docs]            # unknown OR not permitted: indistinguishable on purpose
    rows = [dict(r) for r in S.allowed_chunks(uid, [i for i in doc_ids if i in ok_docs])]
    if not rows: return {"chunks": [], "denied": denied, "candidates": 0}
    qv, qtag = llm.embed(question); qh = None
    def score(r):
        nonlocal qh
        if r["emb_tag"] == qtag and r["embedding"]:
            e = np.frombuffer(r["embedding"], dtype=np.float32)
            if e.shape == qv.shape: return float(e @ qv)
        qh = llm._hash_embed(question) if qh is None else qh      # embedder mismatch: compare like with like
        return float(llm._hash_embed(r["text"]) @ qh)
    for r in rows: r["score"] = score(r)
    ranked = sorted(rows, key=lambda r: -r["score"])
    k = cfg["top_k"]; chosen, seen = [], set()
    for r in ranked:                                              # best chunk of every mentioned doc first...
        if r["doc_id"] not in seen: chosen.append(r); seen.add(r["doc_id"])
    ids = {r["id"] for r in chosen}
    for r in ranked:                                              # ...then fill up with the next-best chunks
        if len(chosen) >= k: break
        if r["id"] not in ids: chosen.append(r); ids.add(r["id"])
    chosen = sorted(chosen[:k], key=lambda r: (r["doc_id"], r["id"]))   # reading order
    for r in chosen: r.pop("embedding", None)
    return {"chunks": chosen, "denied": denied, "candidates": len(rows)}
