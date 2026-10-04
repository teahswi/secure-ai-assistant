import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import { marked } from "marked";
import DOMPurify from "dompurify";
import { call } from "./api.js";

const statusColor = s => ({ executed: "ev-ok", denied: "ev-bad", rejected: "ev-bad", pending_confirm: "ev-warn" }[s] || "mute");
const stageText = j =>
  j.status === "queued" ? (j.position > 0 ? `Queued: ${j.position} message${j.position > 1 ? "s" : ""} ahead of yours` : "Queued: you're next")
  : j.stage === "retrieving" ? "Searching your selected documents…"
  : j.stage === "generating" ? "Model is writing a reply…" : "Working…";

function Typing({ job }) {
  return <div className="msg assistant typing"><span className="dots"><span /><span /><span /></span>{stageText(job)}</div>;
}

function Markdown({ text }) {
  const html = DOMPurify.sanitize(marked.parse(text || "", { breaks: true, gfm: true }));
  return <div className="markdown" dangerouslySetInnerHTML={{ __html: html }} />;
}

export default function Chat({ token, me, onErr, refreshMe }) {
  const [docs, setDocs] = useState([]), [projects, setProjects] = useState([]), [sel, setSel] = useState([]);
  const [sessions, setSessions] = useState([]), [sid, setSid] = useState(null), [data, setData] = useState({ messages: [] });
  const [jobs, setJobs] = useState({});                 // jobId -> {sid,status,stage,position}
  const [text, setText] = useState(""), [pick, setPick] = useState(false), [err, setErr] = useState(""), [sending, setSending] = useState(false);
  const jobsRef = useRef({}), sidRef = useRef(null), inflight = useRef(false), endRef = useRef(null);
  const putJobs = j => { jobsRef.current = j; setJobs(j); };
  const fail = e => { onErr(e); setErr(e.message); };

  const loadDocs = useCallback(async () => {
    try {
      const [d, p] = await Promise.all([call("/documents", { token }), call("/projects", { token })]);
      setDocs(d); setProjects(p); setSel(s => s.filter(i => d.some(x => x.id === i)));
    } catch (e) { fail(e); }
  }, [token]); // eslint-disable-line
  const loadSessions = useCallback(async () => { try { setSessions(await call("/sessions", { token })); } catch (e) { fail(e); } }, [token]); // eslint-disable-line
  const openSession = useCallback(async id => {
    try {
      const s = await call(`/sessions/${id}`, { token });
      sidRef.current = id; setSid(id); setData(s);
      const next = { ...jobsRef.current };               // resume polling for jobs still running in this session (e.g. after reload)
      s.pending_jobs.forEach(j => { if (!next[j]) next[j] = { sid: id, status: "queued", stage: "queued", position: 0 }; });
      putJobs(next);
    } catch (e) { fail(e); }
  }, [token]); // eslint-disable-line

  useEffect(() => { loadDocs(); loadSessions(); }, [loadDocs, loadSessions, me.permissions.join(), me.clearance]);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [data, jobs]);

  // ---- poll queued/running jobs ----
  const tick = useCallback(async () => {
    if (inflight.current) return; inflight.current = true;
    try {
      const next = { ...jobsRef.current }, finished = new Set();
      await Promise.all(Object.entries(jobsRef.current).map(async ([id, j]) => {
        try {
          const s = await call(`/jobs/${id}`, { token });
          if (s.status === "done" || s.status === "error") { delete next[id]; finished.add(j.sid); }
          else next[id] = { ...j, status: s.status, stage: s.stage, position: s.position ?? 0 };
        } catch (e) { onErr(e); if (e.status === 404) delete next[id]; }
      }));
      putJobs(next);
      if (finished.size) {
        loadSessions(); loadDocs(); refreshMe();
        if (finished.has(sidRef.current)) await openSession(sidRef.current);
      }
    } finally { inflight.current = false; }
  }, [token]); // eslint-disable-line
  useEffect(() => {
    if (!Object.keys(jobs).length) return;
    const t = setInterval(tick, 800); return () => clearInterval(t);
  }, [Object.keys(jobs).join(), tick]); // eslint-disable-line

  // ---- sending ----
  const activeJobs = Object.keys(jobs).length;
  const send = async () => {
    const m = text.trim(); if (!m || !sel.length || sending) return;
    setSending(true); setErr("");
    try {
      const r = await call("/chat", { token, body: { message: m, session_id: sid, doc_ids: sel } });
      setText("");
      putJobs({ ...jobsRef.current, [r.job_id]: { sid: r.session_id, status: "queued", stage: "queued", position: 0 } });
      await openSession(r.session_id); loadSessions();
    } catch (e) { fail(e); }
    setSending(false);
  };
  const confirm = async (id, approve) => {
    try { await call(`/actions/${id}/confirm`, { token, body: { approve } }); await openSession(sid); } catch (e) { fail(e); }
  };
  const newChat = () => { sidRef.current = null; setSid(null); setData({ messages: [] }); setErr(""); };

  // ---- @mention autocomplete ----
  const mention = /(^|\s)@([^\s@]*)$/.exec(text);
  const hits = mention ? docs.filter(d => !sel.includes(d.id) && d.title.toLowerCase().replace(/\s+/g, "").includes(mention[2].toLowerCase())).slice(0, 8) : [];
  const addDoc = d => { setSel(s => (s.includes(d.id) ? s : [...s, d.id])); if (mention) setText(text.slice(0, mention.index + mention[1].length)); };
  const toggle = id => setSel(s => (s.includes(id) ? s.filter(i => i !== id) : [...s, id]));
  const byId = Object.fromEntries(docs.map(d => [d.id, d]));
  const here = Object.entries(jobs).filter(([, j]) => j.sid === sid).reduce((a, [id, j]) => ({ ...a, [id]: j }), {});

  return (
    <div className="chat">
      <div className="side">
        <button onClick={newChat}>+ New chat</button>
        {sessions.map(s => (
          <button key={s.id} className={"sess" + (s.id === sid ? " on" : "")} onClick={() => openSession(s.id)} title={s.title}>
            {s.tainted ? "⚠ " : ""}{s.title || `Chat ${s.id}`}
          </button>
        ))}
        {!sessions.length && <small className="mute">No conversations yet.</small>}
      </div>

      <div className="convo">
        <div className="library card">
          <div className="library-head">
            <div><b>Knowledge base</b><div className="mute">Only documents you are authorized to read are shown.</div></div>
            <span className="badge">{docs.length} document{docs.length === 1 ? "" : "s"} · {projects.length} project{projects.length === 1 ? "" : "s"}</span>
          </div>
          {projects.length ? <div className="library-projects">{projects.map(project => (
            <div className="project-card" key={project.name}>
              <div className="project-title"><b>{project.name}</b><span className="mute">{project.document_count} document{project.document_count === 1 ? "" : "s"} · L{project.levels.join(", L")}</span></div>
              <div className="project-docs">{project.documents.map(doc => (
                <button key={doc.id} className={"doc-card" + (sel.includes(doc.id) ? " selected" : "")} onClick={() => toggle(doc.id)} title={doc.flag_reason || doc.title}>
                  <span className="doc-check">{sel.includes(doc.id) ? "✓" : "+"}</span><span>{doc.title}<small>{project.name}/L{doc.level}{doc.flagged ? " · ⚠ flagged" : ""}</small></span>
                </button>
              ))}</div>
            </div>
          ))}</div> : <div className="library-empty">{me.pending ? "Your account is awaiting project permissions." : "No readable documents are assigned to this account yet."}</div>}
        </div>
        <div className="msgs">
          {!data.messages.length && <div className="mute" style={{ margin: "auto", textAlign: "center", maxWidth: 420 }}>
            Pick the documents you need (type <b>@</b> or use <b>+ Documents</b>), then ask a question. The assistant only searches what you select, and only what you're cleared to see.
          </div>}
          {data.messages.map(m => (
            <Fragment key={m.id}>
              <div className={`msg ${m.role}${m.error ? " error" : ""}`}>
                {m.role === "assistant" ? <Markdown text={m.text} /> : m.text}
                {m.role === "assistant" && m.tainted && <div className="meta warn">⚠ session tainted: sensitive or flagged content was used</div>}
                {m.sources?.length > 0 && <div className="meta">Sources: {m.sources.map(s => `${s.title} [${s.project}/L${s.level}${s.flagged ? ` ⚠ ${s.flag_reason || "injection-risk content detected"}` : ""}]`).join("; ")}</div>}
                {m.action && (
                  <div className="action">
                    ⚙ Model proposed <b>{m.action.action}</b> on {m.action.project}: <b className={statusColor(m.action.status)}>{m.action.status}</b>
                    <div className="mute">{m.action.reason}</div>
                    {m.action.status === "pending_confirm" && <div style={{ marginTop: 6, display: "flex", gap: 6 }}>
                      <button className="small" onClick={() => confirm(m.action.id, true)}>Approve</button>
                      <button className="small danger" onClick={() => confirm(m.action.id, false)}>Reject</button></div>}
                  </div>
                )}
              </div>
              {m.role === "user" && here[m.job_id] && <Typing job={here[m.job_id]} />}
            </Fragment>
          ))}
          <div ref={endRef} />
        </div>

        <div className="composer">
          {err && <div className="err">{err}</div>}
          {pick && (
            <div className="menu">
              {docs.length ? docs.map(d => (
                <button key={d.id} onClick={() => toggle(d.id)}>
                  <input type="checkbox" readOnly checked={sel.includes(d.id)} /> {d.title} <span className="badge">{d.project}/L{d.level}</span>{d.flagged && <span className="badge warn" title={d.flag_reason}>⚠ {d.flag_reason || "injection-risk content detected"}</span>}
                </button>
              )) : <div className="mute" style={{ padding: 10 }}>No documents available to your account.</div>}
            </div>
          )}
          {!pick && hits.length > 0 && (
            <div className="menu">{hits.map(d => <button key={d.id} onClick={() => addDoc(d)}>@{d.title} <span className="badge">{d.project}/L{d.level}</span></button>)}</div>
          )}
          <div className="chips">
            <button className="ghost small" onClick={() => setPick(p => !p)}>{pick ? "Done" : "+ Documents"}</button>
            {sel.map(i => byId[i] && <span className="chip" key={i}>{byId[i].title}<button title="remove" onClick={() => toggle(i)}>✕</button></span>)}
            {!sel.length && <small className="mute">no documents selected</small>}
          </div>
          <div className="row">
            <textarea rows={2} value={text} onChange={e => setText(e.target.value)} placeholder={sel.length ? "Ask about the selected documents…  (Enter to send, Shift+Enter for a new line)" : "Select or @mention a document first…"}
              onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); if (hits.length) addDoc(hits[0]); else send(); } }} />
            <button onClick={send} disabled={!text.trim() || !sel.length || sending}>{sending ? "Sending…" : "Send"}</button>
          </div>
          {activeJobs > 0 && <small className="mute">{activeJobs} message{activeJobs > 1 ? "s" : ""} in progress. You can keep typing; replies arrive in order.</small>}
        </div>
      </div>
    </div>
  );
}
