import { useCallback, useEffect, useState } from "react";
import { call, fmtTime } from "./api.js";

function useLoad(token, onErr) {
  const [err, setErr] = useState(""), [ok, setOk] = useState("");
  const run = async (f, success) => { setErr(""); setOk(""); try { const r = await f(); if (success) setOk(success); return r; } catch (e) { onErr(e); setErr(e.message); } };
  return { err, ok, run, Msg: () => <>{err && <div className="err">{err}</div>}{ok && <div className="ok">{ok}</div>}</> };
}

function Users({ token, onErr, meta }) {
  const [users, setUsers] = useState([]), [roles, setRoles] = useState([]), [draft, setDraft] = useState({});
  const { run, Msg } = useLoad(token, onErr);
  const load = useCallback(async () => {
    const [u, r] = await Promise.all([call("/admin/users", { token }), call("/admin/roles", { token })]);
    setUsers(u); setRoles(r); setDraft({});
  }, [token]);
  useEffect(() => { run(load); }, [load]); // eslint-disable-line
  const get = u => ({ clearance: u.clearance, roles: u.roles, ...(draft[u.id] || {}) });
  const set = (u, patch) => setDraft(d => ({ ...d, [u.id]: { ...get(u), ...patch } }));
  const save = u => run(async () => { await call(`/admin/users/${u.id}`, { token, method: "PUT", body: get(u) }); await load(); }, `Saved ${u.username}`);
  return (
    <div className="scroll"><Msg />
      <table><thead><tr><th>User</th><th>Clearance</th><th>Roles</th><th></th></tr></thead><tbody>
        {users.map(u => { const d = get(u); return (
          <tr key={u.id}>
            <td><b>{u.username}</b>{u.pending && <span className="badge warn">awaiting permissions</span>}<div className="mute" style={{ fontSize: 11 }}>{u.created ? "joined " + fmtTime(u.created) : ""}</div></td>
            <td><select value={d.clearance} title={`Allows document levels 0 through ${d.clearance}`} onChange={e => set(u, { clearance: +e.target.value })}>{Array.from({ length: meta.max_clearance + 1 }, (_, i) => <option key={i} value={i}>L{i} (up to level {i})</option>)}</select><small className="mute">reads L0-L{d.clearance}</small></td>
            <td><div className="rolebox">{roles.map(r => (
              <label key={r.name}><input type="checkbox" checked={d.roles.includes(r.name)} onChange={e => set(u, { roles: e.target.checked ? [...d.roles, r.name] : d.roles.filter(x => x !== r.name) })} />{r.name}</label>))}</div></td>
            <td><button className="small" disabled={!draft[u.id]} onClick={() => save(u)}>Save</button></td>
          </tr>); })}
      </tbody></table>
    </div>
  );
}

function Projects({ token, onErr, onChanged }) {
  const [projects, setProjects] = useState([]), [name, setName] = useState("");
  const { run, Msg } = useLoad(token, onErr);
  const load = useCallback(async () => setProjects(await call("/admin/projects", { token })), [token]);
  useEffect(() => { run(load); }, [load]); // eslint-disable-line
  const create = e => { e.preventDefault(); run(async () => { const r = await call("/admin/projects", { token, body: { name: name.trim() } }); setName(""); await load(); onChanged(); return r; }, `Created project ${name.trim()}`); };
  return (
    <div className="scroll"><Msg />
      <div className="card project-help">
        <b>Projects are authorization boundaries.</b>
        <p>Create a project here, upload documents into it, then add <code>read:project</code> or <code>write:project</code> to a role and assign that role to a user. A clearance level is the maximum document sensitivity that user may read.</p>
      </div>
      <form className="form card" onSubmit={create}>
        <label>New project name<input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Project_Z" required /></label>
        <button disabled={!name.trim()}>Create project</button>
      </form>
      <div className="project-list">{projects.map(p => <span className="chip" key={p.name}>{p.name}</span>)}</div>
    </div>
  );
}

function Roles({ token, onErr, meta, onChanged }) {
  const [roles, setRoles] = useState([]), [name, setName] = useState(""), [add, setAdd] = useState({});
  const { run, Msg } = useLoad(token, onErr);
  const load = useCallback(async () => setRoles(await call("/admin/roles", { token })), [token]);
  useEffect(() => { run(load); }, [load]); // eslint-disable-line
  const put = (n, perms, okMsg) => run(async () => { await call(`/admin/roles/${n}`, { token, method: "PUT", body: { permissions: perms } }); await load(); onChanged(); }, okMsg);
  const addPerm = r => { const a = add[r.name] || {}; if (!a.action) return; put(r.name, [...r.permissions, { action: a.action, project: a.project || "*" }], `Updated ${r.name}`); setAdd(x => ({ ...x, [r.name]: {} })); };
  return (
    <div className="scroll"><Msg />
      <div className="form">
        <label>New role<input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. analyst_z" /></label>
        <button disabled={!name} onClick={() => { put(name, [{ action: "read", project: meta.projects[0] || "X" }], `Created ${name} (edit its permissions below)`); setName(""); }}>Create</button>
        <small className="mute">Roles hold permissions (action + project). Assign roles to users in the Users tab.</small>
      </div>
      {roles.map(r => (
        <div className="card" key={r.name} style={{ marginBottom: 8 }}>
          <div className="top"><b>{r.name}</b><span className="mute grow">{r.users} user{r.users === 1 ? "" : "s"}</span>
            <button className="small danger" onClick={() => confirm(`Delete role ${r.name}? It is removed from ${r.users} user(s).`) && run(async () => { await call(`/admin/roles/${r.name}`, { token, method: "DELETE" }); await load(); onChanged(); }, `Deleted ${r.name}`)}>Delete role</button></div>
          <div>{r.permissions.map(p => (
            <span className="chip" key={p.action + p.project}>{p.action}:{p.project}
              <button title="remove" onClick={() => put(r.name, r.permissions.filter(q => q !== p), `Updated ${r.name}`)}>✕</button></span>))}</div>
          <div className="form" style={{ marginTop: 8, marginBottom: 0 }}>
            <select value={add[r.name]?.action || ""} onChange={e => setAdd(x => ({ ...x, [r.name]: { ...x[r.name], action: e.target.value } }))}><option value="">action…</option>{meta.actions.map(a => <option key={a}>{a}</option>)}</select>
            <input list="projs" placeholder="project (X, Y…)" style={{ width: 130 }} value={add[r.name]?.project || ""} onChange={e => setAdd(x => ({ ...x, [r.name]: { ...x[r.name], project: e.target.value } }))} />
            <button className="small" onClick={() => addPerm(r)}>Add permission</button>
          </div>
        </div>))}
      <datalist id="projs">{meta.projects.map(p => <option key={p} value={p} />)}</datalist>
    </div>
  );
}

function Documents({ token, onErr, meta, onChanged }) {
  const [docs, setDocs] = useState([]), [file, setFile] = useState(null), [title, setTitle] = useState(""), [project, setProject] = useState(""), [level, setLevel] = useState(1), [busy, setBusy] = useState(false);
  const { run, Msg } = useLoad(token, onErr);
  const load = useCallback(async () => setDocs(await call("/admin/documents", { token })), [token]);
  useEffect(() => { run(load); }, [load]); // eslint-disable-line
  const upload = async e => {
    e.preventDefault(); setBusy(true);
    const fd = new FormData(); fd.append("file", file); fd.append("project", project); fd.append("level", level); fd.append("title", title);
    await run(async () => { const r = await call("/admin/documents", { token, form: fd }); setFile(null); setTitle(""); e.target.reset(); await load(); onChanged(); return r; }, "Uploaded, chunked and embedded.");
    setBusy(false);
  };
  return (
    <div className="scroll"><Msg />
      <form className="form card" onSubmit={upload}>
        <label>File (.txt .md .docx .pdf)<input type="file" accept=".txt,.md,.csv,.log,.docx,.pdf" onChange={e => setFile(e.target.files[0])} /></label>
        <label>Title (optional)<input value={title} onChange={e => setTitle(e.target.value)} /></label>
        <label>Project<input list="projs2" value={project} onChange={e => setProject(e.target.value)} placeholder="X or new name" style={{ width: 130 }} required /><small>Existing or new project</small></label>
        <label>Level<select value={level} title="Document sensitivity; users need equal or higher clearance" onChange={e => setLevel(+e.target.value)}>{Array.from({ length: meta.max_clearance + 1 }, (_, i) => <option key={i} value={i}>L{i}</option>)}</select><small>Document sensitivity</small></label>
        <button disabled={!file || !project || busy}>{busy ? "Embedding…" : "Upload & ingest"}</button>
        <datalist id="projs2">{meta.projects.map(p => <option key={p} value={p} />)}</datalist>
      </form>
      <div className="form"><small className="mute">Embedder: <b>{meta.config.embed_backend}</b>{meta.config.embed_backend === "ollama" ? ` (${meta.config.embed_model})` : ""} · chat model: <b>{meta.config.mock_llm ? "MOCK" : meta.config.chat_model}</b> (edit backend/config.json)</small>
        <button className="ghost small" onClick={() => run(async () => { const r = await call("/admin/reembed", { token, method: "POST" }); return r; }, "Re-embedded all chunks with the current embedder.")}>Re-embed all</button></div>
      <table><thead><tr><th>Title</th><th>Project</th><th>Level</th><th>Chunks</th><th></th></tr></thead><tbody>
        {docs.map(d => (
          <tr key={d.id}><td>{d.title}{d.flagged && <span className="badge warn" title={d.flag_reason}>⚠ {d.flag_reason || "injection-risk content detected"}</span>}</td><td>{d.project}</td><td>{d.level}</td><td>{d.chunks}</td>
            <td><button className="small danger" onClick={() => confirm(`Delete "${d.title}"?`) && run(async () => { await call(`/admin/documents/${d.id}`, { token, method: "DELETE" }); await load(); onChanged(); }, "Deleted.")}>Delete</button></td></tr>))}
      </tbody></table>
    </div>
  );
}

export default function Admin({ token, onErr }) {
  const [sub, setSub] = useState("users"), [meta, setMeta] = useState(null), [err, setErr] = useState("");
  const loadMeta = useCallback(async () => { try { setMeta(await call("/admin/meta", { token })); } catch (e) { onErr(e); setErr(e.message); } }, [token]); // eslint-disable-line
  useEffect(() => { loadMeta(); }, [loadMeta]);
  if (err) return <div className="err">{err}</div>;
  if (!meta) return <div className="mute">Loading…</div>;
  const P = { token, onErr, meta, onChanged: loadMeta };
  return (
    <div className="main">
      <div className="tabs">{[["users", "Users"], ["roles", "Roles & permissions"], ["projects", "Projects"], ["docs", "Documents"]].map(([k, l]) => <button key={k} className={"tab" + (sub === k ? " on" : "")} onClick={() => setSub(k)}>{l}</button>)}</div>
      {sub === "users" && <Users {...P} />}{sub === "roles" && <Roles {...P} />}{sub === "docs" && <Documents {...P} />}
      {sub === "projects" && <Projects token={token} onErr={onErr} onChanged={loadMeta} />}
    </div>
  );
}
