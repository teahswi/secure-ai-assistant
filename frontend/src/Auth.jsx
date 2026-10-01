import { useState } from "react";
import { call } from "./api.js";

export default function Auth({ onAuthed, notice }) {
  const [mode, setMode] = useState("login");
  const [u, setU] = useState(""), [p, setP] = useState(""), [p2, setP2] = useState("");
  const [err, setErr] = useState(""), [info, setInfo] = useState(""), [busy, setBusy] = useState(false);

  const submit = async e => {
    e.preventDefault(); setErr(""); setInfo("");
    if (mode === "register") {
      if (p.length < 8) return setErr("Password must be at least 8 characters.");
      if (p !== p2) return setErr("Passwords do not match.");
    }
    setBusy(true);
    try {
      if (mode === "register") await call("/register", { body: { username: u.trim(), password: p } });
      const { token } = await call("/login", { body: { username: u.trim(), password: p } });
      await onAuthed(token);
    } catch (e2) { setErr(e2.message); }
    setBusy(false);
  };

  return (
    <form className="auth card" onSubmit={submit}>
      <h2 style={{ margin: "0 0 4px" }}>Secure AI Assistant</h2>
      <div className="tabs">
        <button type="button" className={"tab" + (mode === "login" ? " on" : "")} onClick={() => { setMode("login"); setErr(""); }}>Log in</button>
        <button type="button" className={"tab" + (mode === "register" ? " on" : "")} onClick={() => { setMode("register"); setErr(""); }}>Create account</button>
      </div>
      {notice && <div className="warn">{notice}</div>}
      <input value={u} onChange={e => setU(e.target.value)} placeholder="username" autoComplete="username" autoFocus />
      <input type="password" value={p} onChange={e => setP(e.target.value)} placeholder="password" autoComplete={mode === "login" ? "current-password" : "new-password"} />
      {mode === "register" && <input type="password" value={p2} onChange={e => setP2(e.target.value)} placeholder="repeat password" autoComplete="new-password" />}
      <button disabled={busy || !u || !p}>{busy ? "Please wait…" : mode === "login" ? "Log in" : "Create account"}</button>
      {mode === "register" && <small className="mute">New accounts have no access until an administrator assigns a role and clearance.</small>}
      {err && <div className="err">{err}</div>}{info && <div className="ok">{info}</div>}
      {mode === "login" && <small className="mute">demo: bob/bob123 · alice/alice123 · carol/carol123 · dave/dave123 · admin/admin123</small>}
    </form>
  );
}
