import { useCallback, useEffect, useState } from "react";
import { call } from "./api.js";
import Auth from "./Auth.jsx";
import Chat from "./Chat.jsx";
import Admin from "./Admin.jsx";
import Audit from "./Audit.jsx";

export default function App() {
  const [tok, setTok] = useState(() => sessionStorage.getItem("tok") || "");
  const [me, setMe] = useState(null);
  const [tab, setTab] = useState("chat");
  const [booting, setBooting] = useState(!!sessionStorage.getItem("tok"));
  const [notice, setNotice] = useState("");

  const logout = useCallback((msg = "") => { sessionStorage.removeItem("tok"); setTok(""); setMe(null); setTab("chat"); setNotice(msg); }, []);
  const loadMe = useCallback(async t => { setMe(await call("/me", { token: t })); }, []);

  // restore a session after a page refresh
  useEffect(() => {
    if (!tok || me) { setBooting(false); return; }
    loadMe(tok).catch(e => logout(e.status === 401 ? "Session expired, please log in again." : e.message)).finally(() => setBooting(false));
  }, []); // eslint-disable-line

  // while an account is waiting for an admin, re-check permissions every 8s so access appears without a re-login
  useEffect(() => {
    if (!me?.pending) return;
    const t = setInterval(() => loadMe(tok).catch(() => {}), 8000); return () => clearInterval(t);
  }, [me?.pending, tok, loadMe]);

  const onAuthed = async t => { sessionStorage.setItem("tok", t); setTok(t); setNotice(""); await loadMe(t); };
  // any API call from a child that gets 401 drops back to the login screen
  const onErr = useCallback(e => { if (e?.status === 401) logout("Session expired, please log in again."); }, [logout]);

  if (booting) return <div className="auth card mute">Loading…</div>;
  if (!me) return <Auth onAuthed={onAuthed} notice={notice} />;

  const tabs = [["chat", "Chat"], ...(me.is_admin ? [["admin", "Admin"]] : []), ["audit", me.can_audit ? "Audit log" : "My activity"]];
  return (
    <div className="app">
      <div className="top card">
        <b>{me.username}</b>
        <span className="mute" title={me.clearance_scope}>clearance {me.clearance} <small>({me.clearance_scope})</small></span>
        <span>{me.roles.map(r => <span className="badge" key={r}>{r}</span>)}</span>
        <span className="grow">{me.permissions.map(p => <span className="badge" key={p}>{p}</span>)}</span>
        <button className="ghost small" onClick={() => logout()}>Log out</button>
      </div>
      <details className="clearance-help"><summary>What do clearance levels mean?</summary><div className="clearance-levels">{me.clearance_levels.map(item => <span key={item.level} className={item.level <= me.clearance ? "level allowed" : "level"}><b>L{item.level}</b> {item.meaning}</span>)}</div></details>
      {me.pending && (
        <div className="banner">
          Your account has no permissions yet. An administrator needs to assign you a role and clearance before you can see any documents. This page
          updates automatically; <a href="#" onClick={e => { e.preventDefault(); loadMe(tok); }}>check again</a>.
        </div>
      )}
      <div className="tabs">{tabs.map(([k, l]) => <button key={k} className={"tab" + (tab === k ? " on" : "")} onClick={() => setTab(k)}>{l}</button>)}</div>
      <div className="main">
        {tab === "chat" && <Chat token={tok} me={me} onErr={onErr} refreshMe={() => loadMe(tok)} />}
        {tab === "admin" && me.is_admin && <Admin token={tok} onErr={onErr} />}
        {tab === "audit" && <Audit token={tok} me={me} onErr={onErr} />}
      </div>
    </div>
  );
}
