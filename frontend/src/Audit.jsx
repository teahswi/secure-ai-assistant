import { useCallback, useEffect, useState } from "react";
import { call, fmtTime } from "./api.js";

const PAGE = 25;
const evClass = e => (/denied|rejected|forged|error/.test(e) ? "ev-bad" : /pending|drop/.test(e) ? "ev-warn" : /executed|confirmed|login$|uploaded|registered/.test(e) ? "ev-ok" : "");
const toTs = v => (v ? new Date(v).getTime() / 1000 : "");

export default function Audit({ token, me, onErr }) {
  const [res, setRes] = useState({ items: [], total: 0, events: [], scope: "own" }), [page, setPage] = useState(0);
  const [f, setF] = useState({ event: "", user_id: "", text: "", since: "", until: "" }), [open, setOpen] = useState({});
  const [err, setErr] = useState(""), [chain, setChain] = useState(""), [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true); setErr("");
    const p = new URLSearchParams({ limit: PAGE, offset: page * PAGE });
    if (f.event) p.set("event", f.event); if (f.user_id) p.set("user_id", f.user_id); if (f.text) p.set("text", f.text);
    if (f.since) p.set("since", toTs(f.since)); if (f.until) p.set("until", toTs(f.until));
    try { setRes(await call("/audit?" + p, { token })); } catch (e) { onErr(e); setErr(e.message); }
    setLoading(false);
  }, [token, page, f]); // eslint-disable-line
  useEffect(() => { load(); }, [load]);
  const set = patch => { setPage(0); setF(x => ({ ...x, ...patch })); };
  const pages = Math.max(1, Math.ceil(res.total / PAGE));

  return (
    <div className="main">
      <div className="form">
        <label>Event<select value={f.event} onChange={e => set({ event: e.target.value })}><option value="">all</option>{res.events.map(e => <option key={e}>{e}</option>)}</select></label>
        {me.can_audit && <label>User id<input style={{ width: 80 }} value={f.user_id} onChange={e => set({ user_id: e.target.value.replace(/\D/g, "") })} /></label>}
        <label>Search<input value={f.text} onChange={e => set({ text: e.target.value })} placeholder="user, event or detail" /></label>
        <label>From<input type="datetime-local" value={f.since} onChange={e => set({ since: e.target.value })} /></label>
        <label>To<input type="datetime-local" value={f.until} onChange={e => set({ until: e.target.value })} /></label>
        <button className="ghost" onClick={load}>Refresh</button>
        <button className="ghost" onClick={async () => { try { const v = await call("/audit/verify", { token }); setChain(v.valid ? "✔ hash chain valid" : "✘ TAMPERED at row " + v.first_bad_row); } catch (e) { setChain(e.message); } }}>Verify chain</button>
        <span className={chain.startsWith("✘") ? "err" : "ok"}>{chain}</span>
      </div>
      {err && <div className="err">{err}</div>}
      <div className="mute" style={{ marginBottom: 6 }}>{res.scope === "all" ? "All users" : "Only your own events"} · {res.total} record{res.total === 1 ? "" : "s"}{loading ? " · loading…" : ""}</div>
      <div className="scroll">
        <table><thead><tr><th style={{ width: 70 }}>#</th><th style={{ width: 170 }}>Time</th><th style={{ width: 110 }}>User</th><th style={{ width: 190 }}>Event</th><th>Detail (click to expand)</th></tr></thead><tbody>
          {res.items.map(a => (
            <tr key={a.id}><td className="mute">{a.id}</td><td>{fmtTime(a.ts)}</td><td>{a.username || (a.user_id ?? "—")}</td><td className={evClass(a.event)}><b>{a.event}</b></td>
              <td><div className="pre" onClick={() => setOpen(o => ({ ...o, [a.id]: !o[a.id] }))}>{open[a.id] ? JSON.stringify(JSON.parse(a.detail || "{}"), null, 2) : (a.detail || "{}").slice(0, 140)}</div></td></tr>))}
          {!res.items.length && <tr><td colSpan={5} className="mute">No matching records.</td></tr>}
        </tbody></table>
      </div>
      <div className="pager">
        <button className="ghost small" disabled={page === 0} onClick={() => setPage(0)}>« First</button>
        <button className="ghost small" disabled={page === 0} onClick={() => setPage(p => p - 1)}>‹ Newer</button>
        <span className="mute">Page {page + 1} / {pages}</span>
        <button className="ghost small" disabled={page + 1 >= pages} onClick={() => setPage(p => p + 1)}>Older ›</button>
        <button className="ghost small" disabled={page + 1 >= pages} onClick={() => setPage(pages - 1)}>Oldest »</button>
      </div>
    </div>
  );
}
