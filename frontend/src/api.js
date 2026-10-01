// Single fetch wrapper. Never lets a non-JSON / empty / network failure surface as "Unexpected token ...".
export async function call(path, { token, method, body, form } = {}) {
  let r;
  try {
    r = await fetch("/api" + path, {
      method: method || (body || form ? "POST" : "GET"),
      headers: { ...(body ? { "Content-Type": "application/json" } : {}), ...(token ? { Authorization: "Bearer " + token } : {}) },
      body: form || (body ? JSON.stringify(body) : undefined),
    });
  } catch {
    throw Object.assign(new Error("Cannot reach the backend. Is `uvicorn main:app --port 8000` running?"), { status: 0 });
  }
  const text = await r.text();
  let j = null;
  try { j = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
  if (!r.ok) {
    const d = j && j.detail;
    const msg = typeof d === "string" ? d
      : Array.isArray(d) ? d.map(e => e.msg).join("; ")
      : r.status >= 500 ? `Backend unavailable or crashed (HTTP ${r.status}). Check the uvicorn window.`
      : `Request failed (HTTP ${r.status})`;
    throw Object.assign(new Error(msg), { status: r.status });
  }
  return j;
}

export const fmtTime = ts => (ts ? new Date(ts * 1000).toLocaleString() : "");
