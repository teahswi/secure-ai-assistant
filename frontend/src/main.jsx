import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import "./styles.css";

// If anything in the tree throws, show the error instead of a blank page.
class Boundary extends React.Component {
  state = { err: null };
  static getDerivedStateFromError(err) { return { err }; }
  render() {
    if (!this.state.err) return this.props.children;
    return (
      <div className="auth card">
        <h2>Something broke in the UI</h2>
        <pre className="err">{String(this.state.err?.message || this.state.err)}</pre>
        <button onClick={() => { sessionStorage.clear(); location.reload(); }}>Reset and reload</button>
      </div>
    );
  }
}
createRoot(document.getElementById("root")).render(<Boundary><App /></Boundary>);
